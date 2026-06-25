package common

import (
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type importedScanResult struct {
	target            string
	fingerprintTarget string
	fingerprints      []string
}

var (
	importedURLPattern       = regexp.MustCompile(`https?://[^\s\]]+`)
	importedOpenPortPattern  = regexp.MustCompile(`(?:^|\s)([a-zA-Z0-9.-]+:\d+)\s+open\s*$`)
	importedBracketPattern   = regexp.MustCompile(`\[([^\]]*)\]`)
	importedFscanLinePattern = regexp.MustCompile(`^\[[*+]\]\s+(?:WebTitle|InfoScan)\s+`)
)

func parseImportedScanResult(line string) (importedScanResult, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return importedScanResult{}, false
	}

	if strings.HasPrefix(line, "{") {
		return parseImportedJSONResult(line)
	}
	if strings.HasPrefix(line, "[Finger]") {
		return parseImportedFingerResult(line)
	}
	if importedFscanLinePattern.MatchString(line) ||
		strings.HasPrefix(line, "[Web]") ||
		strings.HasPrefix(line, "[Active-Finger]") ||
		strings.HasPrefix(line, "[Domain-Bind]") {
		if target := importedURLPattern.FindString(line); target != "" {
			return importedScanResult{target: target}, true
		}
		return importedScanResult{}, false
	}
	if strings.HasPrefix(line, "[Nmap]") {
		return parseImportedNmapResult(strings.TrimSpace(strings.TrimPrefix(line, "[Nmap]")))
	}
	if strings.HasPrefix(line, "[PortScan]") {
		target := strings.TrimSpace(strings.TrimPrefix(line, "[PortScan]"))
		if utils.IsIPPort(target) {
			return importedScanResult{target: target}, true
		}
		return importedScanResult{}, false
	}
	if match := importedOpenPortPattern.FindStringSubmatch(line); len(match) == 2 && utils.IsIPPort(match[1]) {
		return importedScanResult{target: match[1]}, true
	}

	return importedScanResult{}, false
}

func parseImportedJSONResult(line string) (importedScanResult, bool) {
	var message ddout.OutputMessage
	if err := json.Unmarshal([]byte(line), &message); err != nil {
		return importedScanResult{}, false
	}

	switch message.Type {
	case "Finger":
		if message.URI == "" || len(message.Finger) == 0 {
			return importedScanResult{}, false
		}
		fingerprints := utils.NormalizeTargetInputs(message.Finger)
		if len(fingerprints) == 0 {
			return importedScanResult{}, false
		}
		return importedScanResult{
			fingerprintTarget: message.URI,
			fingerprints:      fingerprints,
		}, true
	case "Web", "Active-Finger", "Domain-Bind":
		if utils.GetInputType(message.URI) == structs.TypeURL {
			return importedScanResult{target: message.URI}, true
		}
	case "Nmap", "PortScan":
		target := message.IP + ":" + message.Port
		if utils.IsIPPort(target) || utils.IsDomainPort(target) {
			if message.Type == "Nmap" && (message.Protocol == "http" || message.Protocol == "https") {
				return importedScanResult{target: message.Protocol + "://" + target}, true
			}
			return importedScanResult{target: target}, true
		}
	}

	return importedScanResult{}, false
}

func parseImportedFingerResult(line string) (importedScanResult, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "[Finger]"))
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return importedScanResult{}, false
	}

	target := fields[0]
	groups := importedBracketPattern.FindAllStringSubmatch(strings.TrimPrefix(rest, target), -1)
	if len(groups) == 0 {
		return importedScanResult{}, false
	}

	fingerprintGroup := 0
	if _, err := strconv.Atoi(strings.TrimSpace(groups[0][1])); err == nil {
		fingerprintGroup = 1
	}
	if fingerprintGroup >= len(groups) {
		return importedScanResult{}, false
	}

	fingerprints := utils.NormalizeTargetInputs(strings.Split(groups[fingerprintGroup][1], ","))
	if len(fingerprints) == 0 {
		return importedScanResult{}, false
	}
	return importedScanResult{
		fingerprintTarget: target,
		fingerprints:      fingerprints,
	}, true
}

func parseImportedNmapResult(rawTarget string) (importedScanResult, bool) {
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return importedScanResult{}, false
	}

	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		return importedScanResult{target: rawTarget}, true
	}
	if utils.IsIPPort(parsed.Host) || utils.IsDomainPort(parsed.Host) {
		return importedScanResult{target: parsed.Host}, true
	}
	return importedScanResult{}, false
}

func mergeImportedFingerprints(resultMap map[string][]string, target string, fingerprints []string) {
	merged := append(resultMap[target], fingerprints...)
	resultMap[target] = utils.NormalizeTargetInputs(merged)
}
