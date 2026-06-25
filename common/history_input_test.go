package common

import (
	"reflect"
	"testing"
)

func TestParseImportedScanResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		line               string
		wantTarget         string
		wantFingerTarget   string
		wantFingerprints   []string
		wantRecognizedLine bool
	}{
		{
			name:               "fscan web title",
			line:               "[*] WebTitle https://10.241.152.52:8443 code:200 len:7445 title:Welcome to C-Lodop",
			wantTarget:         "https://10.241.152.52:8443",
			wantRecognizedLine: true,
		},
		{
			name:               "fscan info scan",
			line:               "[+] InfoScan https://10.241.152.52:8443 [打印机 C-Lodop打印服务系统]",
			wantTarget:         "https://10.241.152.52:8443",
			wantRecognizedLine: true,
		},
		{
			name:               "prefixed open port",
			line:               "[+] 192.0.2.10:445 open",
			wantTarget:         "192.0.2.10:445",
			wantRecognizedLine: true,
		},
		{
			name:               "dddd nmap tcp",
			line:               "[Nmap] tcp://192.0.2.10:8443",
			wantTarget:         "192.0.2.10:8443",
			wantRecognizedLine: true,
		},
		{
			name:               "dddd nmap https",
			line:               "[Nmap] https://192.0.2.10:8443",
			wantTarget:         "https://192.0.2.10:8443",
			wantRecognizedLine: true,
		},
		{
			name:               "dddd web",
			line:               "[Web] [200] https://example.com/path [Example]",
			wantTarget:         "https://example.com/path",
			wantRecognizedLine: true,
		},
		{
			name:               "dddd finger with status",
			line:               "[Finger] https://example.com [200] [LODOP-cloud printing,nginx] [Welcome]",
			wantFingerTarget:   "https://example.com",
			wantFingerprints:   []string{"LODOP-cloud printing", "nginx"},
			wantRecognizedLine: true,
		},
		{
			name:               "dddd non-web finger",
			line:               "[Finger] 192.0.2.10:6379 [Redis]",
			wantFingerTarget:   "192.0.2.10:6379",
			wantFingerprints:   []string{"Redis"},
			wantRecognizedLine: true,
		},
		{
			name:               "json finger",
			line:               `{"type":"Finger","uri":"https://example.com","finger":["nginx","PHP"]}`,
			wantFingerTarget:   "https://example.com",
			wantFingerprints:   []string{"nginx", "PHP"},
			wantRecognizedLine: true,
		},
		{
			name:               "json web",
			line:               `{"type":"Web","uri":"https://example.com/login"}`,
			wantTarget:         "https://example.com/login",
			wantRecognizedLine: true,
		},
		{
			name: "truncated finger",
			line: "[Finger]",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, ok := parseImportedScanResult(test.line)
			if ok != test.wantRecognizedLine {
				t.Fatalf("recognized = %v, want %v", ok, test.wantRecognizedLine)
			}
			if result.target != test.wantTarget {
				t.Fatalf("target = %q, want %q", result.target, test.wantTarget)
			}
			if result.fingerprintTarget != test.wantFingerTarget {
				t.Fatalf("fingerprint target = %q, want %q", result.fingerprintTarget, test.wantFingerTarget)
			}
			if !reflect.DeepEqual(result.fingerprints, test.wantFingerprints) {
				t.Fatalf("fingerprints = %#v, want %#v", result.fingerprints, test.wantFingerprints)
			}
		})
	}
}

func TestMergeImportedFingerprints(t *testing.T) {
	t.Parallel()

	resultMap := map[string][]string{
		"https://example.com": {"nginx"},
	}
	mergeImportedFingerprints(resultMap, "https://example.com", []string{"PHP", "nginx"})

	want := []string{"nginx", "PHP"}
	if !reflect.DeepEqual(resultMap["https://example.com"], want) {
		t.Fatalf("merged fingerprints = %#v, want %#v", resultMap["https://example.com"], want)
	}
}
