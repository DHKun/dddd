package common

import (
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/lcvvvv/gonmap"
	"github.com/projectdiscovery/gologger"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type protocolScanner interface {
	SetTimeout(time.Duration)
	ScanTimeout(string, int, time.Duration) (gonmap.Status, *gonmap.Response)
}

func parseProtocolTarget(addr string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", addr, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid target %q: empty host", addr)
	}

	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target %q: invalid port", addr)
	}
	return host, port, nil
}

func scanProtocolTarget(scanner protocolScanner, addr string, timeout time.Duration) (result structs.ProtocolResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("protocol scan %q panic: %v", addr, recovered)
		}
	}()

	host, port, err := parseProtocolTarget(addr)
	if err != nil {
		return result, err
	}

	status, response := scanner.ScanTimeout(host, port, timeout)
	return structs.ProtocolResult{
		IP:       host,
		Port:     port,
		Status:   int(status),
		Response: response,
	}, nil
}

func GetProtocol(hostPorts []string, threads int, timeout int) {
	if len(hostPorts) == 0 {
		return
	}

	hostPorts = utils.RemoveDuplicateElement(hostPorts)
	if threads < 1 {
		threads = 1
	}
	if len(hostPorts) < threads {
		threads = len(hostPorts)
	}
	scanTimeout := time.Duration(timeout) * time.Second
	if scanTimeout <= 0 {
		scanTimeout = 5 * time.Second
	}

	gologger.AuditTimeLogger("TCP指纹识别，识别目标: %s", strings.Join(hostPorts, ","))

	addrs := make(chan string, len(hostPorts))
	results := make(chan structs.ProtocolResult, len(hostPorts))
	var workers sync.WaitGroup

	//多线程扫描
	for i := 0; i < threads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()

			for addr := range addrs {
				scanner := gonmap.New()
				scanner.SetTimeout(scanTimeout)
				result, err := scanProtocolTarget(scanner, addr, scanTimeout)
				if err != nil {
					gologger.Warning().Msg(err.Error())
					continue
				}
				results <- result
			}
		}()
	}

	//添加扫描目标
	for _, hostPort := range hostPorts {
		addrs <- hostPort
	}
	close(addrs)

	go func() {
		workers.Wait()
		close(results)
	}()

	for found := range results {
		if found.Status == int(gonmap.Closed) {
			continue
		}
		if found.Status == gonmap.Open || found.Response == nil {
			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "Nmap",
				IP:       found.IP,
				Port:     strconv.Itoa(found.Port),
				Protocol: "tcp",
			})
			continue
		}

		if found.Port == 23 && found.Response.FingerPrint.Service == "" {
			found.Response.FingerPrint.Service = "telnet"
		}
		hostPort := fmt.Sprintf("%s:%v", found.IP, found.Port)
		structs.GlobalIPPortMapLock.Lock()
		_, ok := structs.GlobalIPPortMap[hostPort]
		structs.GlobalIPPortMapLock.Unlock()
		if !ok {
			structs.GlobalBannerHMap.Set(hostPort, []byte(found.Response.Raw))
			structs.GlobalIPPortMapLock.Lock()
			structs.GlobalIPPortMap[hostPort] = found.Response.FingerPrint.Service
			structs.GlobalIPPortMapLock.Unlock()
		}
		proto := found.Response.FingerPrint.Service
		if proto == "" {
			proto = "tcp"
		}
		ddout.FormatOutput(ddout.OutputMessage{
			Type:     "Nmap",
			IP:       found.IP,
			Port:     strconv.Itoa(found.Port),
			Protocol: proto,
		})
	}

	gologger.AuditTimeLogger("TCP指纹识别结束")
}
