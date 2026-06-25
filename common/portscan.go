package common

import (
	"bytes"
	"dddd/ddout"
	"dddd/lib/masscan"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

var BackList map[string]struct{}
var BackListLock sync.Mutex

func PortScanTCP(IPs []string, Ports string, NoPorts string, timeout int) []string {
	var AliveAddress []string
	if timeout < 1 {
		timeout = 1
	}
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s，目标数量: %d", Ports, len(IPs))
	ports := ParsePort(Ports)
	noPorts := ParsePort(NoPorts)

	var probePorts []int
	for _, port := range ports {
		ok := false
		for _, nport := range noPorts {
			if nport == port {
				ok = true
				break
			}
		}
		if !ok {
			probePorts = append(probePorts, port)
		}
	}

	IPPortCount := make(map[string]int)
	BackList = make(map[string]struct{})

	taskCount := portScanTaskCount(len(IPs), len(probePorts))
	workers := tcpPortScanWorkerCount(structs.GlobalConfig.TCPPortScanThreads, taskCount)
	if workers == 0 {
		gologger.AuditTimeLogger("TCP端口扫描结束，无有效任务")
		return AliveAddress
	}
	estimated := estimateTCPPortScanDuration(taskCount, workers, timeout)
	gologger.Info().Msgf(
		"TCP端口扫描任务: %d，并发: %d，连接超时: %ds，最坏耗时估算: %s",
		taskCount,
		workers,
		timeout,
		estimated,
	)

	Addrs := make(chan Addr, workers)
	results := make(chan string, workers)
	resultDone := make(chan struct{})

	//接收结果
	go func() {
		defer close(resultDone)
		for found := range results {
			AliveAddress = append(AliveAddress, found)

			t := strings.Split(found, ":")
			ip := t[0]

			count, ok := IPPortCount[ip]
			if ok {
				if count > structs.GlobalConfig.PortsThreshold {
					inblack := false
					BackListLock.Lock()
					_, inblack = BackList[ip]
					BackListLock.Unlock()
					if !inblack {
						BackListLock.Lock()
						BackList[ip] = struct{}{}
						BackListLock.Unlock()
						gologger.Error().Msgf("%s 端口数量超出阈值,放弃扫描", ip)
					}
				}
				IPPortCount[ip] = count + 1
			} else {
				IPPortCount[ip] = 1
			}
		}
	}()

	//多线程扫描
	var workerGroup sync.WaitGroup
	workerGroup.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer workerGroup.Done()
			for addr := range Addrs {
				if address, ok := PortConnect(addr, timeout); ok {
					results <- address
				}
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range IPs {
			Addrs <- Addr{host, port}
		}
	}
	close(Addrs)
	workerGroup.Wait()
	close(results)
	<-resultDone
	gologger.AuditTimeLogger("TCP端口扫描结束")

	return AliveAddress
}

func portScanTaskCount(hostCount, portCount int) int {
	if hostCount <= 0 || portCount <= 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if hostCount > maxInt/portCount {
		return maxInt
	}
	return hostCount * portCount
}

func tcpPortScanWorkerCount(requested, taskCount int) int {
	if taskCount <= 0 {
		return 0
	}
	if requested < 1 {
		requested = 1
	}
	if requested > taskCount {
		return taskCount
	}
	return requested
}

func estimateTCPPortScanDuration(taskCount, workers, timeoutSeconds int) time.Duration {
	if taskCount <= 0 || workers <= 0 || timeoutSeconds <= 0 {
		return 0
	}
	batches := taskCount / workers
	if taskCount%workers != 0 {
		batches++
	}
	return time.Duration(batches) * time.Duration(timeoutSeconds) * time.Second
}

type Addr struct {
	ip   string
	port int
}

var PortScan bool
var tcpPortDial = WrapperTcpWithTimeout

func PortConnect(addr Addr, adjustedTimeout int) (string, bool) {
	inblack := false
	BackListLock.Lock()
	_, inblack = BackList[addr.ip]
	BackListLock.Unlock()
	if inblack {
		return "", false
	}

	host, port := addr.ip, addr.port
	conn, err := tcpPortDial("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		if PortScan {
			// gologger.Silent().Msgf("[PortScan] %v", address)
			ddout.FormatOutput(ddout.OutputMessage{
				Type: "PortScan",
				IP:   host,
				Port: strconv.Itoa(port),
			})

		} else {
			// gologger.Silent().Msgf("[TCP-Alive] %v", address)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "IPAlive",
				IP:            host,
				AdditionalMsg: "TCP:" + strconv.Itoa(port),
			})
		}
		return address, true
	}
	return "", false
}

func PortScanSYN(IPs []string) []string {
	ips := strings.Join(utils.RemoveDuplicateElement(IPs), "\n")
	err := os.WriteFile("masscan_tmp.txt", []byte(ips), 0666)
	if err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(structs.GlobalConfig.MasscanPath)
	ms.SetFileName("masscan_tmp.txt")
	ms.SetPorts("1-65535")
	ms.SetRate(strconv.Itoa(structs.GlobalConfig.SYNPortScanThreads))
	gologger.Info().Msgf("调用masscan进行SYN端口扫描")
	err = ms.Run()
	gologger.AuditTimeLogger("masscan扫描结束")
	if err != nil {
		return []string{}
	}
	hosts, errParse := ms.Parse()
	if errParse != nil {
		gologger.Error().Msgf("masscan结果解析失败")
		return []string{}
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}
	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		// gologger.Silent().Msg("[PortScan] " + each)
		t := strings.Split(each, ":")
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   t[0],
			Port: t[1],
		})
	}
	return results
}

// CheckMasScan 校验MasScan是否正确安装
func CheckMasScan() bool {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", structs.GlobalConfig.MasscanPath)
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}
	_ = command.Wait()

	// 未检测到masscan的默认banner
	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}

	return true
}

func RemoveFirewall(ipPorts []string) []string {
	var results []string

	gologger.AuditTimeLogger("移除开放端口过多的目标")

	m := make(map[string][]string)
	for _, ipPort := range ipPorts {
		t := strings.Split(ipPort, ":")
		ip := t[0]
		port := t[1]

		_, ok := m[ip]
		if !ok {
			m[ip] = []string{port}
		} else {
			m[ip] = append(m[ip], port)
		}
	}

	for ip, ports := range m {
		ps := utils.RemoveDuplicateElement(ports)
		if len(ps) >= structs.GlobalConfig.PortsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, p := range ports {
			results = append(results, ip+":"+p)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
