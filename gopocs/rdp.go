package gopocs

import (
	"dddd/common"
	"dddd/ddout"
	"dddd/structs"
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

//go:embed dict/rdp.txt
var rdpUserPasswdDict string

type Brutelist struct {
	user string
	pass string
}

type rdpLoginState struct {
	once sync.Once
	done chan error
}

func newRDPLoginState() *rdpLoginState {
	return &rdpLoginState{
		done: make(chan error, 1),
	}
}

func (s *rdpLoginState) finish(err error) {
	s.once.Do(func() {
		s.done <- err
	})
}

func (s *rdpLoginState) recoverProtocolPanic(event interface{}, _ interface{}, err error) {
	s.finish(fmt.Errorf("rdp protocol panic during event %v: %w", event, err))
}

func RdpScan(info *structs.HostInfo) (tmperr error) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	userPasswdList := sortUserPassword(info, rdpUserPasswdDict, []string{})
	gologger.AuditTimeLogger("[Go] [RDP-Brute] start try %s:%v", info.Host, info.Ports)
	defer gologger.AuditTimeLogger("[Go] [RDP-Brute] RdpScan return %s:%v", info.Host, info.Ports)

	var wg sync.WaitGroup
	var signal bool
	var num = 0
	var all = len(userPasswdList)
	var mutex sync.Mutex
	brlist := make(chan Brutelist, all)
	port, _ := strconv.Atoi(info.Ports)

	for _, userPass := range userPasswdList {
		brlist <- Brutelist{userPass.UserName, userPass.Password}
	}

	for i := 0; i < 1; i++ {
		wg.Add(1)
		go worker(info.Host, "", port, &wg, brlist, &signal, &num, all, &mutex, 6)
	}

	close(brlist)
	wg.Wait()

	return tmperr
}

func worker(host, domain string, port int, wg *sync.WaitGroup, brlist chan Brutelist, signal *bool, num *int, all int, mutex *sync.Mutex, timeout int64) {
	defer wg.Done()
	for one := range brlist {
		if *signal == true {
			return
		}
		incrNum(num, mutex)
		user, pass := one.user, one.pass
		gologger.AuditTimeLogger("[Go] [RDP-Brute] start try %s:%v %v %v", host, port, user, pass)

		flag, err := RdpConn(host, domain, user, pass, port, timeout)
		if flag == true && err == nil {
			var result string
			if domain != "" {
				result = fmt.Sprintf("RDP://%v:%v:%v\\%v %v", host, port, domain, user, pass)
			} else {
				result = fmt.Sprintf("RDP://%v:%v:%v %v", host, port, user, pass)
			}

			// gologger.Silent().Msg("[GoPoc] " + result)
			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", host, port, user, pass)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{PocName: "RDP-Login",
					Security:    "CRITICAL",
					Target:      fmt.Sprintf("%v:%v", host, port),
					InfoLeft:    showData,
					Description: "RDP弱口令",
					ShowMsg:     result},
				AdditionalMsg: "",
			})

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "RDP-Login",
				Security:    "CRITICAL",
				Target:      fmt.Sprintf("%v:%v", host, port),
				InfoLeft:    showData,
				Description: "RDP弱口令",
			})

			*signal = true
			return
		}
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}

func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	target := fmt.Sprintf("%s:%d", ip, port)
	g := NewClient(target, glog.NONE)
	err := g.Login(domain, user, password, timeout)

	if err == nil {
		return true, nil
	}

	return false, err
}

type Client struct {
	Host string // ip:port
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

func NewClient(host string, logLevel glog.LEVEL) *Client {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Client{
		Host: host,
	}
}

func (g *Client) Login(domain, user, pwd string, timeout int64) error {
	timeoutDuration := time.Duration(timeout) * time.Second
	if timeoutDuration <= 0 {
		timeoutDuration = 6 * time.Second
	}

	conn, err := common.WrapperTcpWithTimeout("tcp", g.Host, timeoutDuration)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeoutDuration)); err != nil {
		return fmt.Errorf("[deadline err] %v", err)
	}
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	state := newRDPLoginState()
	g.tpkt.RecoverWith(state.recoverProtocolPanic)
	g.x224.RecoverWith(state.recoverProtocolPanic)
	g.mcs.RecoverWith(state.recoverProtocolPanic)
	g.sec.RecoverWith(state.recoverProtocolPanic)
	g.pdu.RecoverWith(state.recoverProtocolPanic)

	g.pdu.On("error", func(err error) {
		glog.Error("error", err)
		state.finish(err)
	})
	g.pdu.On("close", func() {
		glog.Info("on close")
		state.finish(fmt.Errorf("rdp connection closed"))
	})
	g.pdu.On("success", func() {
		glog.Info("on success")
		state.finish(nil)
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
		state.finish(nil)
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
	})

	//g.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)
	//g.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")

	timer := time.NewTimer(timeoutDuration)
	defer timer.Stop()

	select {
	case err := <-state.done:
		return err
	case <-timer.C:
		return fmt.Errorf("rdp login timeout after %s", timeoutDuration)
	}
}
