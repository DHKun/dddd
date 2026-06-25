package gonmap

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: gonmap-test\r\nContent-Length: 0\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	host, portRaw, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}

	scanner := New()
	status, response := scanner.ScanTimeout(host, port, 2*time.Second)
	if status != Open && status != Matched {
		t.Fatalf("ScanTimeout() status = %v, want Open or Matched", status)
	}
	if status == Matched && (response == nil || response.FingerPrint == nil) {
		t.Fatal("matched scan returned an empty response")
	}
	if status == Matched && response.FingerPrint.Service != "http" {
		t.Fatalf("service = %q, want http", response.FingerPrint.Service)
	}
}
