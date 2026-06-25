package common

import (
	"testing"
	"time"

	"github.com/lcvvvv/gonmap"
)

type panicProtocolScanner struct{}

func (panicProtocolScanner) SetTimeout(time.Duration) {}

func (panicProtocolScanner) ScanTimeout(string, int, time.Duration) (gonmap.Status, *gonmap.Response) {
	panic("malformed banner")
}

func TestParseProtocolTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "IPv4", target: "192.0.2.1:443", wantHost: "192.0.2.1", wantPort: 443},
		{name: "domain", target: "example.com:8443", wantHost: "example.com", wantPort: 8443},
		{name: "trim spaces", target: " 127.0.0.1:22 ", wantHost: "127.0.0.1", wantPort: 22},
		{name: "missing port", target: "127.0.0.1", wantErr: true},
		{name: "invalid port", target: "127.0.0.1:ssh", wantErr: true},
		{name: "port too large", target: "127.0.0.1:65536", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			host, port, err := parseProtocolTarget(test.target)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseProtocolTarget(%q) returned nil error", test.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProtocolTarget(%q): %v", test.target, err)
			}
			if host != test.wantHost || port != test.wantPort {
				t.Fatalf("parseProtocolTarget(%q) = %q, %d; want %q, %d", test.target, host, port, test.wantHost, test.wantPort)
			}
		})
	}
}

func TestGetProtocolSkipsInvalidTargets(t *testing.T) {
	done := make(chan struct{})
	go func() {
		GetProtocol([]string{
			"missing-port",
			"127.0.0.1:not-a-port",
			"127.0.0.1:65536",
		}, 0, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GetProtocol blocked on invalid targets")
	}
}

func TestScanProtocolTargetRecoversScannerPanic(t *testing.T) {
	t.Parallel()

	_, err := scanProtocolTarget(panicProtocolScanner{}, "127.0.0.1:443", time.Second)
	if err == nil {
		t.Fatal("scanProtocolTarget() returned nil error after scanner panic")
	}
}
