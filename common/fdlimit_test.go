package common

import (
	"dddd/structs"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDesiredTCPScanFDSoftLimit(t *testing.T) {
	tests := []struct {
		name      string
		current   uint64
		hard      uint64
		requested int
		want      uint64
	}{
		{name: "raise common Linux soft limit", current: 1024, hard: 65535, requested: 4000, want: 4128},
		{name: "respect hard limit", current: 1024, hard: 2048, requested: 4000, want: 2048},
		{name: "keep sufficient current limit", current: 8192, hard: 8192, requested: 4000, want: 8192},
		{name: "normalize invalid request", current: 64, hard: 64, requested: 0, want: 64},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := desiredTCPScanFDSoftLimit(test.current, test.hard, test.requested); got != test.want {
				t.Fatalf("desiredTCPScanFDSoftLimit() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestEffectiveTCPScanThreads(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		soft      uint64
		want      int
	}{
		{name: "requested fits", requested: 4000, soft: 4128, want: 4000},
		{name: "reserve descriptors", requested: 4000, soft: 1024, want: 896},
		{name: "small limit keeps proportional reserve", requested: 4000, soft: 64, want: 48},
		{name: "invalid request becomes one", requested: 0, soft: 1024, want: 1},
		{name: "unknown limit preserves request", requested: 4000, soft: 0, want: 4000},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveTCPScanThreads(test.requested, test.soft); got != test.want {
				t.Fatalf("effectiveTCPScanThreads() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTCPPortScanWorkerCount(t *testing.T) {
	tests := []struct {
		requested int
		tasks     int
		want      int
	}{
		{requested: 4000, tasks: 65536, want: 4000},
		{requested: 4000, tasks: 20, want: 20},
		{requested: 0, tasks: 20, want: 1},
		{requested: -10, tasks: 20, want: 1},
		{requested: 4000, tasks: 0, want: 0},
	}

	for _, test := range tests {
		if got := tcpPortScanWorkerCount(test.requested, test.tasks); got != test.want {
			t.Fatalf("tcpPortScanWorkerCount(%d, %d) = %d, want %d", test.requested, test.tasks, got, test.want)
		}
	}
}

func TestEstimateTCPPortScanDuration(t *testing.T) {
	got := estimateTCPPortScanDuration(65536, 896, 6)
	want := 7*time.Minute + 24*time.Second
	if got != want {
		t.Fatalf("estimateTCPPortScanDuration() = %s, want %s", got, want)
	}
}

func TestPortScanTCPCompletesWithInvalidThreadCount(t *testing.T) {
	oldDial := tcpPortDial
	oldThreads := structs.GlobalConfig.TCPPortScanThreads
	tcpPortDial = func(string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("closed")
	}
	structs.GlobalConfig.TCPPortScanThreads = 0
	t.Cleanup(func() {
		tcpPortDial = oldDial
		structs.GlobalConfig.TCPPortScanThreads = oldThreads
	})

	done := make(chan []string, 1)
	go func() {
		done <- PortScanTCP([]string{"192.0.2.1", "192.0.2.2"}, "21,22", "", 1)
	}()

	select {
	case results := <-done:
		if len(results) != 0 {
			t.Fatalf("expected no open ports, got %v", results)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PortScanTCP deadlocked with zero configured threads")
	}
}

func BenchmarkPortScanTCPDispatch(b *testing.B) {
	oldDial := tcpPortDial
	oldThreads := structs.GlobalConfig.TCPPortScanThreads
	tcpPortDial = func(string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("closed")
	}
	structs.GlobalConfig.TCPPortScanThreads = 4000
	b.Cleanup(func() {
		tcpPortDial = oldDial
		structs.GlobalConfig.TCPPortScanThreads = oldThreads
	})

	hosts := make([]string, 4096)
	for i := range hosts {
		hosts[i] = "192.0.2.1"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PortScanTCP(hosts, "21,22", "", 1)
	}
}
