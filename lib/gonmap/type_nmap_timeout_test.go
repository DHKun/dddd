package gonmap

import (
	"testing"
	"time"
)

func TestScanTimeoutRecoversScannerPanic(t *testing.T) {
	t.Parallel()

	scanner := &Nmap{}
	status, response := scanner.ScanTimeout("127.0.0.1", 1, time.Second)

	if status != Closed {
		t.Fatalf("ScanTimeout() status = %v, want %v", status, Closed)
	}
	if response != nil {
		t.Fatalf("ScanTimeout() response = %#v, want nil", response)
	}
}
