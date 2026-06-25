//go:build linux

package common

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestTCPScanFDLimitRaisesSoftLimit(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestTCPScanFDLimitSubprocessHelper$")
	command.Env = append(os.Environ(), "DDDD_FD_LIMIT_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fd limit subprocess failed: %v\n%s", err, output)
	}
}

func TestTCPScanFDLimitSubprocessHelper(t *testing.T) {
	if os.Getenv("DDDD_FD_LIMIT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}

	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if limit.Max < 512 {
		t.Skipf("hard file descriptor limit is too low: %d", limit.Max)
	}

	limit.Cur = 256
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Skipf("cannot lower soft file descriptor limit: %v", err)
	}

	originalSoft, soft, hard, raised, err := prepareTCPScanFDLimit(400)
	if err != nil {
		t.Fatalf("prepareTCPScanFDLimit: %v", err)
	}
	if originalSoft != 256 {
		t.Fatalf("original soft limit = %d, want 256", originalSoft)
	}
	if hard != limit.Max {
		t.Fatalf("hard limit = %d, want %d", hard, limit.Max)
	}
	if !raised {
		t.Fatal("expected soft file descriptor limit to be raised")
	}
	if want := desiredTCPScanFDSoftLimit(256, limit.Max, 400); soft != want {
		t.Fatalf("soft limit = %d, want %d", soft, want)
	}
}
