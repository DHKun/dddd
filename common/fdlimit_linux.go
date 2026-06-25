//go:build linux

package common

import "syscall"

func prepareTCPScanFDLimit(requested int) (originalSoft, soft, hard uint64, raised bool, err error) {
	var limit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, 0, 0, false, err
	}

	originalSoft = limit.Cur
	soft = limit.Cur
	hard = limit.Max
	target := desiredTCPScanFDSoftLimit(limit.Cur, limit.Max, requested)
	if target <= limit.Cur {
		return originalSoft, soft, hard, false, nil
	}

	limit.Cur = target
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return originalSoft, soft, hard, false, err
	}
	return originalSoft, target, hard, true, nil
}
