package common

const tcpScanFDReserve uint64 = 128

type tcpScanFDStatus struct {
	Requested    int
	Effective    int
	OriginalSoft uint64
	Soft         uint64
	Hard         uint64
	Raised       bool
	Err          error
}

func configureTCPScanThreads(requested int) tcpScanFDStatus {
	status := tcpScanFDStatus{Requested: requested}
	normalized := requested
	if normalized < 1 {
		normalized = 1
	}

	status.OriginalSoft, status.Soft, status.Hard, status.Raised, status.Err = prepareTCPScanFDLimit(normalized)
	status.Effective = effectiveTCPScanThreads(normalized, status.Soft)
	return status
}

func desiredTCPScanFDSoftLimit(current, hard uint64, requested int) uint64 {
	if requested < 1 {
		requested = 1
	}
	if hard == 0 {
		return current
	}

	desired := uint64(requested)
	if desired <= ^uint64(0)-tcpScanFDReserve {
		desired += tcpScanFDReserve
	}
	if desired > hard {
		desired = hard
	}
	if desired < current {
		return current
	}
	return desired
}

func effectiveTCPScanThreads(requested int, softLimit uint64) int {
	if requested < 1 {
		requested = 1
	}
	if softLimit == 0 {
		return requested
	}

	available := softLimit
	if available > tcpScanFDReserve {
		available -= tcpScanFDReserve
	} else if available > 1 {
		available -= available / 4
	}
	if available == 0 {
		return 1
	}
	if uint64(requested) > available {
		return int(available)
	}
	return requested
}
