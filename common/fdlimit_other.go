//go:build !linux

package common

func prepareTCPScanFDLimit(requested int) (originalSoft, soft, hard uint64, raised bool, err error) {
	return 0, 0, 0, false, nil
}
