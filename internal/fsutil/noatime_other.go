//go:build !linux

package fsutil

import "os"

// OpenNoAtime is the portable fallback: platforms without O_NOATIME read
// normally (atime updates are relatime-mitigated anyway).
func OpenNoAtime(name string) (*os.File, error) {
	return os.Open(name)
}
