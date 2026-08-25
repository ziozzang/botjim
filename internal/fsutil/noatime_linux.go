//go:build linux

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenNoAtime opens name for reading without updating its atime.
// O_NOATIME requires ownership or CAP_FOWNER; on EPERM it silently falls
// back to a plain open (relatime makes the update a non-issue mostly).
func OpenNoAtime(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOATIME, 0)
	if err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return os.Open(name)
		}
		if err == unix.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
