//go:build darwin

package manifest

import "syscall"

func statTimes(st *syscall.Stat_t) (mtime, atime Timespec) {
	return Timespec{Sec: st.Mtimespec.Sec, Nsec: uint32(st.Mtimespec.Nsec)},
		Timespec{Sec: st.Atimespec.Sec, Nsec: uint32(st.Atimespec.Nsec)}
}
