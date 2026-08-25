//go:build linux

package manifest

import "syscall"

func statTimes(st *syscall.Stat_t) (mtime, atime Timespec) {
	return Timespec{Sec: st.Mtim.Sec, Nsec: uint32(st.Mtim.Nsec)},
		Timespec{Sec: st.Atim.Sec, Nsec: uint32(st.Atim.Nsec)}
}
