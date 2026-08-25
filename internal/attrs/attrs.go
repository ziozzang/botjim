//go:build unix

// Package attrs applies manifest entry metadata to received files. The apply
// order is protocol: chown before chmod (chown clears setuid/setgid bits),
// xattr before utimes (xattr writes bump ctime only), utimes last (data
// writes dirty mtime). Everything that needs privileges degrades to a
// warning instead of failing the file.
package attrs

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/pkg/xattr"
	"golang.org/x/sys/unix"

	"github.com/ziozzang/botjim/internal/manifest"
)

// OwnerPolicy controls uid/gid handling.
type OwnerPolicy uint8

const (
	OwnerNone    OwnerPolicy = iota // do not touch ownership (default)
	OwnerNumeric                    // apply uid/gid numbers
	OwnerName                       // map uname/gname to local ids, fall back to numeric
)

// Warning is a non-fatal attribute application failure.
type Warning struct {
	Path string
	Op   string
	Err  error
}

func (w Warning) String() string { return fmt.Sprintf("%s: %s: %v", w.Path, w.Op, w.Err) }

func isEPERMish(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func goMode(m uint32) os.FileMode { return os.FileMode(m & 0o7777) }

// ApplyFile applies entry metadata through an open fd (order: chown, chmod,
// xattr, utimes). Returns warnings; a warning never fails the file.
func ApplyFile(fd *os.File, e manifest.Entry, policy OwnerPolicy) []Warning {
	var ws []Warning
	if policy != OwnerNone {
		uid, gid, ok := resolveOwner(e, policy)
		if ok {
			if err := fd.Chown(int(uid), int(gid)); err != nil && !isEPERMish(err) {
				ws = append(ws, Warning{Path: e.RelPath, Op: "chown", Err: err})
			} else if err != nil {
				ws = append(ws, Warning{Path: e.RelPath, Op: "chown(unprivileged)", Err: err})
			}
		}
	}
	if err := fd.Chmod(goMode(e.Mode)); err != nil {
		ws = append(ws, Warning{Path: e.RelPath, Op: "chmod", Err: err})
	}
	ws = append(ws, applyXattrsFD(fd, e)...)
	if err := futimens(fd, e.Mtime, e.Atime); err != nil {
		ws = append(ws, Warning{Path: e.RelPath, Op: "utimes", Err: err})
	}
	return ws
}

// ApplyPath applies metadata to a path without following a final symlink
// (directories, symlinks, special nodes).
func ApplyPath(abs string, e manifest.Entry, policy OwnerPolicy) []Warning {
	var ws []Warning
	flags := unix.AT_SYMLINK_NOFOLLOW
	if policy != OwnerNone {
		uid, gid, ok := resolveOwner(e, policy)
		if ok {
			if err := unix.Fchownat(unix.AT_FDCWD, abs, int(uid), int(gid), flags); err != nil {
				ws = append(ws, Warning{Path: e.RelPath, Op: "lchown", Err: err})
			}
		}
	}
	// lchmod does not exist on Linux: symlink modes are kernel-fixed at 0777.
	if e.Kind != manifest.KindSymlink {
		if err := os.Chmod(abs, goMode(e.Mode)); err != nil {
			ws = append(ws, Warning{Path: e.RelPath, Op: "chmod", Err: err})
		}
	} else if e.Mode&0o777 != 0o777 {
		ws = append(ws, Warning{Path: e.RelPath, Op: "lchmod", Err: fmt.Errorf("symlink mode %04o not representable on Linux (always 0777)", e.Mode&0o777)})
	}
	ws = append(ws, applyXattrsPath(abs, e)...)
	if err := utimensat(abs, e.Mtime, e.Atime); err != nil {
		ws = append(ws, Warning{Path: e.RelPath, Op: "lutimes", Err: err})
	}
	return ws
}

// MakeSymlink creates (or replaces) a symlink at abs.
func MakeSymlink(abs string, e manifest.Entry) error {
	if fi, err := os.Lstat(abs); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if cur, err := os.Readlink(abs); err == nil && cur == e.LinkTarget {
				return nil
			}
		}
		if err := os.Remove(abs); err != nil {
			return fmt.Errorf("replace existing: %w", err)
		}
	}
	return os.Symlink(e.LinkTarget, abs)
}

// MakeNode creates a fifo or device node.
func MakeNode(abs string, e manifest.Entry) error {
	mode := goMode(e.Mode)
	var dev uint64
	var err error
	switch e.Kind {
	case manifest.KindFIFO:
		err = unix.Mkfifo(abs, uint32(mode))
	case manifest.KindCharDev:
		dev = e.Rdev
		err = unix.Mknod(abs, uint32(mode), int(dev))
	case manifest.KindBlockDev:
		dev = e.Rdev
		err = unix.Mknod(abs, uint32(mode), int(dev))
	default:
		return fmt.Errorf("not a special node: %v", e.Kind)
	}
	if err != nil {
		if isEPERMish(err) {
			return fmt.Errorf("%s requires privileges (run as root or CAP_MKNOD): %w", e.Kind, err)
		}
		return err
	}
	return nil
}

// MakeHardlink links src (already-finalized file) to dst.
func MakeHardlink(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		if err := os.Remove(dst); err != nil {
			return err
		}
	}
	return os.Link(src, dst)
}

func resolveOwner(e manifest.Entry, policy OwnerPolicy) (uid, gid uint32, ok bool) {
	switch policy {
	case OwnerNumeric:
		return e.UID, e.GID, true
	case OwnerName:
		uid, gid = e.UID, e.GID
		if e.Uname != "" {
			if u, err := lookupUser(e.Uname); err == nil {
				uid = u
			}
		}
		if e.Gname != "" {
			if g, err := lookupGroup(e.Gname); err == nil {
				gid = g
			}
		}
		return uid, gid, true
	}
	return 0, 0, false
}

func futimens(fd *os.File, mtime, atime manifest.Timespec) error {
	tv := []unix.Timeval{
		{Sec: atime.Sec, Usec: int64(atime.Nsec / 1000)},
		{Sec: mtime.Sec, Usec: int64(mtime.Nsec / 1000)},
	}
	return unix.Futimes(int(fd.Fd()), tv)
}

func utimensat(path string, mtime, atime manifest.Timespec) error {
	tv := []unix.Timeval{
		{Sec: atime.Sec, Usec: int64(atime.Nsec / 1000)},
		{Sec: mtime.Sec, Usec: int64(mtime.Nsec / 1000)},
	}
	return unix.Lutimes(path, tv)
}

func applyXattrsFD(fd *os.File, e manifest.Entry) []Warning {
	var ws []Warning
	xs := sortedXattrs(e)
	for _, x := range xs {
		if err := xattr.FSet(fd, x.Name, x.Value); err != nil {
			if isEPERMish(err) || errors.Is(err, unix.ENOTSUP) {
				continue // security.*/trusted.* on unprivileged receiver: skip quietly
			}
			ws = append(ws, Warning{Path: e.RelPath, Op: "xattr " + x.Name, Err: err})
		}
	}
	return ws
}

func applyXattrsPath(abs string, e manifest.Entry) []Warning {
	var ws []Warning
	xs := sortedXattrs(e)
	for _, x := range xs {
		if err := xattr.LSet(abs, x.Name, x.Value); err != nil {
			if isEPERMish(err) || errors.Is(err, unix.ENOTSUP) {
				continue
			}
			ws = append(ws, Warning{Path: e.RelPath, Op: "xattr " + x.Name, Err: err})
		}
	}
	return ws
}

func sortedXattrs(e manifest.Entry) []manifest.Xattr {
	xs := append([]manifest.Xattr(nil), e.Xattrs...)
	sort.Slice(xs, func(i, j int) bool { return xs[i].Name < xs[j].Name })
	return xs
}
