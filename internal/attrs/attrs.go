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
	"strings"

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

// goMode converts raw POSIX mode bits (S_ISUID/S_ISGID/S_ISVTX included)
// into an os.FileMode the Chmod family interprets correctly.
func goMode(m uint32) os.FileMode {
	fm := os.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		fm |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		fm |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// ApplyFile applies entry metadata through an open fd and its on-disk path
// (order: chown, chmod, xattr, utimes). The path is used for nanosecond-
// precision utimensat; the fd keeps chown/chmod/xattr race-free. Returns
// warnings; a warning never fails the file.
func ApplyFile(fd *os.File, path string, e manifest.Entry, policy OwnerPolicy) []Warning {
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
	if err := utimensatFollow(path, e.Mtime, e.Atime); err != nil {
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

// MakeNode creates a fifo or device node. The mode is assembled from raw
// POSIX bits (perm + setuid/setgid/sticky) plus the node-type bits —
// passing os.FileMode's own bit layout to mknod produces a regular file
// with garbled permissions.
func MakeNode(abs string, e manifest.Entry) error {
	mode := rawModeBits(e.Mode)
	var err error
	switch e.Kind {
	case manifest.KindFIFO:
		err = unix.Mkfifo(abs, mode)
	case manifest.KindCharDev:
		err = unix.Mknod(abs, mode|unix.S_IFCHR, int(e.Rdev))
	case manifest.KindBlockDev:
		err = unix.Mknod(abs, mode|unix.S_IFBLK, int(e.Rdev))
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

// rawModeBits extracts perm + setuid/setgid/sticky from a full POSIX mode.
func rawModeBits(m uint32) uint32 {
	out := m & 0o777
	if m&0o4000 != 0 {
		out |= unix.S_ISUID
	}
	if m&0o2000 != 0 {
		out |= unix.S_ISGID
	}
	if m&0o1000 != 0 {
		out |= unix.S_ISVTX
	}
	return out
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

func utimensatFollow(path string, mtime, atime manifest.Timespec) error {
	ts := []unix.Timespec{
		{Sec: atime.Sec, Nsec: int64(atime.Nsec)},
		{Sec: mtime.Sec, Nsec: int64(mtime.Nsec)},
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, 0)
}

func utimensat(path string, mtime, atime manifest.Timespec) error {
	ts := []unix.Timespec{
		{Sec: atime.Sec, Nsec: int64(atime.Nsec)},
		{Sec: mtime.Sec, Nsec: int64(mtime.Nsec)},
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}

func applyXattrsFD(fd *os.File, e manifest.Entry) []Warning {
	var ws []Warning
	xs := sortedXattrs(e)
	for _, x := range xs {
		if !safeXattrName(x.Name) {
			continue // never apply security.*/system.*/trusted.* from a peer
		}
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
		if !safeXattrName(x.Name) {
			continue
		}
		if err := xattr.LSet(abs, x.Name, x.Value); err != nil {
			if isEPERMish(err) || errors.Is(err, unix.ENOTSUP) {
				continue
			}
			ws = append(ws, Warning{Path: e.RelPath, Op: "xattr " + x.Name, Err: err})
		}
	}
	return ws
}

// safeXattrName gates which xattrs a received manifest may set. Only the
// user.* namespace is honored: security.capability (file capabilities),
// system.posix_acl_* (ACLs) and trusted.* are privilege- or ACL-bearing
// and a malicious sender could otherwise set them on a root receiver
// (e.g. cap_setuid on an attacker-supplied binary — remote root).
func safeXattrName(name string) bool {
	return strings.HasPrefix(name, "user.")
}

func sortedXattrs(e manifest.Entry) []manifest.Xattr {
	xs := append([]manifest.Xattr(nil), e.Xattrs...)
	sort.Slice(xs, func(i, j int) bool { return xs[i].Name < xs[j].Name })
	return xs
}
