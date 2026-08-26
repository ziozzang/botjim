// Package manifest defines the transfer manifest — the deterministic
// description of every file, directory, symlink and special node being sent —
// and the walker that produces it.
//
// The walker is deterministic: entries are emitted per-directory in name
// order, hardlinked regular files are detected by (dev, ino) and only the
// first instance carries data. Relative paths are computed against the
// longest common ancestor of all roots so that two arguments sharing a
// directory reproduce that structure at the receiver.
package manifest

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/pkg/xattr"

	"github.com/ziozzang/botjim/internal/chunking"
)

// Kind is the entry type.
type Kind uint8

const (
	KindRegular Kind = iota
	KindDir
	KindSymlink
	KindHardlink
	KindFIFO
	KindCharDev
	KindBlockDev
	KindSocket
)

// String renders k for logs and TUI.
func (k Kind) String() string {
	switch k {
	case KindRegular:
		return "file"
	case KindDir:
		return "dir"
	case KindSymlink:
		return "symlink"
	case KindHardlink:
		return "hardlink"
	case KindFIFO:
		return "fifo"
	case KindCharDev:
		return "chardev"
	case KindBlockDev:
		return "blockdev"
	case KindSocket:
		return "socket"
	}
	return "?"
}

// Timespec is a Unix timestamp with nanoseconds.
type Timespec struct {
	Sec  int64
	Nsec uint32
}

// Equal compares two Timespecs.
func (t Timespec) Equal(o Timespec) bool { return t.Sec == o.Sec && t.Nsec == o.Nsec }

// Xattr is one extended attribute.
type Xattr struct {
	Name  string `json:"n"`
	Value []byte `json:"v"`
}

// Entry is one manifest record. Wire encoding lives in internal/protocol.
type Entry struct {
	ID         uint32
	Kind       Kind
	RelPath    string // '/' separated, relative to the manifest root, no leading '/'
	AbsPath    string // sender-side absolute path (never transmitted)
	Mode       uint32 // full POSIX mode bits incl. setuid/setgid/sticky
	UID, GID   uint32
	Uname      string
	Gname      string
	Mtime      Timespec
	Atime      Timespec
	Size       int64  // regular files
	Dev, Ino   uint64 // hardlink identity (sender side only)
	ChunkSize  int64
	LinkTarget string // symlink target
	LinkRefID  uint32 // hardlink: ID of the data-carrying entry
	Rdev       uint64 // device nodes
	Xattrs     []Xattr
}

// IsRegularData is true for entries the receiver writes as chunked part files.
func (e Entry) IsRegularData() bool { return e.Kind == KindRegular }

// Grid returns the chunk grid of a regular file entry.
func (e Entry) Grid() chunking.Grid { return chunking.Grid{Size: e.Size, ChunkSize: e.ChunkSize} }

// WalkOpts controls what the walker emits.
type WalkOpts struct {
	Xattrs     bool     // read extended attributes
	Hardlinks  bool     // detect hardlinks (else duplicates become full copies)
	Devices    bool     // emit fifo/device nodes (else skip with a warning)
	OneFS      bool     // do not cross filesystem boundaries
	UnameGname bool     // resolve uid/gid to names (cached lookups)
	Exclude    []string // glob patterns to skip (matched on basename or rel path)
	Include    []string // when set, only matching paths are kept
}

// excluded reports whether rel matches any of pats. A pattern with a '/'
// matches the whole relative path; a bare name matches any component.
func excluded(rel string, pats []string) bool {
	for _, pat := range pats {
		if strings.Contains(pat, "/") {
			if ok, _ := path.Match(pat, rel); ok {
				return true
			}
			continue
		}
		for _, comp := range strings.Split(rel, "/") {
			if ok, _ := path.Match(pat, comp); ok {
				return true
			}
		}
	}
	return false
}

// Skipped records something the walker declined to transfer.
type Skipped struct {
	Path string
	Why  string
}

// Walker walks roots and emits entries through emit. IDs are assigned at emit
// time in traversal order; the receiver sees the same numbering.
type Walker struct {
	Opts   WalkOpts
	OnSkip func(Skipped)
	// Home, when set, maps any root equal to it to the manifest-relative
	// "." — pulling "." mirrors the jail root's content instead of
	// wrapping it in the root's basename.
	Home string

	uidNames map[string]string
	gidNames map[string]string
	seen     map[devino]uint32 // (dev,ino) → first data-carrying entry ID
	skipped  []Skipped
	nextID   uint32
}

type devino struct{ dev, ino uint64 }

// Walk produces the manifest for roots. relFor maps each root to its
// manifest-relative base (see RelBase). Back-pressure on emit propagates to
// the filesystem walk naturally.
func (w *Walker) Walk(ctx context.Context, roots []string, emit func(Entry) error) error {
	w.seen = make(map[devino]uint32)
	w.uidNames = make(map[string]string)
	w.gidNames = make(map[string]string)
	w.skipped = nil

	bases, err := RelBase(roots)
	if err != nil {
		return err
	}
	if w.Home != "" {
		home := filepath.Clean(w.Home)
		for _, root := range roots {
			if filepath.Clean(root) == home {
				bases[root] = "."
			}
		}
	}
	for _, root := range roots {
		rootInfo, err := os.Lstat(root)
		if err != nil {
			return fmt.Errorf("%s: %w", root, err)
		}
		if err := w.walk(ctx, root, rootInfo, bases[root], emit); err != nil {
			return err
		}
	}
	return nil
}

// Skipped returns the things declined during the last Walk.
func (w *Walker) Skipped() []Skipped { return w.skipped }

func (w *Walker) skip(path, why string) {
	s := Skipped{Path: path, Why: why}
	w.skipped = append(w.skipped, s)
	if w.OnSkip != nil {
		w.OnSkip(s)
	}
}

// RelBase maps each root to the manifest-relative base it transfers under:
// the longest common ancestor directory of all roots is stripped. A single
// root keeps its own base name ("./foo" → "foo"; "/a/b /a/c" → "b", "c").
func RelBase(roots []string) (map[string]string, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("no roots")
	}
	clean := make([]string, len(roots))
	for i, r := range roots {
		c := filepath.Clean(r)
		if c == "/" {
			return nil, fmt.Errorf("refusing to transfer filesystem root %q", r)
		}
		clean[i] = c
	}
	anc := commonAncestor(clean)
	out := make(map[string]string, len(roots))
	for i, r := range roots {
		rel := strings.TrimPrefix(clean[i], anc)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			rel = "."
		}
		_ = i
		out[r] = rel
	}
	return out, nil
}

// commonAncestor returns the deepest path that is a prefix (by components)
// of every path. For a single path that is the path itself, so its basename
// survives in the manifest.
func commonAncestor(ps []string) string {
	if len(ps) == 1 {
		return filepath.Dir(ps[0])
	}
	parts := strings.Split(ps[0], "/")
	for _, p := range ps[1:] {
		other := strings.Split(p, "/")
		n := 0
		for n < len(parts) && n < len(other) && parts[n] == other[n] {
			n++
		}
		parts = parts[:n]
	}
	if len(parts) == 0 {
		return "/"
	}
	return strings.Join(parts, "/")
}

func (w *Walker) walk(ctx context.Context, path string, info os.FileInfo, rel string, emit func(Entry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e, skipWhy, err := w.entryFor(path, info, rel)
	if err != nil {
		return err
	}
	if skipWhy != "" {
		w.skip(path, skipWhy)
		return nil
	}
	w.nextID++
	e.ID = w.nextID
	if e.Kind == KindRegular {
		// Record the data-carrying instance so later links can reference it.
		w.seen[devino{e.Dev, e.Ino}] = e.ID
	}
	if err := emit(*e); err != nil {
		return err
	}
	if e.Kind != KindDir {
		return nil
	}
	return w.walkDir(ctx, path, rel, emit)
}

func (w *Walker) walkDir(ctx context.Context, path, rel string, emit func(Entry) error) error {
	parentDev := w.devOf(path)
	entries, err := os.ReadDir(path)
	if err != nil {
		w.skip(path, "readdir: "+err.Error())
		return nil
	}
	byName := make(map[string]os.DirEntry, len(entries))
	for _, de := range entries {
		byName[de.Name()] = de
	}
	names := make([]string, 0, len(entries))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names) // os.ReadDir sorts, but be explicit about determinism
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		child := filepath.Join(path, name)
		childRel := name
		if rel != "." {
			childRel = rel + "/" + name
		}
		if len(w.Opts.Exclude) > 0 && excluded(childRel, w.Opts.Exclude) {
			w.skip(child, "excluded by --exclude")
			continue
		}
		if len(w.Opts.Include) > 0 && !excluded(childRel, w.Opts.Include) {
			w.skip(child, "not matched by --include")
			continue
		}
		ci, err := byName[name].Info()
		if err != nil {
			w.skip(child, "lstat: "+err.Error())
			continue
		}
		if w.Opts.OneFS && w.devOf(child) != parentDev {
			w.skip(child, "different filesystem")
			continue
		}
		if err := w.walk(ctx, child, ci, childRel, emit); err != nil {
			return err
		}
	}
	return nil
}

func (w *Walker) devOf(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}

// entryFor converts one Lstat result into an Entry (or a skip reason).
func (w *Walker) entryFor(path string, info os.FileInfo, rel string) (*Entry, string, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		st = &syscall.Stat_t{}
	}
	mt, at := statTimes(st)
	e := &Entry{
		RelPath: rel,
		AbsPath: path,
		Mode:    uint32(st.Mode),
		UID:     st.Uid,
		GID:     st.Gid,
		Mtime:   mt,
		Atime:   at,
		Dev:     uint64(st.Dev),
		Ino:     uint64(st.Ino),
	}
	if w.Opts.UnameGname {
		e.Uname = w.lookupName(w.uidNames, e.UID, true)
		e.Gname = w.lookupName(w.gidNames, e.GID, false)
	}
	switch {
	case info.Mode().IsRegular():
		if w.Opts.Hardlinks && e.Ino != 0 {
			if first, dup := w.seen[devino{e.Dev, e.Ino}]; dup {
				e.Kind = KindHardlink
				e.LinkRefID = first
				return e, "", nil
			}
		}
		e.Kind = KindRegular
		e.Size = info.Size()
		e.ChunkSize = chunking.ChunkSizeFor(e.Size)
	case info.IsDir():
		e.Kind = KindDir
	case info.Mode()&os.ModeSymlink != 0:
		e.Kind = KindSymlink
		target, err := os.Readlink(path)
		if err != nil {
			return nil, "readlink: " + err.Error(), nil
		}
		e.LinkTarget = target
	case info.Mode()&os.ModeNamedPipe != 0:
		if !w.Opts.Devices {
			return nil, "fifo (--devices to include)", nil
		}
		e.Kind = KindFIFO
		e.Rdev = uint64(st.Rdev)
	case info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice != 0:
		if !w.Opts.Devices {
			return nil, "char device (--devices to include)", nil
		}
		e.Kind = KindCharDev
		e.Rdev = uint64(st.Rdev)
	case info.Mode()&os.ModeDevice != 0:
		if !w.Opts.Devices {
			return nil, "block device (--devices to include)", nil
		}
		e.Kind = KindBlockDev
		e.Rdev = uint64(st.Rdev)
	case info.Mode()&os.ModeSocket != 0:
		return nil, "socket (not transferable)", nil
	default:
		return nil, "unknown file type", nil
	}
	if w.Opts.Xattrs && (e.Kind == KindRegular || e.Kind == KindDir || e.Kind == KindSymlink) {
		if xs, err := ReadXattrs(path); err == nil {
			e.Xattrs = xs
		}
	}
	return e, "", nil
}

func (w *Walker) lookupName(cache map[string]string, id uint32, isUser bool) string {
	key := fmt.Sprint(id)
	if n, ok := cache[key]; ok {
		return n
	}
	var name string
	if isUser {
		if u, err := user.LookupId(key); err == nil {
			name = u.Username
		}
	} else {
		if g, err := user.LookupGroupId(key); err == nil {
			name = g.Name
		}
	}
	cache[key] = name
	return name
}

// MaxXattrTotal caps how many bytes of xattr values one entry may carry.
const MaxXattrTotal = 64 * 1024

// ReadXattrs reads all user-visible extended attributes of path (no
// symlink-follow), best-effort, total value bytes capped.
func ReadXattrs(path string) ([]Xattr, error) {
	names, err := xattr.LList(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	sort.Strings(names)
	var out []Xattr
	total := 0
	for _, n := range names {
		v, err := xattr.LGet(path, n)
		if err != nil {
			continue // vanished or not readable: skip quietly
		}
		total += len(v)
		if total > MaxXattrTotal {
			break
		}
		out = append(out, Xattr{Name: n, Value: v})
	}
	return out, nil
}
