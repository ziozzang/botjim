// Package sidecar manages the resume metadata that shadows every in-flight
// part file: chunk hashes, the have-bitmap, and the source identity (size +
// mtime) that invalidates the partial when the source changed.
//
// Naming: the part file is "<final>.fs-part-<nonce>" and the sidecar is
// "<final>.fs-meta-<nonce>.json", both in the final file's directory (same
// filesystem ⇒ atomic rename). The nonce separates concurrent sessions and
// disambiguates source trees that themselves contain "*.fs-part-*" names.
// Resume discovery globs the pattern, so a new session picks up an old
// session's part and keeps writing to it (adopting its nonce).
package sidecar

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/chunking"
	"github.com/ziozzang/botjim/internal/manifest"
)

// Version is the sidecar format version.
const Version = 1

// Sibling name affixes.
const (
	PartPrefix = ".fs-part-"
	MetaPrefix = ".fs-meta-"
)

// Sidecar is the JSON document shadowing a part file.
type Sidecar struct {
	Version      int       `json:"version"`
	Path         string    `json:"path"` // manifest-relative path
	Nonce        string    `json:"nonce"`
	SrcSize      int64     `json:"srcSize"`
	SrcMtime     Spec      `json:"srcMtime"`
	ChunkSize    int64     `json:"chunkSize"`
	ChunkCount   int64     `json:"chunkCount"`
	Hashes       []string  `json:"hashes"` // hex | "Z" (zero chunk) | "" (missing)
	HaveB64      string    `json:"have"`   // base64 bitmap; authoritative with Hashes
	FullyWritten bool      `json:"fullyWritten"`
	Updated      time.Time `json:"updated"`

	have []byte `json:"-"`
}

// Spec is a JSON-friendly manifest.Timespec.
type Spec struct {
	Sec  int64  `json:"sec"`
	Nsec uint32 `json:"nsec"`
}

// New creates a fresh sidecar for an entry and session nonce.
func New(e manifest.Entry, nonce string) *Sidecar {
	grid := e.Grid()
	sc := &Sidecar{
		Version:    Version,
		Path:       e.RelPath,
		Nonce:      nonce,
		SrcSize:    e.Size,
		SrcMtime:   Spec{Sec: e.Mtime.Sec, Nsec: e.Mtime.Nsec},
		ChunkSize:  grid.ChunkSize,
		ChunkCount: grid.Count(),
		Hashes:     make([]string, grid.Count()),
		Updated:    time.Now(),
	}
	sc.have = make([]byte, (grid.Count()+7)/8)
	return sc
}

// Have reports whether chunk i is verified present.
func (s *Sidecar) Have(i int64) bool {
	if i < 0 || i >= s.ChunkCount {
		return false
	}
	return s.have[i/8]&(1<<(uint(i)%8)) != 0
}

// SetHave marks chunk i present with its hash ("Z" for holes).
func (s *Sidecar) SetHave(i int64, h [32]byte, zero bool) {
	if i < 0 || i >= s.ChunkCount || int64(len(s.Hashes)) <= i {
		return
	}
	if zero {
		s.Hashes[i] = "Z"
	} else {
		s.Hashes[i] = hex.EncodeToString(h[:])
	}
	s.have[i/8] |= 1 << (uint(i) % 8)
}

// ClearHave unmarks chunk i (failed re-hash during resume verification).
func (s *Sidecar) ClearHave(i int64) {
	if i < 0 || i >= s.ChunkCount || int64(len(s.Hashes)) <= i {
		return
	}
	s.Hashes[i] = ""
	s.have[i/8] &^= 1 << (uint(i) % 8)
}

// HaveCount counts verified chunks.
func (s *Sidecar) HaveCount() int64 {
	n := int64(0)
	for i := int64(0); i < s.ChunkCount; i++ {
		if s.Have(i) {
			n++
		}
	}
	return n
}

// Complete reports whether every chunk is marked present.
func (s *Sidecar) Complete() bool { return s.HaveCount() == s.ChunkCount }

// Bitmap returns a copy of the have-bitmap.
func (s *Sidecar) Bitmap() []byte {
	out := make([]byte, len(s.have))
	copy(out, s.have)
	return out
}

// AdoptBitmap replaces the bitmap wholesale (after a resume re-hash pass).
func (s *Sidecar) AdoptBitmap(b []byte) {
	s.have = make([]byte, len(b))
	copy(s.have, b)
}

// ResizeHave fixes up the in-memory bitmap after Load.
func (s *Sidecar) ResizeHave() {
	need := (s.ChunkCount + 7) / 8
	if int64(len(s.have)) != need {
		fixed := make([]byte, need)
		copy(fixed, s.have)
		s.have = fixed
	}
}

// Validate checks the sidecar against a manifest entry. strictMtime compares
// mtimes too (default resume mode; --resume=size skips it).
func (s *Sidecar) Validate(e manifest.Entry, strictMtime bool) error {
	if s.Version != Version {
		return fmt.Errorf("sidecar version %d", s.Version)
	}
	if s.SrcSize != e.Size {
		return fmt.Errorf("size changed: %d → %d", s.SrcSize, e.Size)
	}
	if strictMtime && (s.SrcMtime.Sec != e.Mtime.Sec || s.SrcMtime.Nsec != e.Mtime.Nsec) {
		return fmt.Errorf("mtime changed")
	}
	if s.ChunkSize != chunking.ChunkSizeFor(e.Size) {
		return fmt.Errorf("chunk grid changed: %d vs %d", s.ChunkSize, chunking.ChunkSizeFor(e.Size))
	}
	if s.ChunkCount != e.Grid().Count() {
		return fmt.Errorf("chunk count changed")
	}
	if s.Path != e.RelPath {
		return fmt.Errorf("path mismatch: %q vs %q", s.Path, e.RelPath)
	}
	return nil
}

// PartPath builds the part file path for a final path and nonce.
func PartPath(finalAbs, nonce string) string {
	return finalAbs + PartPrefix + nonce
}

// MetaPath builds the sidecar path for a final path and nonce.
func MetaPath(finalAbs, nonce string) string {
	return finalAbs + MetaPrefix + nonce + ".json"
}

// MetaPathForPart derives the sidecar path from a part path.
func MetaPathForPart(partPath string) string {
	idx := strings.LastIndex(partPath, PartPrefix)
	if idx < 0 {
		return partPath + ".json"
	}
	final := partPath[:idx]
	nonce := partPath[idx+len(PartPrefix):]
	return MetaPath(final, nonce)
}

// Discover finds the newest existing part for a final path. It returns the
// part path, its sidecar path ("" when the sidecar is missing — the part is
// still resumable via full re-hash) and any stale older parts to prune.
func Discover(finalAbs string) (part, meta string, stale []string) {
	dir, base := filepath.Split(finalAbs)
	dir = filepath.Clean(dir)
	parts, err := filepath.Glob(filepath.Join(dir, base+PartPrefix+"*"))
	if err != nil || len(parts) == 0 {
		return "", "", nil
	}
	type cand struct {
		path string
		mod  time.Time
		size int64
	}
	var cs []cand
	for _, p := range parts {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		cs = append(cs, cand{p, fi.ModTime(), fi.Size()})
	}
	if len(cs) == 0 {
		return "", "", nil
	}
	sort.Slice(cs, func(i, j int) bool {
		if !cs[i].mod.Equal(cs[j].mod) {
			return cs[i].mod.After(cs[j].mod)
		}
		return cs[i].size > cs[j].size
	})
	part = cs[0].path
	meta = MetaPathForPart(part)
	if _, err := os.Stat(meta); err != nil {
		meta = ""
	}
	for _, c := range cs[1:] {
		stale = append(stale, c.path)
	}
	return part, meta, stale
}

// Load reads and sanity-checks a sidecar.
func Load(metaPath string) (*Sidecar, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var sc Sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, err
	}
	if sc.ChunkCount < 0 || int64(len(sc.Hashes)) != sc.ChunkCount {
		return nil, fmt.Errorf("sidecar chunk bookkeeping corrupt")
	}
	if raw, err := base64.StdEncoding.DecodeString(sc.HaveB64); err == nil {
		sc.have = raw
	} else {
		sc.have = nil
	}
	sc.ResizeHave()
	return &sc, nil
}

// SaveAtomic serializes and writes the sidecar via tmp+rename so a crash
// never leaves a torn document.
func (s *Sidecar) SaveAtomic(partPath string) error {
	s.Updated = time.Now()
	s.HaveB64 = base64.StdEncoding.EncodeToString(s.have)
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	meta := MetaPathForPart(partPath)
	tmp := meta + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, meta)
}
