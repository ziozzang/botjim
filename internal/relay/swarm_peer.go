package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/chunking"
	"github.com/ziozzang/botjim/internal/fsutil"
)

// SwarmSpec is the hashed description of one artifact: the swarm's
// ground truth. Written as <name>.swarm.json next to the seed data and
// shareable alongside the token.
type SwarmSpec struct {
	Version int         `json:"version"`
	Name    string      `json:"name"`
	Files   []SwarmFile `json:"files"`
}
type SwarmFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
	SHA  string `json:"sha256"` // whole-file hash: end-to-end verification
	// v2 chunk catalog: SHA-256 per grid chunk, in order. Lets joiners
	// verify every chunk as it lands (instead of only at finalize),
	// detect a lying peer immediately, and trust an existing part file
	// chunk-by-chunk on resume. Empty for v1 specs.
	Chunks []string `json:"chunks,omitempty"`
}

// SpecHash is the swarm ID.
func (s *SwarmSpec) SpecHash() string {
	h := sha256.New()
	for _, f := range s.Files {
		// Mode is bound in: an unsigned/MITM'd descriptor must not be able
		// to set e.g. setuid on a file whose content still hashes clean
		fmt.Fprintf(h, "%s\x00%d\x00%o\x00%s\x00", f.Path, f.Size, f.Mode&0o7777, f.SHA)
		for _, c := range f.Chunks {
			fmt.Fprintf(h, "%s\x00", c)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TotalBytes sums the file sizes.
func (s *SwarmSpec) TotalBytes() int64 {
	var n int64
	for _, f := range s.Files {
		n += f.Size
	}
	return n
}

// BuildSwarmSpec walks roots and hashes every file (whole-file SHA-256 —
// the joiner's end-to-end check). Chunk grids are the deterministic
// ladder, so every peer agrees on chunking without shipping the spec.
func BuildSwarmSpec(ctx context.Context, roots []string, name string) (*SwarmSpec, error) {
	type entry struct{ rel, abs string }
	var entries []entry
	for _, root := range roots {
		bases, err := swarmRelBase(roots)
		if err != nil {
			return nil, err
		}
		base := bases[root]
		err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(p, filepath.Dir(root)+string(filepath.Separator)), root)
			if base == "." {
				rel = strings.TrimPrefix(p, root+string(filepath.Separator))
			}
			if p == root {
				// the root IS the file: its rel is the basename (the full
				// path here used to desync the spec from the serve root,
				// so seeding a single file always answered MISS)
				rel = filepath.Base(p)
			}
			if rel == "" {
				rel = filepath.Base(p)
			}
			entries = append(entries, entry{rel: filepath.ToSlash(rel), abs: p})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	spec := &SwarmSpec{Version: 2, Name: name}
	for _, en := range entries {
		fi, err := os.Lstat(en.abs)
		if err != nil {
			return nil, err
		}
		h, chunks, err := hashFileChunks(en.abs, fi.Size())
		if err != nil {
			return nil, err
		}
		spec.Files = append(spec.Files, SwarmFile{
			Path: en.rel, Size: fi.Size(), Mode: uint32(fi.Mode().Perm()), SHA: h, Chunks: chunks,
		})
	}
	return spec, nil
}

// hashFileChunks streams the file once, producing the whole-file SHA and
// the per-chunk SHA-256 catalog on the deterministic grid.
func hashFileChunks(p string, size int64) (string, []string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	grid := chunking.NewGrid(size, chunking.ChunkSizeFor(size))
	whole := sha256.New()
	chunks := make([]string, 0, grid.Count())
	buf := make([]byte, 256<<10)
	for i := int64(0); i < grid.Count(); i++ {
		ch := sha256.New()
		remaining := grid.Len(i)
		for remaining > 0 {
			r := remaining
			if int64(len(buf)) < r {
				r = int64(len(buf))
			}
			got, err := io.ReadFull(f, buf[:r])
			if err != nil {
				return "", nil, err
			}
			whole.Write(buf[:got])
			ch.Write(buf[:got])
			remaining -= int64(got)
		}
		chunks = append(chunks, hex.EncodeToString(ch.Sum(nil)))
	}
	return hex.EncodeToString(whole.Sum(nil)), chunks, nil
}

func swarmRelBase(roots []string) (map[string]string, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("no roots")
	}
	out := map[string]string{}
	for _, r := range roots {
		out[r] = "."
	}
	return out, nil
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---- peer wire (inside the token-PSK record layer) ----
//
//	PEER1 <specHash>\n                  → OK\n | ERR mismatch\n
//	GET <fileIdx> <chunkIdx>\n          → <n>\n<bytes> | MISS\n
//
// fileIdx indexes spec.Files (sorted, stable). Dead simple on purpose:
// integrity rides the AEAD record layer; correctness rides the per-file
// SHA in the spec after assembly.

const peerWire = "PEER1"

// ServePeer answers GET requests from local files under root. One
// connection at a time is fine; seeds are expected to be few.
func ServePeer(ctx context.Context, ln net.Listener, spec *SwarmSpec, root, token string) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func(c net.Conn) {
			defer c.Close()
			// every peer link is e2ee with the swarm token as PSK
			wrapped, err := EncryptConn(c, []byte("botjim-swarm-psk/v1/"+NormalizeCode(token)), true)
			if err != nil {
				return
			}
			defer wrapped.Close()
			servePeerConn(ctx, wrapped, spec, root)
		}(conn)
	}
}

func servePeerConn(ctx context.Context, c net.Conn, spec *SwarmSpec, root string) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Minute))
	line, err := readSwarmLine(c)
	if err != nil || !strings.HasPrefix(line, peerWire+" ") {
		fmt.Fprintf(c, "ERR protocol\n")
		return
	}
	if strings.TrimSpace(line[len(peerWire):]) != spec.SpecHash() {
		fmt.Fprintf(c, "ERR mismatch\n")
		return
	}
	fmt.Fprint(c, "OK\n")
	for {
		line, err := readSwarmLine(c)
		if err != nil {
			return
		}
		var fileIdx, chunkIdx int64
		if _, err := fmt.Sscanf(line, "GET %d %d", &fileIdx, &chunkIdx); err != nil {
			fmt.Fprintf(c, "ERR get\n")
			return
		}
		if fileIdx < 0 || fileIdx >= int64(len(spec.Files)) {
			fmt.Fprint(c, "MISS\n")
			continue
		}
		f := spec.Files[fileIdx]
		grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
		if chunkIdx < 0 || chunkIdx >= grid.Count() {
			fmt.Fprint(c, "MISS\n")
			continue
		}
		abs, err := fsutil.SafeJoin(root, f.Path)
		if err != nil {
			fmt.Fprint(c, "MISS\n")
			continue
		}
		n := grid.Len(chunkIdx)
		buf := make([]byte, n)
		got, err := readChunkAt(abs, buf, grid.Offset(chunkIdx))
		if err != nil || int64(got) != n {
			fmt.Fprint(c, "MISS\n")
			continue
		}
		fmt.Fprintf(c, "%d\n", n)
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

func readChunkAt(p string, buf []byte, off int64) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.ReadAt(buf, off)
}

// PeerFetch pulls one chunk from a peer and returns the raw bytes.
// A MISS or a short read returns an error for re-routing.
func PeerFetch(ctx context.Context, peerAddr, specHash, token string, fileIdx, chunkIdx int64) ([]byte, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", peerAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	wrapped, err := EncryptConn(conn, []byte("botjim-swarm-psk/v1/"+NormalizeCode(token)), false)
	if err != nil {
		return nil, err
	}
	defer wrapped.Close()
	if _, err := fmt.Fprintf(wrapped, "%s %s\n", peerWire, specHash); err != nil {
		return nil, err
	}
	ok, err := readSwarmLine(wrapped)
	if err != nil || ok != "OK" {
		return nil, fmt.Errorf("peer refused: %s", ok)
	}
	if _, err := fmt.Fprintf(wrapped, "GET %d %d\n", fileIdx, chunkIdx); err != nil {
		return nil, err
	}
	head, err := readSwarmLine(wrapped)
	if err != nil {
		return nil, err
	}
	var n int64
	if head == "MISS" {
		return nil, ErrChunkMiss
	}
	if _, err := fmt.Sscanf(head, "%d", &n); err != nil || n <= 0 || n > 17<<20 {
		return nil, fmt.Errorf("bad peer reply %q", head)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(wrapped, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ErrChunkMiss marks a peer that does not (yet) hold the chunk.
var ErrChunkMiss = fmt.Errorf("chunk not held by this peer")
