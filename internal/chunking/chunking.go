// Package chunking defines the deterministic chunk grid that every transfer
// is laid out on, and the chunk identity hash that ties a chunk to its file
// path, index and content.
//
// The ladder in ChunkSizeFor must never change for a given file size: resume
// sidecars record chunk positions derived from it, so any change would
// invalidate every partial file in the wild.
package chunking

import (
	"crypto/sha256"
	"encoding/binary"
)

// MiB is one mebibyte.
const MiB = 1 << 20

// Fixed chunk-size ladder. Files up to 64MiB use 4MiB chunks, up to 1GiB use
// 8MiB, larger files use 16MiB. All powers of two so grid offsets never need
// a divide.
const (
	SmallChunk  = 4 * MiB
	MediumChunk = 8 * MiB
	LargeChunk  = 16 * MiB
	smallLimit  = 64 * MiB
	mediumLimit = 1 << 30
)

// ChunkSizeFor returns the deterministic chunk size for a file of the given
// size. Zero-size files still get a nominal grid; their chunk count is 0.
func ChunkSizeFor(size int64) int64 {
	switch {
	case size <= smallLimit:
		return SmallChunk
	case size <= mediumLimit:
		return MediumChunk
	default:
		return LargeChunk
	}
}

// Grid is the chunk layout of one file: a fixed chunk size and total size.
type Grid struct {
	Size      int64
	ChunkSize int64
}

// NewGrid builds a grid for size, substituting chunkSize when it is a sane
// power-of-two override and 0 means "auto".
func NewGrid(size int64, chunkSize int64) Grid {
	if chunkSize <= 0 || chunkSize&(chunkSize-1) != 0 || chunkSize > LargeChunk || chunkSize < 512*1024 {
		chunkSize = ChunkSizeFor(size)
	}
	return Grid{Size: size, ChunkSize: chunkSize}
}

// Count returns the number of chunks in the grid (0 for empty files).
func (g Grid) Count() int64 {
	// defensive: Grid is often built directly from wire-decoded fields
	// (Entry.Grid bypasses NewGrid), so a crafted ChunkSize==0 must not
	// divide-by-zero and a near-MaxInt64 Size must not overflow the numerator
	if g.Size <= 0 || g.ChunkSize <= 0 {
		return 0
	}
	if g.Size > (1 << 62) {
		return 0 // absurd size: callers cap real files well below this
	}
	return (g.Size + g.ChunkSize - 1) / g.ChunkSize
}

// Offset returns the byte offset of chunk i.
func (g Grid) Offset(i int64) int64 { return i * g.ChunkSize }

// Len returns the byte length of chunk i (the last chunk may be short).
func (g Grid) Len(i int64) int64 {
	n := g.Size - i*g.ChunkSize
	if n > g.ChunkSize {
		n = g.ChunkSize
	}
	return n
}

// ChunkSHA is the identity of a chunk: SHA-256 over a domain tag, the file's
// manifest-relative path, the chunk index and the chunk payload. Binding the
// path and index into the hash means a frame that lands at the wrong file or
// offset fails verification even though its bytes are intact.
func ChunkSHA(relPath string, idx int64, payload []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	var v [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(v[:], uint64(len(relPath)))
	h.Write(v[:n])
	h.Write([]byte(relPath))
	n = binary.PutUvarint(v[:], uint64(idx))
	h.Write(v[:n])
	h.Write(payload)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// ZeroHash is the recorded hash for zero (sparse-hole) chunks, which carry no
// payload on the wire and no written bytes in the part file.
var ZeroHash = [32]byte{}

// IsZero reports whether h is the zero-chunk marker.
func IsZero(h [32]byte) bool { return h == ZeroHash }

// AllZero reports whether b consists entirely of zero bytes. It scans a word
// at a time and is used both by the sender (hole detection) and the receiver
// (resume re-hash of holes in sparse part files).
func AllZero(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	i := 0
	for ; i+8 <= len(b); i += 8 {
		if b[i] != 0 || b[i+1] != 0 || b[i+2] != 0 || b[i+3] != 0 ||
			b[i+4] != 0 || b[i+5] != 0 || b[i+6] != 0 || b[i+7] != 0 {
			return false
		}
	}
	for ; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
