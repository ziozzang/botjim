package chunking

import (
	"bytes"
	"testing"
)

func TestChunkSizeLadder(t *testing.T) {
	cases := []struct {
		size int64
		want int64
	}{
		{0, SmallChunk},
		{1, SmallChunk},
		{64 * MiB, SmallChunk},
		{64*MiB + 1, MediumChunk},
		{1 << 30, MediumChunk},
		{1<<30 + 1, LargeChunk},
		{1 << 40, LargeChunk},
	}
	for _, c := range cases {
		if got := ChunkSizeFor(c.size); got != c.want {
			t.Errorf("ChunkSizeFor(%d) = %d, want %d", c.size, got, c.want)
		}
	}
}

func TestGridBoundaries(t *testing.T) {
	for _, size := range []int64{0, 1, 4 * MiB, 4*MiB + 1, 12*MiB + 12345, 3 * LargeChunk} {
		g := NewGrid(size, 0)
		if size == 0 {
			if g.Count() != 0 {
				t.Errorf("size 0: count %d", g.Count())
			}
			continue
		}
		want := (size + g.ChunkSize - 1) / g.ChunkSize
		if g.Count() != want {
			t.Errorf("size %d: count %d want %d", size, g.Count(), want)
		}
		var total int64
		for i := int64(0); i < g.Count(); i++ {
			l := g.Len(i)
			if l <= 0 || l > g.ChunkSize {
				t.Fatalf("size %d chunk %d: bad len %d", size, i, l)
			}
			if g.Offset(i) != total {
				t.Fatalf("size %d chunk %d: offset %d want %d", size, i, g.Offset(i), total)
			}
			total += l
		}
		if total != size {
			t.Errorf("size %d: chunk lens sum %d", size, total)
		}
		if g.Len(g.Count()-1) != size-g.Offset(g.Count()-1) {
			t.Errorf("size %d: last chunk len mismatch", size)
		}
	}
}

func TestChunkSHABindsPathAndIndex(t *testing.T) {
	data := []byte("same payload")
	a := ChunkSHA("a", 0, data)
	b := ChunkSHA("b", 0, data)
	c := ChunkSHA("a", 1, data)
	if a == b {
		t.Error("hash must depend on path")
	}
	if a == c {
		t.Error("hash must depend on index")
	}
	if a != ChunkSHA("a", 0, data) {
		t.Error("hash must be deterministic")
	}
}

func TestAllZero(t *testing.T) {
	if !AllZero(nil) || !AllZero([]byte{}) || !AllZero(make([]byte, 100)) {
		t.Error("zero input must be all-zero")
	}
	for _, b := range [][]byte{{1}, {0, 0, 1}, make([]byte, 9)[:8+1]} {
		b[len(b)-1] = 1
		if AllZero(b) {
			t.Errorf("input with trailing 1 reported all-zero: %v", b)
		}
	}
	long := make([]byte, 4096)
	long[4095] = 1
	if AllZero(long) {
		t.Error("long input with trailing 1 reported all-zero")
	}
}

func TestZeroHashDistinct(t *testing.T) {
	if IsZero(ChunkSHA("x", 0, []byte{})) {
		t.Error("empty payload hash must differ from the zero marker")
	}
	if !bytes.Equal(ZeroHash[:], make([]byte, 32)) {
		t.Error("zero marker must be all zero bytes")
	}
}
