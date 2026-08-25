package compress

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestCodecsRoundtrip(t *testing.T) {
	payloads := [][]byte{
		bytes.Repeat([]byte("A"), 1<<20),
		make([]byte, 8<<20), // zeros (sparse-ish)
		func() []byte {
			r := rand.New(rand.NewSource(1))
			b := make([]byte, 3<<20)
			r.Read(b)
			return b
		}(),
		[]byte("tiny"),
		nil,
	}
	for _, alg := range []uint8{AlgZstd, AlgLz4} {
		for level := range []int{1, 4} {
			c, err := New(alg, level)
			if err != nil {
				t.Fatalf("alg %d: %v", alg, err)
			}
			if c == nil {
				t.Fatal("codec nil")
			}
			var zbuf []byte
			for i, p := range payloads {
				out, raw := c.Compress(zbuf, p)
				if !raw && len(out) >= len(p) {
					t.Fatalf("alg %d payload %d: compressed %d >= raw %d", alg, i, len(out), len(p))
				}
				if raw {
					continue // raw fallback: the wire carries the original bytes
				}
				zbuf = out
				got, err := c.Decompress(nil, out, len(p))
				if err != nil {
					t.Fatalf("alg %d payload %d decompress: %v", alg, i, err)
				}
				if !bytes.Equal(got, p) {
					t.Fatalf("alg %d payload %d: roundtrip mismatch (%d vs %d bytes)", alg, i, len(got), len(p))
				}
			}
			c.Close()
		}
	}
}

func TestDecompressCapEnforced(t *testing.T) {
	for _, alg := range []uint8{AlgZstd, AlgLz4} {
		c, _ := New(alg, 3)
		if c == nil {
			continue
		}
		out, raw := c.Compress(nil, bytes.Repeat([]byte("x"), 1<<20))
		if raw {
			continue
		}
		// claim a much smaller expected size: must refuse
		if _, err := c.Decompress(nil, out, 1024); err == nil {
			t.Fatalf("alg %d: decompression bomb cap not enforced", alg)
		}
		// oversize compressed input must also refuse
		if _, err := c.Decompress(nil, bytes.Repeat([]byte{0xFF}, 1<<20), 16); err == nil {
			t.Fatalf("alg %d: oversize compressed input accepted", alg)
		}
		c.Close()
	}
}

func TestNoneCodecIsNil(t *testing.T) {
	c, err := New(AlgNone, 3)
	if err != nil || c != nil {
		t.Fatalf("none: %v %v", c, err)
	}
	if _, err := New(99, 3); err == nil {
		t.Fatal("unknown alg accepted")
	}
}
