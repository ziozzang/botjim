// Package compress wraps per-chunk compression. Chunks are compressed
// independently so resume works at chunk granularity; each worker owns its
// codec instance (compressors are stateful and not free-threaded).
//
// zstd uses klauspost/compress frame API (EncodeAll/DecodeAll); lz4 uses
// pierrec/lz4/v4 raw block API, which stores no length — exactly right here
// because the receiver already knows each chunk's expected size from the
// manifest grid, and that bound doubles as decompression-bomb protection.
package compress

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// Codec is a per-worker, per-chunk compressor. Compress returns (out, raw):
// when raw is true the caller must send the original bytes (compression did
// not shrink them). Decompress enforces maxLen so a corrupt or malicious
// frame cannot balloon memory.
type Codec interface {
	ID() uint8
	Compress(dst, src []byte) (out []byte, raw bool)
	Decompress(dst, src []byte, maxLen int) ([]byte, error)
	Close()
}

// Algorithm IDs from the wire protocol.
const (
	AlgNone uint8 = 0
	AlgZstd uint8 = 1
	AlgLz4  uint8 = 2
)

// New builds a codec for the negotiated algorithm; AlgNone returns nil (the
// caller then always sends raw chunks).
func New(alg uint8, zstdLevel int) (Codec, error) {
	switch alg {
	case AlgNone:
		return nil, nil
	case AlgZstd:
		return newZstd(zstdLevel)
	case AlgLz4:
		return newLZ4(), nil
	}
	return nil, fmt.Errorf("unknown compression algorithm %d", alg)
}

// zstdLevelToEncoder maps the CLI 1..4 scale onto encoder levels.
var zstdLevelToEncoder = []zstd.EncoderLevel{
	zstd.SpeedFastest,           // 1
	zstd.SpeedDefault,           // 2
	zstd.SpeedBetterCompression, // 3
	zstd.SpeedBestCompression,   // 4
}

// NormalizeZstdLevel clamps the CLI scale into 1..4.
func NormalizeZstdLevel(level int) int {
	if level < 1 {
		level = 1
	}
	if level > 4 {
		level = 4
	}
	return level
}

type zstdCodec struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

func newZstd(level int) (Codec, error) {
	lvl := NormalizeZstdLevel(level)
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstdLevelToEncoder[lvl-1]),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(256<<20),
	)
	if err != nil {
		return nil, err
	}
	return &zstdCodec{enc: enc, dec: dec}, nil
}

func (c *zstdCodec) ID() uint8 { return AlgZstd }

func (c *zstdCodec) Compress(dst, src []byte) ([]byte, bool) {
	out := c.enc.EncodeAll(src, dst[:0])
	if len(out) >= len(src) {
		return src, true
	}
	return out, false
}

func (c *zstdCodec) Decompress(dst, src []byte, maxLen int) ([]byte, error) {
	if len(src) > maxLen {
		return nil, fmt.Errorf("compressed %dB exceeds expected %dB", len(src), maxLen)
	}
	out, err := c.dec.DecodeAll(src, dst[:0])
	if err != nil {
		return nil, err
	}
	if len(out) > maxLen {
		return nil, fmt.Errorf("decompressed %dB exceeds expected %dB", len(out), maxLen)
	}
	return out, nil
}

func (c *zstdCodec) Close() {
	c.enc.Close()
	c.dec.Close()
}

type lz4Codec struct{}

func newLZ4() Codec { return &lz4Codec{} }

func (c *lz4Codec) ID() uint8 { return AlgLz4 }

func (c *lz4Codec) Compress(dst, src []byte) ([]byte, bool) {
	bound := lz4.CompressBlockBound(len(src))
	if cap(dst) < bound {
		dst = make([]byte, bound)
	}
	n, err := lz4.CompressBlock(src, dst[:bound], nil)
	// 0 = incompressible; the block API may also return output larger than
	// the input for high-entropy data — both fall back to raw.
	if err != nil || n == 0 || n >= len(src) {
		return src, true
	}
	return dst[:n], false
}

func (c *lz4Codec) Decompress(dst, src []byte, maxLen int) ([]byte, error) {
	if len(src) > maxLen {
		return nil, fmt.Errorf("compressed %dB exceeds expected %dB", len(src), maxLen)
	}
	if cap(dst) < maxLen {
		dst = make([]byte, maxLen)
	}
	n, err := lz4.UncompressBlock(src, dst[:maxLen])
	if err != nil {
		return nil, err
	}
	if n != maxLen {
		return nil, fmt.Errorf("decompressed %dB, expected %dB", n, maxLen)
	}
	return dst[:n], nil
}

func (c *lz4Codec) Close() {}
