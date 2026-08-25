package engine

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Control-payload compression: manifest batches get zstd-framed above ~4KiB
// so million-file trees do not bottleneck on control bandwidth. One encoder
// and one decoder per engine; both are guarded because senders encode from
// the walker goroutine while retries may compress from elsewhere.

const ctrlZstdThreshold = 4096
const ctrlMaxFrame = protocol_MaxCtrlPayload

// protocol_MaxCtrlPayload mirrors protocol.MaxCtrlPayload (kept local to
// avoid an import cycle in constant expressions).
const protocol_MaxCtrlPayload = 8 << 20

var (
	ctlOnce sync.Once
	ctlEnc  *zstd.Encoder
	ctlDec  *zstd.Decoder
	ctlErr  error
	ctlMu   sync.Mutex
)

func ctlCodecs() (*zstd.Encoder, *zstd.Decoder, error) {
	ctlOnce.Do(func() {
		ctlEnc, ctlErr = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if ctlErr != nil {
			return
		}
		ctlDec, ctlErr = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(ctrlMaxFrame))
	})
	return ctlEnc, ctlDec, ctlErr
}

// zstdCompressFrame compresses p when it clears the size threshold.
func zstdCompressFrame(p []byte) ([]byte, bool) {
	if len(p) < ctrlZstdThreshold {
		return p, false
	}
	enc, _, err := ctlCodecs()
	if err != nil {
		return p, false
	}
	ctlMu.Lock()
	defer ctlMu.Unlock()
	out := enc.EncodeAll(p, nil)
	if len(out) >= len(p) {
		return p, false
	}
	return out, true
}

// zstdDecompressFrame decompresses a control payload with a hard cap.
func zstdDecompressFrame(p []byte, max int) ([]byte, error) {
	_, dec, err := ctlCodecs()
	if err != nil {
		return nil, err
	}
	ctlMu.Lock()
	defer ctlMu.Unlock()
	out, err := dec.DecodeAll(p, nil)
	if err != nil {
		return nil, err
	}
	if len(out) > max {
		return nil, fmt.Errorf("control payload %dB over cap %d", len(out), max)
	}
	return out, nil
}
