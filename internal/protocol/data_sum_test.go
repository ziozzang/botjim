package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestChunkSumDetectsCorruption: a flipped payload byte (or header bit)
// must fail the frame checksum.
func TestChunkSumDetectsCorruption(t *testing.T) {
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i * 13)
	}
	var wire bytes.Buffer
	ds := &DataStream{conn: rwBuf{&wire}}
	h := ChunkHeader{FileID: 7, ChunkIdx: 3, Flags: ChunkFlagRaw}
	if err := ds.WriteChunkSummed(h, body); err != nil {
		t.Fatal(err)
	}

	verify := func(frame []byte) error {
		rd, _, err := AcceptDataStream(rwBuf{bytes.NewBuffer(append([]byte{StreamKindData, 0}, frame...))})
		if err != nil {
			t.Fatal(err)
		}
		hd, payload, err := rd.ReadChunk()
		if err != nil {
			return err
		}
		bd := payload[:len(payload)-4]
		want := binary.LittleEndian.Uint32(payload[len(payload)-4:])
		if ChunkSum(hd, bd) != want {
			return errMismatch
		}
		return nil
	}
	good := append([]byte(nil), wire.Bytes()...)
	if err := verify(good); err != nil {
		t.Fatalf("clean frame failed: %v", err)
	}
	// flip one payload byte
	bad := append([]byte(nil), good...)
	bad[len(bad)-100] ^= 0x40
	if err := verify(bad); err != errMismatch {
		t.Fatalf("payload corruption not detected: %v", err)
	}
}

var errMismatch = &mismatchErr{}

type mismatchErr struct{}

func (*mismatchErr) Error() string { return "sum mismatch" }

type rwBuf struct{ *bytes.Buffer }
