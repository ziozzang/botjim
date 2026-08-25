package protocol

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/ziozzang/botjim/internal/manifest"
)

func TestHandshakeRoundtrip(t *testing.T) {
	h, err := NewHandshake(FeatAll)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteHandshake(&buf, h); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 36 {
		t.Fatalf("handshake is %d bytes, want 36", buf.Len())
	}
	got, err := ReadHandshake(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.FeatureBits != FeatAll || got.ProtoMajor != ProtoMajor || got.CipherID != CipherPlain {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if got.Nonce != h.Nonce {
		t.Error("nonce mismatch")
	}
}

func TestHandshakeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"GET / HTTP/1.1\r\n\r\n",
		"FSY2" + string(make([]byte, 32)), // wrong magic
	} {
		if _, err := ReadHandshake(bytes.NewReader([]byte(bad))); err == nil {
			t.Errorf("garbage accepted: %q", bad)
		}
	}
	// corrupt CRC
	h, _ := NewHandshake(0)
	var buf bytes.Buffer
	_ = WriteHandshake(&buf, h)
	b := buf.Bytes()
	b[16] ^= 0xFF
	if _, err := ReadHandshake(bytes.NewReader(b)); err == nil {
		t.Error("corrupt handshake accepted")
	}
}

func TestCtrlStreamRoundtrip(t *testing.T) {
	var wire bytes.Buffer
	c := NewCtrlStream(&wire)
	big := bytes.Repeat([]byte("z"), 1<<20)
	if err := c.Send(MsgManifestBatch, CtrlFlagZstd, big); err != nil {
		t.Fatal(err)
	}
	// decode side over the same buffer
	d := NewCtrlStream(&wire)
	f, err := d.Recv(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != MsgManifestBatch || f.Flags != CtrlFlagZstd || !bytes.Equal(f.Payload, big) {
		t.Fatalf("frame mismatch: type=%#x len=%d", f.Type, len(f.Payload))
	}
}

func TestMessageCodecsRoundtrip(t *testing.T) {
	init := InitTransfer{Dir: DirPull, Compression: AlgZstd, ZstdLevel: 3, Preserve: 0xF, Parallel: 8, Resume: 1, RootName: "x", Paths: []string{"a", "b/c"}}
	gotInit, err := DecodeInitTransfer(init.Encode())
	if err != nil || !reflect.DeepEqual(gotInit, init) {
		t.Fatalf("InitTransfer: %+v err=%v", gotInit, err)
	}

	ack := TransferAck{OK: true, ErrCode: 7, Msg: "hi"}
	gotAck, err := DecodeTransferAck(ack.Encode())
	if err != nil || gotAck != ack {
		t.Fatalf("TransferAck: %+v err=%v", gotAck, err)
	}

	me := ManifestEnd{Files: 3, Bytes: 99, Dirs: 2, HasHardlinks: true}
	gotMe, err := DecodeManifestEnd(me.Encode())
	if err != nil || gotMe != me {
		t.Fatalf("ManifestEnd: %+v err=%v", gotMe, err)
	}

	hb := HaveBitmap{FileID: 42, Status: HavePartial, Bitmap: []byte{0b101}}
	gotHb, err := DecodeHaveBitmap(hb.Encode())
	if err != nil || gotHb.FileID != hb.FileID || gotHb.Status != hb.Status || !bytes.Equal(gotHb.Bitmap, hb.Bitmap) {
		t.Fatalf("HaveBitmap: %+v err=%v", gotHb, err)
	}

	fr := FileResult{FileID: 9, Status: ResultError, Code: 6, Msg: "nope"}
	gotFr, err := DecodeFileResult(fr.Encode())
	if err != nil || gotFr != fr {
		t.Fatalf("FileResult: %+v err=%v", gotFr, err)
	}

	cr := ChunkRetry{FileID: 1, ChunkIdx: 77, Reason: 2}
	gotCr, err := DecodeChunkRetry(cr.Encode())
	if err != nil || gotCr != cr {
		t.Fatalf("ChunkRetry: %+v err=%v", gotCr, err)
	}

	lr := ListReq{Path: "a/b", Offset: 3, Limit: 100}
	gotLr, err := DecodeListReq(lr.Encode())
	if err != nil || gotLr != lr {
		t.Fatalf("ListReq: %+v err=%v", gotLr, err)
	}

	lp := ListResp{Total: 5, Truncated: true, Entries: []ListEntry{{Name: "n", IsDir: true, Size: 9, MtimeMS: -1, Mode: 0o755}}}
	gotLp, err := DecodeListResp(lp.Encode())
	if err != nil || !reflect.DeepEqual(gotLp, lp) {
		t.Fatalf("ListResp: %+v err=%v", gotLp, err)
	}

	em := ErrMsg{Scope: ScopeFile, Code: 3, Msg: "x"}
	gotEm, err := DecodeErrMsg(em.Encode())
	if err != nil || gotEm != em {
		t.Fatalf("ErrMsg: %+v err=%v", gotEm, err)
	}

	dn := Done{Files: 1, Bytes: 2, Errors: 3}
	gotDn, err := DecodeDone(dn.Encode())
	if err != nil || gotDn != dn {
		t.Fatalf("Done: %+v err=%v", gotDn, err)
	}
}

func TestEntryCodecRoundtrip(t *testing.T) {
	entries := []manifest.Entry{
		{ID: 1, Kind: manifest.KindRegular, RelPath: "a/b.bin", Mode: 0o4711, UID: 1000, GID: 100,
			Mtime: manifest.Timespec{Sec: 1715000000, Nsec: 123456789}, Atime: manifest.Timespec{Sec: -5, Nsec: 1},
			Size: 12345678, ChunkSize: 4 << 20, Xattrs: []manifest.Xattr{{Name: "user.x", Value: []byte{1, 2, 3}}}},
		{ID: 2, Kind: manifest.KindDir, RelPath: "d", Mode: 0o750},
		{ID: 3, Kind: manifest.KindSymlink, RelPath: "l", LinkTarget: "../elsewhere"},
		{ID: 4, Kind: manifest.KindHardlink, RelPath: "h", LinkRefID: 1},
		{ID: 5, Kind: manifest.KindFIFO, RelPath: "f", Rdev: 77},
		{ID: 6, Kind: manifest.KindCharDev, RelPath: "c", Mode: 0o644, Rdev: 0x1234},
	}
	for _, e := range entries {
		enc := EncodeEntry(&e)
		got, used, err := DecodeEntry(enc)
		if err != nil {
			t.Fatalf("entry %s: %v", e.RelPath, err)
		}
		if used != len(enc) {
			t.Fatalf("entry %s: consumed %d of %d", e.RelPath, used, len(enc))
		}
		if !entryEqual(got, e) {
			t.Fatalf("entry %s mismatch:\n got %+v\nwant %+v", e.RelPath, got, e)
		}
	}
}

func entryEqual(a, b manifest.Entry) bool {
	a.AbsPath, b.AbsPath = "", ""
	if len(a.Xattrs) == 0 && len(b.Xattrs) == 0 {
		a.Xattrs, b.Xattrs = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

func TestManifestBatchRoundtrip(t *testing.T) {
	b := ManifestBatch{Entries: []manifest.Entry{
		{ID: 1, Kind: manifest.KindRegular, RelPath: "x", Size: 5, ChunkSize: 4 << 20},
		{ID: 2, Kind: manifest.KindDir, RelPath: "y"},
	}}
	got, err := DecodeManifestBatch(b.Encode())
	if err != nil || len(got.Entries) != 2 {
		t.Fatalf("batch: %+v err=%v", got, err)
	}
	if got.Entries[0].RelPath != "x" || got.Entries[1].RelPath != "y" {
		t.Fatalf("batch content: %+v", got.Entries)
	}
}

func TestTruncatedPayloadsRejected(t *testing.T) {
	init := InitTransfer{Dir: DirPush, Paths: []string{"a"}}.Encode()
	for n := 0; n < len(init); n++ {
		if _, err := DecodeInitTransfer(init[:n]); err == nil {
			t.Errorf("truncated InitTransfer at %d accepted", n)
		}
	}
	e := EncodeEntry(&manifest.Entry{ID: 1, Kind: manifest.KindRegular, RelPath: "x", Size: 1, ChunkSize: 4 << 20})
	for n := 0; n < len(e); n++ {
		if _, _, err := DecodeEntry(e[:n]); err == nil {
			t.Errorf("truncated entry at %d accepted", n)
		}
	}
}

func TestDataStreamChunkFrames(t *testing.T) {
	var wire bytes.Buffer
	ds, err := NewDataStream(&wire, 7)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("compressed-bytes")
	if err := ds.WriteChunk(ChunkHeader{FileID: 5, ChunkIdx: 12, Flags: 0, PayloadLen: uint64(len(payload))}, payload); err != nil {
		t.Fatal(err)
	}
	if err := ds.WriteChunk(ChunkHeader{FileID: 5, ChunkIdx: 13, Flags: ChunkFlagZero, PayloadLen: 0}, nil); err != nil {
		t.Fatal(err)
	}
	rds, idx, err := AcceptDataStream(&wire)
	if err != nil || idx != 7 {
		t.Fatalf("accept: idx=%d err=%v", idx, err)
	}
	h, p, err := rds.ReadChunk()
	if err != nil || h.FileID != 5 || h.ChunkIdx != 12 || !bytes.Equal(p, payload) {
		t.Fatalf("chunk1: %+v err=%v", h, err)
	}
	h, p, err = rds.ReadChunk()
	if err != nil || h.Flags&ChunkFlagZero == 0 || p != nil {
		t.Fatalf("chunk2 (zero): %+v err=%v", h, err)
	}
}

func TestVarintHelpers(t *testing.T) {
	var e enc
	for _, v := range []int64{-1 << 40, -1, 0, 1, 1 << 40} {
		e.sv(v)
	}
	var d dec
	d.b = e.b
	for _, want := range []int64{-1 << 40, -1, 0, 1, 1 << 40} {
		if got := d.sv(); got != want || d.err != nil {
			t.Fatalf("zigzag %d: got %d err=%v", want, got, d.err)
		}
	}
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:], 300)
	var e2 enc
	e2.uv(300)
	if !bytes.Equal(e2.b, b[:n]) {
		t.Error("uvarint encoding mismatch with stdlib")
	}
}
