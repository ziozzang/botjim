package protocol

import (
	"fmt"

	"github.com/ziozzang/botjim/internal/manifest"
)

// Direction of a transfer.
const (
	DirPush uint8 = 0 // client → server
	DirPull uint8 = 1 // server → client
)

// Compression algorithms (also data-frame-external: negotiated once per
// transfer, applied per chunk with a raw fallback flag).
const (
	AlgNone uint8 = 0
	AlgZstd uint8 = 1
	AlgLz4  uint8 = 2
)

// PreserveBits in InitTransfer.
const (
	PreserveXattr    uint16 = 1 << 0
	PreserveHardlink uint16 = 1 << 1
	PreserveSparse   uint16 = 1 << 2
	PreserveDevices  uint16 = 1 << 3
	PreserveUname    uint16 = 1 << 4
	PreserveOwners   uint16 = 1 << 5
	PreserveDryRun   uint16 = 1 << 6 // plan only: receiver reports haves, sends nothing
	PreserveDelete   uint16 = 1 << 7 // mirror: delete dest entries missing from the manifest
)

// InitTransfer opens a transfer on a session. Paths carries the pull-side
// roots (server-relative) when Dir is pull.
type InitTransfer struct {
	Dir         uint8
	Compression uint8
	ZstdLevel   uint8 // 1..4 mapped onto encoder levels
	ChunkPolicy uint8 // 0 = auto ladder
	Preserve    uint16
	Parallel    uint8
	Resume      uint8 // 0 = on (strict), 1 = size-only, 2 = fresh
	RootName    string
	Paths       []string
}

// Encode serializes m.
func (m InitTransfer) Encode() []byte {
	var e enc
	e.u8(m.Dir)
	e.u8(m.Compression)
	e.u8(m.ZstdLevel)
	e.u8(m.ChunkPolicy)
	e.u16(m.Preserve)
	e.u8(m.Parallel)
	e.u8(m.Resume)
	e.str(m.RootName)
	e.uv(uint64(len(m.Paths)))
	for _, p := range m.Paths {
		e.str(p)
	}
	return e.b
}

// DecodeInitTransfer parses an InitTransfer payload.
func DecodeInitTransfer(p []byte) (InitTransfer, error) {
	var d dec
	d.b = p
	var m InitTransfer
	m.Dir = d.u8()
	m.Compression = d.u8()
	m.ZstdLevel = d.u8()
	m.ChunkPolicy = d.u8()
	m.Preserve = d.u16()
	m.Parallel = d.u8()
	m.Resume = d.u8()
	m.RootName = d.str()
	n := d.uv()
	if n > 4096 {
		return m, fmt.Errorf("too many pull paths: %d", n)
	}
	for i := uint64(0); i < n; i++ {
		m.Paths = append(m.Paths, d.str())
	}
	if d.err != nil {
		return m, d.err
	}
	if m.Dir != DirPush && m.Dir != DirPull {
		return m, fmt.Errorf("bad direction %d", m.Dir)
	}
	return m, nil
}

// TransferAck answers InitTransfer.
type TransferAck struct {
	OK      bool
	ErrCode uint16
	Msg     string
}

// Encode serializes m.
func (m TransferAck) Encode() []byte {
	var e enc
	ok := uint8(0)
	if m.OK {
		ok = 1
	}
	e.u8(ok)
	e.u16(m.ErrCode)
	e.str(m.Msg)
	return e.b
}

// DecodeTransferAck parses a TransferAck payload.
func DecodeTransferAck(p []byte) (TransferAck, error) {
	var d dec
	d.b = p
	var m TransferAck
	m.OK = d.u8() == 1
	m.ErrCode = d.u16()
	m.Msg = d.str()
	return m, d.err
}

// ManifestBatch carries up to a few hundred entries; large batches are
// zstd-compressed at the frame level (CtrlFlagZstd).
type ManifestBatch struct {
	Entries []manifest.Entry
}

// EncodeEntry serializes one entry. Field order is part of the wire format.
func EncodeEntry(e *manifest.Entry) []byte {
	var b enc
	b.u8(uint8(e.Kind))
	b.str(e.RelPath)
	b.uv(uint64(e.ID))
	b.u32(e.Mode)
	b.sv(int64(e.UID))
	b.sv(int64(e.GID))
	b.str(e.Uname)
	b.str(e.Gname)
	b.sv(e.Mtime.Sec)
	b.uv(uint64(e.Mtime.Nsec))
	b.sv(e.Atime.Sec)
	b.uv(uint64(e.Atime.Nsec))
	switch e.Kind {
	case manifest.KindRegular:
		b.u64(uint64(e.Size))
		b.u64(e.Dev)
		b.u64(e.Ino)
		b.u32(uint32(e.ChunkSize))
	case manifest.KindHardlink:
		b.uv(uint64(e.LinkRefID))
	case manifest.KindSymlink:
		b.str(e.LinkTarget)
	case manifest.KindFIFO, manifest.KindCharDev, manifest.KindBlockDev:
		b.u64(e.Rdev)
	}
	b.uv(uint64(len(e.Xattrs)))
	for _, x := range e.Xattrs {
		b.str(x.Name)
		b.bytes(x.Value)
	}
	return b.b
}

// DecodeEntry parses one entry from the front of p, returning the entry and
// the number of bytes consumed (0 with an error on parse failure).
func DecodeEntry(p []byte) (manifest.Entry, int, error) {
	var d dec
	d.b = p
	var e manifest.Entry
	e.Kind = manifest.Kind(d.u8())
	e.RelPath = d.str()
	e.ID = uint32(d.uv())
	e.Mode = d.u32()
	e.UID = uint32(d.sv())
	e.GID = uint32(d.sv())
	e.Uname = d.str()
	e.Gname = d.str()
	e.Mtime.Sec = d.sv()
	e.Mtime.Nsec = uint32(d.uv())
	e.Atime.Sec = d.sv()
	e.Atime.Nsec = uint32(d.uv())
	switch e.Kind {
	case manifest.KindRegular:
		e.Size = int64(d.u64())
		e.Dev = d.u64()
		e.Ino = d.u64()
		e.ChunkSize = int64(d.u32())
	case manifest.KindHardlink:
		e.LinkRefID = uint32(d.uv())
	case manifest.KindSymlink:
		e.LinkTarget = d.str()
	case manifest.KindFIFO, manifest.KindCharDev, manifest.KindBlockDev:
		e.Rdev = d.u64()
	case manifest.KindDir, manifest.KindSocket:
		// no extra fields
	default:
		return e, 0, fmt.Errorf("bad entry kind %d", e.Kind)
	}
	nx := d.uv()
	if nx > 1024 {
		return e, 0, fmt.Errorf("too many xattrs: %d", nx)
	}
	for i := uint64(0); i < nx; i++ {
		name := d.str()
		// copy: the payload may alias the control reader's reusable buffer,
		// and xattr values outlive the frame (applied at finalize time)
		val := append([]byte(nil), d.bytes()...)
		e.Xattrs = append(e.Xattrs, manifest.Xattr{Name: name, Value: val})
	}
	if d.err != nil {
		return e, 0, d.err
	}
	return e, len(p) - len(d.b), nil
}

// Encode serializes a batch.
func (m ManifestBatch) Encode() []byte {
	var e enc
	e.uv(uint64(len(m.Entries)))
	for i := range m.Entries {
		e.b = append(e.b, EncodeEntry(&m.Entries[i])...)
	}
	return e.b
}

// DecodeManifestBatch parses a batch payload.
func DecodeManifestBatch(p []byte) (ManifestBatch, error) {
	var d dec
	d.b = p
	n := d.uv()
	if n > 4096 {
		return ManifestBatch{}, fmt.Errorf("batch too large: %d entries", n)
	}
	m := ManifestBatch{Entries: make([]manifest.Entry, 0, min(n, 256))}
	for i := uint64(0); i < n; i++ {
		e, used, err := DecodeEntry(d.b)
		if err != nil {
			return m, err
		}
		m.Entries = append(m.Entries, e)
		d.b = d.b[used:]
	}
	return m, d.err
}

// ManifestEnd closes the manifest stream. Totals are authoritative at this
// point (the receiver learns the full denominator).
type ManifestEnd struct {
	Files        uint64
	Bytes        uint64
	Dirs         uint64
	HasHardlinks bool
}

// Encode serializes m.
func (m ManifestEnd) Encode() []byte {
	var e enc
	e.u64(m.Files)
	e.u64(m.Bytes)
	e.u64(m.Dirs)
	hl := uint8(0)
	if m.HasHardlinks {
		hl = 1
	}
	e.u8(hl)
	return e.b
}

// DecodeManifestEnd parses a ManifestEnd payload.
func DecodeManifestEnd(p []byte) (ManifestEnd, error) {
	var d dec
	d.b = p
	var m ManifestEnd
	m.Files = d.u64()
	m.Bytes = d.u64()
	m.Dirs = d.u64()
	m.HasHardlinks = d.u8() == 1
	return m, d.err
}

// HaveBitmap statuses.
const (
	HaveNone    uint8 = 0 // nothing usable
	HavePartial uint8 = 1 // bitmap of verified chunks
	HaveAllSkip uint8 = 2 // final file already matches (size+mtime)
)

// HaveBitmap tells the sender which chunks the receiver already has. When
// the claim is trusted (a sidecar verified against the same source) Hashes
// is empty; when the receiver adopted an existing file it cannot fully
// trust (delta), Hashes carries one SHA-256 per claimed chunk and the
// sender verifies each against its own bytes before skipping.
type HaveBitmap struct {
	FileID uint32
	Status uint8
	Bitmap []byte
	Hashes [][32]byte
}

// Encode serializes m.
func (m HaveBitmap) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	e.u8(m.Status)
	e.bytes(m.Bitmap)
	e.uv(uint64(len(m.Hashes)))
	for _, h := range m.Hashes {
		e.b = append(e.b, h[:]...)
	}
	return e.b
}

// DecodeHaveBitmap parses a HaveBitmap payload.
func DecodeHaveBitmap(p []byte) (HaveBitmap, error) {
	var d dec
	d.b = p
	var m HaveBitmap
	m.FileID = uint32(d.uv())
	m.Status = d.u8()
	m.Bitmap = d.bytes()
	nh := d.uv()
	if nh > 1<<20 {
		return m, fmt.Errorf("too many have hashes: %d", nh)
	}
	for i := uint64(0); i < nh; i++ {
		var h [32]byte
		// hashes are fixed-width on the wire (no per-hash length prefix)
		if len(d.b) < 32 {
			return m, fmt.Errorf("short have hash")
		}
		copy(h[:], d.b[:32])
		d.b = d.b[32:]
		m.Hashes = append(m.Hashes, h)
	}
	return m, d.err
}

// FileResult statuses.
const (
	ResultOK    uint8 = 0
	ResultSkip  uint8 = 1
	ResultError uint8 = 2
	ResultRetry uint8 = 3 // unused, reserved
)

// FileResult reports the outcome of one file.
type FileResult struct {
	FileID uint32
	Status uint8
	Code   uint16
	Msg    string
}

// Encode serializes m.
func (m FileResult) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	e.u8(m.Status)
	e.u16(m.Code)
	e.str(m.Msg)
	return e.b
}

// DecodeFileResult parses a FileResult payload.
func DecodeFileResult(p []byte) (FileResult, error) {
	var d dec
	d.b = p
	var m FileResult
	m.FileID = uint32(d.uv())
	m.Status = d.u8()
	m.Code = d.u16()
	m.Msg = d.str()
	return m, d.err
}

// ChunkRetry asks the sender to re-send one chunk (negative ack: decompress
// or write failure on the receiver).
type ChunkRetry struct {
	FileID   uint32
	ChunkIdx uint64
	Reason   uint8
}

// Encode serializes m.
func (m ChunkRetry) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	e.uv(m.ChunkIdx)
	e.u8(m.Reason)
	return e.b
}

// DecodeChunkRetry parses a ChunkRetry payload.
func DecodeChunkRetry(p []byte) (ChunkRetry, error) {
	var d dec
	d.b = p
	var m ChunkRetry
	m.FileID = uint32(d.uv())
	m.ChunkIdx = d.uv()
	m.Reason = d.u8()
	return m, d.err
}

// ListEntry is one row of a directory listing for the browser.
type ListEntry struct {
	Name    string
	IsDir   bool
	Size    uint64
	MtimeMS int64
	Mode    uint16
}

// ListReq asks the server to list a directory (browser, pull mode).
type ListReq struct {
	Path   string
	Offset uint32
	Limit  uint16
}

// Encode serializes m.
func (m ListReq) Encode() []byte {
	var e enc
	e.str(m.Path)
	e.u32(m.Offset)
	e.u16(m.Limit)
	return e.b
}

// DecodeListReq parses a ListReq payload.
func DecodeListReq(p []byte) (ListReq, error) {
	var d dec
	d.b = p
	var m ListReq
	m.Path = d.str()
	m.Offset = d.u32()
	m.Limit = d.u16()
	return m, d.err
}

// ListResp answers ListReq.
type ListResp struct {
	Total     uint32
	Truncated bool
	Entries   []ListEntry
}

// Encode serializes m.
func (m ListResp) Encode() []byte {
	var e enc
	e.u32(m.Total)
	t := uint8(0)
	if m.Truncated {
		t = 1
	}
	e.u8(t)
	e.uv(uint64(len(m.Entries)))
	for _, le := range m.Entries {
		e.str(le.Name)
		isDir := uint8(0)
		if le.IsDir {
			isDir = 1
		}
		e.u8(isDir)
		e.u64(le.Size)
		e.sv(le.MtimeMS)
		e.u16(le.Mode)
	}
	return e.b
}

// DecodeListResp parses a ListResp payload.
func DecodeListResp(p []byte) (ListResp, error) {
	var d dec
	d.b = p
	var m ListResp
	m.Total = d.u32()
	m.Truncated = d.u8() == 1
	n := d.uv()
	if n > 65536 {
		return m, fmt.Errorf("list too large: %d", n)
	}
	for i := uint64(0); i < n; i++ {
		var le ListEntry
		le.Name = d.str()
		le.IsDir = d.u8() == 1
		le.Size = d.u64()
		le.MtimeMS = d.sv()
		le.Mode = d.u16()
		m.Entries = append(m.Entries, le)
	}
	return m, d.err
}

// Error scopes.
const (
	ScopeSession  uint8 = 0
	ScopeTransfer uint8 = 1
	ScopeFile     uint8 = 2
)

// ErrMsg reports a fatal or transfer-level error.
type ErrMsg struct {
	Scope uint8
	Code  uint16
	Msg   string
}

// Encode serializes m.
func (m ErrMsg) Encode() []byte {
	var e enc
	e.u8(m.Scope)
	e.u16(m.Code)
	e.str(m.Msg)
	return e.b
}

// DecodeErrMsg parses an ErrMsg payload.
func DecodeErrMsg(p []byte) (ErrMsg, error) {
	var d dec
	d.b = p
	var m ErrMsg
	m.Scope = d.u8()
	m.Code = d.u16()
	m.Msg = d.str()
	return m, d.err
}

// Commit tells the receiver an untrusted have-claim (delta adoption)
// verified in full — nothing will arrive for this file, finalize it.
type Commit struct {
	FileID uint32
}

// Encode serializes m.
func (m Commit) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	return e.b
}

// DecodeCommit parses a Commit payload.
func DecodeCommit(p []byte) (Commit, error) {
	var d dec
	d.b = p
	var m Commit
	m.FileID = uint32(d.uv())
	return m, d.err
}

// ClaimResult answers an untrusted delta claim (HaveBitmap with hashes)
// when some claims failed verification: Verified is the sender's post-
// verification have bitmap. Chunks the receiver claimed that are absent
// here WILL arrive as data — the receiver must not finalize before they
// do. (A fully-verified claim is answered with Commit instead.)
type ClaimResult struct {
	FileID   uint32
	Verified []byte
}

// Encode serializes m.
func (m ClaimResult) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	e.bytes(m.Verified)
	return e.b
}

// DecodeClaimResult parses a ClaimResult payload.
func DecodeClaimResult(p []byte) (ClaimResult, error) {
	var d dec
	d.b = p
	var m ClaimResult
	m.FileID = uint32(d.uv())
	m.Verified = d.bytes()
	return m, d.err
}

// ChunkRequest asks a source to send one chunk on the next data stream
// frame — receiver-driven acquisition, the mesh/swarm primitive. The
// sender role answers; the push scheduler never sends these.
type ChunkRequest struct {
	FileID   uint32
	ChunkIdx uint64
}

// Encode serializes m.
func (m ChunkRequest) Encode() []byte {
	var e enc
	e.uv(uint64(m.FileID))
	e.uv(m.ChunkIdx)
	return e.b
}

// DecodeChunkRequest parses a ChunkRequest payload.
func DecodeChunkRequest(p []byte) (ChunkRequest, error) {
	var d dec
	d.b = p
	var m ChunkRequest
	m.FileID = uint32(d.uv())
	m.ChunkIdx = d.uv()
	return m, d.err
}

// Done summarizes a finished transfer (receiver → sender).
type Done struct {
	Files  uint64
	Bytes  uint64
	Errors uint32
}

// Encode serializes m.
func (m Done) Encode() []byte {
	var e enc
	e.u64(m.Files)
	e.u64(m.Bytes)
	e.u32(m.Errors)
	return e.b
}

// DecodeDone parses a Done payload.
func DecodeDone(p []byte) (Done, error) {
	var d dec
	d.b = p
	var m Done
	m.Files = d.u64()
	m.Bytes = d.u64()
	m.Errors = d.u32()
	return m, d.err
}
