// Package protocol implements the botjim wire protocol: the 36-byte
// handshake, the length-prefixed control-stream framing, every control
// message, the manifest entry encoding and the data-stream chunk frames.
//
// Everything here is a pure codec — no network, no goroutines — so it is
// trivially testable and can be layered over any io.ReadWriter. Encryption
// (when added) wraps the whole byte stream below this layer, which is why the
// handshake carries a cipher ID but the frames carry nothing crypto-shaped.
//
// varint  = LEB128 unsigned (encoding/binary.{PutUvarint,Uvarint})
// sintXX  = zigzag-encoded varint
// u16/u32/u64 = little-endian fixed width
package protocol

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
)

// Magic opens every connection: "FSY1".
const Magic = "FSY1"

// ProtoMajor increments on incompatible wire changes; peers with different
// majors refuse the session in the handshake.
const ProtoMajor = 1

// Cipher IDs. V1 ships plain only; the ID and the handshake nonce are the
// reserved hooks for an X25519 + ChaCha20-Poly1305 record layer that will
// wrap the whole stream under yamux.
const (
	CipherPlain          = 0
	CipherX25519ChaCha20 = 1 // reserved
)

// Handshake flag bits (byte 7). Auth/e2ee negotiate here; unknown flag
// bits on either side must refuse the session (downgrade guard).
const (
	HSFlagToken = 1 << 0 // --token auth follows the handshake
	HSFlagPass  = 1 << 1 // --pass record-layer encryption follows
)

// Handshake feature bits, exchanged as a u64 in the handshake. The effective
// feature set for the session is the intersection.
const (
	FeatZstd     = 1 << 0
	FeatLz4      = 1 << 1
	FeatXattr    = 1 << 2
	FeatHardlink = 1 << 3
	FeatSparse   = 1 << 4
	FeatDevices  = 1 << 5
	FeatUname    = 1 << 6
	FeatBrowser  = 1 << 7
	FeatClaimAck = 1 << 8 // sender reports verified delta claims (MsgClaimResult)
	FeatChunkSum = 1 << 9 // per-chunk crc32c trailer on data frames
	FeatAll      = FeatZstd | FeatLz4 | FeatXattr | FeatHardlink | FeatSparse | FeatDevices | FeatUname | FeatBrowser | FeatClaimAck | FeatChunkSum
)

// Handshake is 36 bytes on the wire:
//
//	 0  4  magic
//	 4  1  protoMajor
//	 5  1  protoMinor
//	 6  1  cipherID
//	 7  1  flags (bit0: token auth — reserved)
//	 8  8  featureBits LE
//	16 16  session nonce (random; also keys part-file name suffixes)
//	32  4  crc32c over bytes 0..31
type Handshake struct {
	ProtoMajor  uint8
	ProtoMinor  uint8
	CipherID    uint8
	Flags       uint8
	FeatureBits uint64
	Nonce       [16]byte
}

// NewHandshake builds a fresh handshake with a random nonce.
func NewHandshake(features uint64) (*Handshake, error) {
	h := &Handshake{ProtoMajor: ProtoMajor, CipherID: CipherPlain, FeatureBits: features}
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return nil, err
	}
	return h, nil
}

// NonceHex renders the first 8 nonce bytes (64 bits) as hex — the
// per-session suffix used for part/sidecar file names on the receiving
// side.
func (h *Handshake) NonceHex() string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for _, b := range h.Nonce[:8] {
		out = append(out, hexd[b>>4], hexd[b&0xF])
	}
	return string(out)
}

var crc32c = crc32.MakeTable(crc32.Castagnoli)

// WriteHandshake serializes h (computing the trailing CRC) to w.
func WriteHandshake(w io.Writer, h *Handshake) error {
	var buf [36]byte
	copy(buf[0:4], Magic)
	buf[4] = h.ProtoMajor
	buf[5] = h.ProtoMinor
	buf[6] = h.CipherID
	buf[7] = h.Flags
	binary.LittleEndian.PutUint64(buf[8:16], h.FeatureBits)
	copy(buf[16:32], h.Nonce[:])
	binary.LittleEndian.PutUint32(buf[32:36], crc32.Checksum(buf[:32], crc32c))
	_, err := w.Write(buf[:])
	return err
}

// ReadHandshake reads and validates a handshake frame. Magic, CRC and major
// version mismatches are hard errors.
func ReadHandshake(r io.Reader) (*Handshake, error) {
	var buf [36]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	if string(buf[0:4]) != Magic {
		return nil, errors.New("not a botjim peer (bad magic)")
	}
	if binary.LittleEndian.Uint32(buf[32:36]) != crc32.Checksum(buf[:32], crc32c) {
		return nil, errors.New("handshake corrupt")
	}
	if buf[4] != ProtoMajor {
		return nil, fmt.Errorf("protocol major mismatch: peer %d, us %d", buf[4], ProtoMajor)
	}
	if buf[6] != CipherPlain {
		return nil, fmt.Errorf("unsupported cipher id %d (this build speaks plaintext only)", buf[6])
	}
	if buf[7]&^(uint8(HSFlagToken|HSFlagPass)) != 0 {
		return nil, fmt.Errorf("unsupported handshake flags %#x", buf[7])
	}
	h := &Handshake{
		ProtoMajor:  buf[4],
		ProtoMinor:  buf[5],
		CipherID:    buf[6],
		Flags:       buf[7],
		FeatureBits: binary.LittleEndian.Uint64(buf[8:16]),
	}
	copy(h.Nonce[:], buf[16:32])
	return h, nil
}

// Control message types.
const (
	MsgInitTransfer  uint8 = 0x01
	MsgTransferAck   uint8 = 0x02
	MsgManifestBatch uint8 = 0x03
	MsgManifestEnd   uint8 = 0x04
	MsgHaveBitmap    uint8 = 0x10
	MsgFileResult    uint8 = 0x11
	MsgChunkRetry    uint8 = 0x12
	MsgListReq       uint8 = 0x20
	MsgListResp      uint8 = 0x21
	MsgCancel        uint8 = 0x30
	MsgAbort         uint8 = 0x31
	MsgGoodbye       uint8 = 0x32
	MsgError         uint8 = 0x33
	MsgDone          uint8 = 0x34
	MsgCommit        uint8 = 0x35 // sender→receiver: untrusted claim fully verified
	MsgChunkRequest  uint8 = 0x36 // receiver→source: request-driven chunk fetch
	MsgClaimResult   uint8 = 0x37 // sender→receiver: which delta claims verified
)

// CtrlFrameFlags — control payload compression.
const CtrlFlagZstd uint8 = 1 << 0

// MaxCtrlPayload caps one control message (manifest batches split below it).
const MaxCtrlPayload = 8 << 20

// CtrlFrame is one decoded control message.
type CtrlFrame struct {
	Type    uint8
	Flags   uint8
	Payload []byte
}

// CtrlStream frames a bidirectional byte stream: one writer goroutine, one
// reader goroutine, each side serialized by a mutex / single reader.
type CtrlStream struct {
	rw  io.ReadWriter
	bw  *bufio.Writer
	br  *bufio.Reader
	wmu sync.Mutex
}

// NewCtrlStream wraps rw with buffered framing.
func NewCtrlStream(rw io.ReadWriter) *CtrlStream {
	return &CtrlStream{rw: rw, bw: bufio.NewWriterSize(rw, 64<<10), br: bufio.NewReaderSize(rw, 256<<10)}
}

// Send writes one control frame. Flushed immediately — control traffic is
// sparse and latency-sensitive.
func (c *CtrlStream) Send(t uint8, flags uint8, payload []byte) error {
	if len(payload) > MaxCtrlPayload {
		return fmt.Errorf("control payload too large: %d", len(payload))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr [6]byte
	hdr[0] = t
	hdr[1] = flags
	binary.LittleEndian.PutUint32(hdr[2:6], uint32(len(payload)))
	if _, err := c.bw.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

// Recv reads the next control frame. The payload buffer is owned by the
// caller; it is re-used frame to frame to keep allocs down.
func (c *CtrlStream) Recv(buf []byte) (CtrlFrame, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return CtrlFrame{}, err
	}
	n := binary.LittleEndian.Uint32(hdr[2:6])
	if n > MaxCtrlPayload {
		return CtrlFrame{}, fmt.Errorf("control frame too large: %d", n)
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n)
	}
	payload := buf[:n]
	if n > 0 {
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return CtrlFrame{}, err
		}
	}
	return CtrlFrame{Type: hdr[0], Flags: hdr[1], Payload: payload}, nil
}

// ---- little encode/decode helpers used by all message codecs ----

type enc struct{ b []byte }

func (e *enc) u8(v uint8)   { e.b = append(e.b, v) }
func (e *enc) u16(v uint16) { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32) { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64) { e.b = binary.LittleEndian.AppendUint64(e.b, v) }
func (e *enc) uv(v uint64)  { e.b = binary.AppendUvarint(e.b, v) }
func (e *enc) sv(v int64)   { e.b = binary.AppendVarint(e.b, v) }
func (e *enc) bytes(p []byte) {
	e.uv(uint64(len(p)))
	e.b = append(e.b, p...)
}
func (e *enc) str(s string) {
	e.uv(uint64(len(s)))
	e.b = append(e.b, s...)
}

type dec struct {
	b   []byte
	err error
}

func (d *dec) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf(format, args...)
	}
}

func (d *dec) u8() uint8 {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 1 {
		d.fail("short u8")
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *dec) u16() uint16 {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 2 {
		d.fail("short u16")
		return 0
	}
	v := binary.LittleEndian.Uint16(d.b)
	d.b = d.b[2:]
	return v
}

func (d *dec) u32() uint32 {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 4 {
		d.fail("short u32")
		return 0
	}
	v := binary.LittleEndian.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *dec) u64() uint64 {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 8 {
		d.fail("short u64")
		return 0
	}
	v := binary.LittleEndian.Uint64(d.b)
	d.b = d.b[8:]
	return v
}

func (d *dec) uv() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail("bad uvarint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *dec) sv() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail("bad varint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *dec) bytes() []byte {
	if d.err != nil {
		return nil
	}
	n := d.uv()
	if uint64(len(d.b)) < n {
		d.fail("short bytes")
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) str() string {
	return string(d.bytes())
}
