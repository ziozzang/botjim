package protocol

import (
	"bufio"
	"fmt"
	"hash/crc32"
	"io"

	"encoding/binary"
)

// Stream kind bytes open every yamux stream so each side can classify an
// accepted stream by its first byte regardless of who opened it.
const (
	StreamKindCtrl uint8 = 0x01
	StreamKindData uint8 = 0x02
)

// Data-frame chunk flags.
const (
	ChunkFlagZero     uint8 = 1 << 0 // all-zero chunk: no payload, receiver leaves a hole
	ChunkFlagRaw      uint8 = 1 << 1 // payload not compressed (fallback or alg=none)
	ChunkFlagLastFile uint8 = 1 << 2 // last chunk of this file (diagnostics only)
	// ChunkFlagSum: the payload ends with a 4-byte LE crc32c over the
	// frame identity (fileID, chunkIdx, flags sans this bit) and the body.
	// TCP's 16-bit checksum misses real-world corruption on long streams;
	// zstd frames carry their own CRC but raw chunks — incompressible
	// data, the common case for media — had no integrity check at all.
	// Negotiated via FeatChunkSum.
	ChunkFlagSum uint8 = 1 << 3
)

const frameChunkType uint8 = 0x20

// maxChunkPayload bounds a pre-allocated chunk buffer: the largest chunk
// is 16MiB and compressed output never exceeds it by contract (raw
// fallback), so anything larger is protocol abuse.
const maxChunkPayload = 17<<20 + 4096

// DataStream frames one yamux stream carrying chunk frames. One stream is
// owned by exactly one sender worker / receiver handler goroutine.
type DataStream struct {
	conn io.ReadWriter
	br   *bufio.Reader
	buf  []byte // read-side payload scratch
	wbuf []byte // write-side scratch: coalesce header+payload into one write
}

// coalesceLimit bounds when a chunk frame is written as a single buffer
// (header+payload copied together) vs two writes. Small payloads (the
// common many-small-files case) are cheaper to copy than to split into two
// yamux frames; large payloads are written in two calls to avoid a 16MiB
// memcpy that would cost more than the saved frame.
const coalesceLimit = 128 << 10

// NewDataStream wraps a freshly opened stream after exchanging the kind
// hello. index is diagnostic (which worker owns the stream).
func NewDataStream(rw io.ReadWriter, index uint64) (*DataStream, error) {
	hdr := []byte{StreamKindData}
	hdr = binary.AppendUvarint(hdr, index)
	if _, err := rw.Write(hdr); err != nil {
		return nil, err
	}
	return &DataStream{conn: rw, br: bufio.NewReaderSize(rw, 256<<10)}, nil
}

// AcceptDataStream validates the hello on an accepted stream. The buffered
// reader created here is the one the stream keeps: re-reading with a fresh
// reader would lose any frames the first one buffered.
func AcceptDataStream(rw io.ReadWriter) (*DataStream, uint64, error) {
	br := bufio.NewReaderSize(rw, 256<<10)
	kind, err := br.ReadByte()
	if err != nil {
		return nil, 0, err
	}
	if kind != StreamKindData {
		return nil, 0, fmt.Errorf("expected data stream, got kind 0x%02x", kind)
	}
	index, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, 0, err
	}
	return &DataStream{conn: rw, br: br}, index, nil
}

// ChunkHeader describes one chunk frame.
type ChunkHeader struct {
	FileID     uint32
	ChunkIdx   uint64
	Flags      uint8
	PayloadLen uint64
}

// WriteChunk sends one chunk frame. payload may be nil for zero chunks.
func (s *DataStream) WriteChunk(h ChunkHeader, payload []byte) error {
	if uint64(len(payload)) != h.PayloadLen {
		return fmt.Errorf("payload length mismatch: header %d, actual %d", h.PayloadLen, len(payload))
	}
	var hdr [2 + 3*binary.MaxVarintLen64]byte
	hdr[0] = frameChunkType
	n := 1
	n += binary.PutUvarint(hdr[n:], uint64(h.FileID))
	n += binary.PutUvarint(hdr[n:], h.ChunkIdx)
	hdr[n] = h.Flags
	n++
	n += binary.PutUvarint(hdr[n:], h.PayloadLen)
	if len(payload) > 0 && len(payload) <= coalesceLimit {
		// one write = one yamux frame; avoids the per-chunk header frame
		if cap(s.wbuf) < n+len(payload) {
			s.wbuf = make([]byte, 0, n+len(payload))
		}
		s.wbuf = append(s.wbuf[:0], hdr[:n]...)
		s.wbuf = append(s.wbuf, payload...)
		_, err := s.conn.Write(s.wbuf)
		return err
	}
	if _, err := s.conn.Write(hdr[:n]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadChunk receives the next chunk frame, returning the header and a view
// into an internal buffer valid until the next ReadChunk.
func (s *DataStream) ReadChunk() (ChunkHeader, []byte, error) {
	t, err := s.br.ReadByte()
	if err != nil {
		return ChunkHeader{}, nil, err
	}
	if t != frameChunkType {
		return ChunkHeader{}, nil, fmt.Errorf("expected chunk frame, got 0x%02x", t)
	}
	fileID, err := binary.ReadUvarint(s.br)
	if err != nil {
		return ChunkHeader{}, nil, err
	}
	idx, err := binary.ReadUvarint(s.br)
	if err != nil {
		return ChunkHeader{}, nil, err
	}
	flags, err := s.br.ReadByte()
	if err != nil {
		return ChunkHeader{}, nil, err
	}
	plen, err := binary.ReadUvarint(s.br)
	if err != nil {
		return ChunkHeader{}, nil, err
	}
	if plen > maxChunkPayload {
		return ChunkHeader{}, nil, fmt.Errorf("chunk payload too large: %d", plen)
	}
	h := ChunkHeader{FileID: uint32(fileID), ChunkIdx: idx, Flags: flags, PayloadLen: plen}
	if plen == 0 {
		if flags&ChunkFlagZero == 0 {
			return h, nil, fmt.Errorf("empty payload without zero flag (file %d chunk %d)", fileID, idx)
		}
		return h, nil, nil
	}
	if cap(s.buf) < int(plen) {
		s.buf = make([]byte, plen)
	}
	payload := s.buf[:plen]
	if _, err := io.ReadFull(s.br, payload); err != nil {
		return ChunkHeader{}, nil, err
	}
	return h, payload, nil
}

// ChunkSum is the frame checksum: crc32c over the frame identity and the
// body. The Sum flag itself is masked so both sides hash the same bytes.
func ChunkSum(h ChunkHeader, body []byte) uint32 {
	var idb [1 + 2*binary.MaxVarintLen64]byte
	n := binary.PutUvarint(idb[:], uint64(h.FileID))
	n += binary.PutUvarint(idb[n:], h.ChunkIdx)
	idb[n] = h.Flags &^ ChunkFlagSum
	n++
	c := crc32.Update(0, crc32c, idb[:n])
	return crc32.Update(c, crc32c, body)
}

// WriteChunkSummed sends one chunk frame with the crc32c trailer (the
// negotiated FeatChunkSum path). body may be nil for zero chunks.
func (s *DataStream) WriteChunkSummed(h ChunkHeader, body []byte) error {
	h.Flags |= ChunkFlagSum
	h.PayloadLen = uint64(len(body)) + 4
	var tr [4]byte
	binary.LittleEndian.PutUint32(tr[:], ChunkSum(h, body))
	var hdr [2 + 3*binary.MaxVarintLen64]byte
	hdr[0] = frameChunkType
	n := 1
	n += binary.PutUvarint(hdr[n:], uint64(h.FileID))
	n += binary.PutUvarint(hdr[n:], h.ChunkIdx)
	hdr[n] = h.Flags
	n++
	n += binary.PutUvarint(hdr[n:], h.PayloadLen)
	// the summed path always has a trailer, so coalescing saves two writes
	// for small payloads (three yamux frames → one)
	if len(body) <= coalesceLimit {
		need := n + len(body) + 4
		if cap(s.wbuf) < need {
			s.wbuf = make([]byte, 0, need)
		}
		s.wbuf = append(s.wbuf[:0], hdr[:n]...)
		s.wbuf = append(s.wbuf, body...)
		s.wbuf = append(s.wbuf, tr[:]...)
		_, err := s.conn.Write(s.wbuf)
		return err
	}
	if _, err := s.conn.Write(hdr[:n]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := s.conn.Write(body); err != nil {
			return err
		}
	}
	_, err := s.conn.Write(tr[:])
	return err
}

// Underlying exposes the wrapped stream (for Close).
func (s *DataStream) Underlying() io.ReadWriter { return s.conn }
