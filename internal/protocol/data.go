package protocol

import (
	"bufio"
	"fmt"
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
)

const frameChunkType uint8 = 0x20

// DataStream frames one yamux stream carrying chunk frames. One stream is
// owned by exactly one sender worker / receiver handler goroutine.
type DataStream struct {
	conn io.ReadWriter
	br   *bufio.Reader
	buf  []byte // read-side payload scratch
}

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

// AcceptDataStream validates the hello on an accepted stream.
func AcceptDataStream(rw io.ReadWriter) (*DataStream, uint64, error) {
	br := bufio.NewReaderSize(rw, 64)
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
	return &DataStream{conn: rw, br: bufio.NewReaderSize(rw, 256<<10)}, index, nil
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
	var hdr [4 + binary.MaxVarintLen64*2]byte
	hdr[0] = frameChunkType
	n := 1
	n += binary.PutUvarint(hdr[n:], uint64(h.FileID))
	n += binary.PutUvarint(hdr[n:], h.ChunkIdx)
	hdr[n] = h.Flags
	n++
	n += binary.PutUvarint(hdr[n:], h.PayloadLen)
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
	if plen > 1<<30 {
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

// Underlying exposes the wrapped stream (for Close).
func (s *DataStream) Underlying() io.ReadWriter { return s.conn }
