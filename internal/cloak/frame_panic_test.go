package cloak

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestOversizeFrameNoPanic: a 127-length frame whose 64-bit length has the
// top bit set must be rejected, never panic make([]byte, negative).
func TestOversizeFrameNoPanic(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{0x82, 127}
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], 0x8000000000000000) // → negative int64
		hdr = append(hdr, ext[:]...)
		_ = c1.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c1.Write(hdr)
	}()
	ws := &wsConn{Conn: c2, rbuf: bufio.NewReader(c2), server: true}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	_, err := ws.Read(buf) // must return an error, not panic
	if err == nil {
		t.Fatal("oversize/negative frame accepted")
	}
}
