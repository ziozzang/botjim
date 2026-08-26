package cloak

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// TestPlainConnReplaysBufferedBytes: after a sniff Peek, the plain path
// must still see every byte (regression: the demux used to lose the
// buffered handshake and plain clients got EOF on cloak servers).
func TestPlainConnReplaysBufferedBytes(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c1.Write([]byte("FSY1 + handshake bytes"))
	}()
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(c2)
	if SniffCloaked(br) {
		t.Fatal("FSY1 bytes sniffed as HTTP")
	}
	pc := PlainConn(c2, br)
	want := []byte("FSY1 + handshake bytes")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(pc, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("replay lost bytes: %q", got)
	}
}
