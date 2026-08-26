package cloak

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
)

// echoServer accepts one connection, demuxes, and echoes ws payload back.
func echoServer(t *testing.T, path string) (addr string, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if !SniffCloaked(br) {
			t.Error("sniff failed to see HTTP")
			return
		}
		ws := ServeHTTP(conn, br, path)
		if ws == nil {
			return // decoy path: rejection is a normal outcome
		}
		buf := make([]byte, 4096)
		for {
			n, err := ws.Read(buf)
			if err != nil {
				return
			}
			if _, err := ws.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), ch
}

func TestCloakRoundtrip(t *testing.T) {
	addr, done := echoServer(t, "/cdn/data")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Dial(conn, "/cdn/data", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("cloak-me "), 100000) // ~900KB: multi-frame
	go func() {
		if _, err := ws.Write(payload); err != nil {
			t.Error(err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(ws, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %d vs %d bytes", len(got), len(payload))
	}
	_ = ws.Close()
	<-done
}

func TestCloakWrongPathDecoy(t *testing.T) {
	addr, done := echoServer(t, "/secret")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := Dial(conn, "/wrong", "x"); err == nil {
		t.Fatal("wrong path upgraded")
	}
	<-done
}

func TestSniffPlainNotCloaked(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("FSY1\x01\x00")))
	if SniffCloaked(br) {
		t.Fatal("plain FSY1 sniffed as HTTP")
	}
}
