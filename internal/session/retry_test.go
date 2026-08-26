package session

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/protocol"
)

// TestRetriesReconnect: a kill-and-resume loop converges through
// RunWithRetries — the receiver's sidecars carry progress across dials.
func TestRetriesReconnect(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	// ~40MiB so a mid-transfer kill leaves real partial state
	if err := os.WriteFile(filepath.Join(src, "big.bin"), makePattern(40<<20), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(ServerConfig{Root: dst, AllowPush: true, Parallel: 4, Fsync: true})
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(srvLn) }()
	defer srv.Stop()

	// proxy that dies after ~2MB once — the retry re-dials and resumes
	once := newSyncOnce()
	proxyAddr, stopProxy := flakyProxy(t, srvLn.Addr().String(), once)
	defer stopProxy()

	reg := progress.New()
	res := RunWithRetries(context.Background(), ClientConfig{
		Addr: proxyAddr, Direction: protocol.DirPush,
		Paths:       []string{filepath.Join(src, "big.bin")},
		Compression: 0, Parallel: 2,
	}, reg, 3)
	if res.Err != nil {
		t.Fatalf("retries did not converge: %v", res.Err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "big.bin"))
	if err != nil || len(got) != 40<<20 {
		t.Fatalf("result wrong: %d bytes err=%v", len(got), err)
	}
}

// makePattern returns deterministic non-zero bytes.
func makePattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

type syncOnce struct {
	ch   chan struct{}
	used bool
	mu   chan struct{}
}

func newSyncOnce() *syncOnce {
	return &syncOnce{ch: make(chan struct{}), mu: make(chan struct{}, 1)}
}

// take claims the once: true the first time, false after.
func (o *syncOnce) take() bool {
	o.mu <- struct{}{}
	defer func() { <-o.mu }()
	if o.used {
		return false
	}
	o.used = true
	close(o.ch)
	return true
}

func flakyProxy(t *testing.T, backend string, once *syncOnce) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b, err := net.Dial("tcp", backend)
				if err != nil {
					return
				}
				defer b.Close()
				// first connection: cut after ~2MB
				if once.take() {
					cutAfter(c, b, 2<<20)
				} else {
					pump(c, b) // later connections: pass through
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func pump(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = copyBoth(a, b); done <- struct{}{} }()
	<-done
}

func copyBoth(a, b net.Conn) (int64, error) {
	go func() { _, _ = transfer(a, b) }()
	return transfer(b, a)
}

func transfer(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}

// cutAfter pipes until limit bytes then hard-closes both sides.
func cutAfter(a, b net.Conn, limit int64) {
	buf := make([]byte, 32<<10)
	var total int64
	for total < limit {
		a.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := a.Read(buf)
		if n > 0 {
			if _, werr := b.Write(buf[:n]); werr != nil {
				break
			}
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	_ = a.Close()
	_ = b.Close()
}
