package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/botjim/internal/protocol"
)

// startTestServer runs a server on an ephemeral port and returns its address
// and a stop function.
func startTestServer(t *testing.T, root string, push, pull bool) (string, func()) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(ServerConfig{
		Root:      root,
		AllowPush: push,
		AllowPull: pull,
		Parallel:  4,
		Fsync:     true,
	})
	done := make(chan struct{})
	go func() { _ = srv.Serve(ln); close(done) }()
	return ln.Addr().String(), func() {
		srv.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func TestPushBasic(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	content := []byte("hello ferry\n")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "d", "e"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "d", "e", "b.bin"), make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}

	addr, stop := startTestServer(t, dst, true, true)
	defer stop()

	res := RunTransfer(context.Background(), ClientConfig{
		Addr:        addr,
		Direction:   protocol.DirPush,
		Paths:       []string{filepath.Join(src, "a.txt"), filepath.Join(src, "d")},
		Compression: 1,
		ZstdLevel:   3,
		Parallel:    4,
		Resume:      0,
		Preserve:    protocol.PreserveHardlink | protocol.PreserveSparse,
		Fsync:       true,
		Timeout:     10 * time.Second,
	})
	if res.Err != nil {
		t.Fatalf("push: %v", res.Err)
	}
	if res.Report.Files != 4 { // a.txt, d, e, b.bin
		t.Fatalf("expected 4 entries, got %d (report %+v)", res.Report.Files, res.Report)
	}
	if res.Report.Cancelled {
		t.Fatalf("transfer flagged cancelled: %+v", res.Report)
	}
	got, err := os.ReadFile(filepath.Join(dst, "a.txt"))
	if err != nil || string(got) != string(content) {
		t.Fatalf("a.txt mismatch: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "d", "e", "b.bin")); err != nil {
		t.Fatalf("nested file missing: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "a.txt"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v err=%v", fi.Mode(), err)
	}
	fmt.Println("basic push ok")
}
