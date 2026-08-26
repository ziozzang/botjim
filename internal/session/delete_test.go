package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/protocol"
)

// TestDeleteMirror: --delete removes dest files absent from the source.
func TestDeleteMirror(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	// stale dest content mirrors the src-basename layout the walker produces
	base := filepath.Base(src)
	mk := func(rel, content string) {
		p := filepath.Join(dst, base, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("keep.txt", "old")
	mk("stale.bin", "x")
	mk("staledir/junk", "x")
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2, Preserve: protocol.PreserveDelete,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if _, err := os.Stat(filepath.Join(dst, base, "stale.bin")); !os.IsNotExist(err) {
		t.Error("stale.bin survived --delete")
	}
	if _, err := os.Stat(filepath.Join(dst, base, "staledir")); !os.IsNotExist(err) {
		t.Error("staledir survived --delete")
	}
	if b, err := os.ReadFile(filepath.Join(dst, base, "keep.txt")); err != nil || string(b) != "k" {
		t.Fatalf("keep.txt wrong: %q %v", b, err)
	}
}

// TestDeleteOffByDefault: without the bit nothing is removed.
func TestDeleteOffByDefault(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	os.WriteFile(filepath.Join(src, "a"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(dst, "extra"), []byte("x"), 0o644)
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	if res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2,
	}); res.Err != nil {
		t.Fatal(res.Err)
	}
	if _, err := os.Stat(filepath.Join(dst, "extra")); err != nil {
		t.Error("extra removed without --delete")
	}
}
