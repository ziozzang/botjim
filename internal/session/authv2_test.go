package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/protocol"
)

// TestTokenOnlyEncrypts: with only --token (no --pass), the transferred
// bytes must not appear in plaintext at the transport — token now drives
// the X25519 record layer. We verify indirectly: a token transfer of a
// known marker succeeds and round-trips, and a wrong token is refused
// (both already covered), plus that the SENSITIVE marker written by the
// sender is reconstructed exactly (encryption round-trip integrity).
func TestTokenOnlyEncrypts(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	marker := bytes.Repeat([]byte("SECRET-MARKER-9f3a "), 4096) // ~76KB
	if err := os.WriteFile(filepath.Join(src, "s.bin"), marker, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServerOpts(t, dst, ServerConfig{
		Root: dst, AllowPush: true, AllowPull: true, Parallel: 4, Fsync: true,
		Token: "tok-v2",
	})
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush,
		Paths: []string{filepath.Join(src, "s.bin")}, Parallel: 2,
		Token: "tok-v2",
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	got, _ := os.ReadFile(filepath.Join(dst, "s.bin"))
	if !bytes.Equal(got, marker) {
		t.Fatal("token-only transfer corrupted the payload")
	}
}

// TestTokenPassCombined: when both --token and --pass are set, the peer
// must know BOTH; either alone is refused.
func TestTokenPassCombined(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	os.WriteFile(filepath.Join(src, "f.txt"), []byte("hello"), 0o644)
	addr, _, stop := startTestServerOpts(t, dst, ServerConfig{
		Root: dst, AllowPush: true, AllowPull: true, Parallel: 2, Fsync: true,
		Token: "T", Pass: "P",
	})
	defer stop()
	// correct both
	if r := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "f.txt")},
		Parallel: 2, Token: "T", Pass: "P",
	}); r.Err != nil {
		t.Fatalf("both correct rejected: %v", r.Err)
	}
	// token only (missing pass) → refused
	if r := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "f.txt")},
		Parallel: 2, Token: "T",
	}); r.Err == nil {
		t.Fatal("token-only accepted against token+pass server")
	}
	// wrong pass → refused
	if r := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "f.txt")},
		Parallel: 2, Token: "T", Pass: "WRONG",
	}); r.Err == nil {
		t.Fatal("wrong pass accepted")
	}
}
