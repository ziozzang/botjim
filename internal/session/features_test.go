package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ziozzang/botjim/internal/protocol"
)

// TestTokenAuth: a token server refuses plaintext and wrong-token clients.
func TestTokenAuth(t *testing.T) {
	dst := t.TempDir()
	addr, _, stop := startTestServerOpts(t, dst, ServerConfig{
		Root: dst, AllowPush: true, AllowPull: true, Parallel: 4, Fsync: true,
		Token: "sekrit-token",
	})
	defer stop()

	// no token → refused
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{"/etc/hostname"},
		Compression: 1, Parallel: 2,
	})
	if res.Err == nil {
		t.Fatal("plaintext client accepted by token server")
	}

	// wrong token → refused
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{"/etc/hostname"},
		Compression: 1, Parallel: 2, Token: "wrong",
	})
	if res.Err == nil {
		t.Fatal("wrong token accepted")
	}

	// right token → works
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "ok.txt"), []byte("v"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "ok.txt")},
		Compression: 1, Parallel: 2, Token: "sekrit-token",
	})
	if res.Err != nil {
		t.Fatalf("correct token refused: %v", res.Err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "ok.txt")); err != nil || string(b) != "v" {
		t.Fatalf("content wrong: %q %v", b, err)
	}
}

// TestPassEncryption: passphrase sessions work; a plaintext client is
// refused by an encrypted server, and a wrong passphrase fails.
func TestPassEncryption(t *testing.T) {
	dst := t.TempDir()
	addr, _, stop := startTestServerOpts(t, dst, ServerConfig{
		Root: dst, AllowPush: true, AllowPull: true, Parallel: 4, Fsync: true,
		Pass: "a-long-passphrase-42",
	})
	defer stop()

	src := t.TempDir()
	p := filepath.Join(src, "e.txt")
	if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// plaintext client → refused
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{p},
		Compression: 1, Parallel: 2,
	})
	if res.Err == nil {
		t.Fatal("plaintext client accepted by encrypted server")
	}

	// wrong passphrase → handshake fails
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{p},
		Compression: 1, Parallel: 2, Pass: "another-long-passphrase",
	})
	if res.Err == nil {
		t.Fatal("wrong passphrase accepted")
	}

	// correct passphrase → transfer succeeds and decrypts
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{p},
		Compression: 1, Parallel: 2, Pass: "a-long-passphrase-42",
	})
	if res.Err != nil {
		t.Fatalf("encrypted transfer failed: %v", res.Err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "e.txt")); err != nil || string(b) != "secret" {
		t.Fatalf("decrypted content wrong: %q %v", b, err)
	}
}

// TestExcludeInclude: walker filters flow through a real transfer.
func TestExcludeInclude(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	for _, n := range []string{"keep.txt", "skip.log", "sub/x.tmp", "sub/y.txt"} {
		p := filepath.Join(src, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()

	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2, Exclude: []string{"*.log", "*.tmp"},
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	for _, gone := range []string{"skip.log", "sub/x.tmp"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.Base(src), gone)); err == nil {
			t.Errorf("excluded file transferred: %s", gone)
		}
	}
	for _, keep := range []string{"keep.txt", "sub/y.txt"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.Base(src), keep)); err != nil {
			t.Errorf("kept file missing: %s", keep)
		}
	}

	// include narrows to only *.txt
	dst2 := t.TempDir()
	addr2, _, stop2 := startTestServer(t, dst2, true, true)
	defer stop2()
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr2, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2, Include: []string{"*.txt"},
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if _, err := os.Stat(filepath.Join(dst2, filepath.Base(src), "skip.log")); err == nil {
		t.Error("include filter did not narrow")
	}
}

// TestDeltaTransfer: same-size changed file → only differing chunks move.
func TestDeltaTransfer(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	// 12 MiB in 4 MiB chunks; chunk 0 differs, chunks 1-2 identical
	body := make([]byte, 12<<20)
	for i := range body {
		body[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")},
		Compression: 0, Parallel: 2,
	})
	if res.Err != nil || res.Report.Bytes != 12<<20 {
		t.Fatalf("seed: %+v %v", res.Report, res.Err)
	}
	stop()

	// change chunk 0 only, shift mtime
	body2 := append([]byte(nil), body...)
	for i := 0; i < 1<<20; i++ {
		body2[i] ^= 0xFF
	}
	if err := os.WriteFile(filepath.Join(src, "data.bin"), body2, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(filepath.Join(src, "data.bin"), time.Now(), time.Now().Add(time.Second))

	addr2, _, stop2 := startTestServer(t, dst, true, true)
	defer stop2()
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr2, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")},
		Compression: 0, Parallel: 2,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	// delta should move ~1 chunk (4 MiB), not 12 MiB
	if res.Report.Bytes > 5<<20 {
		t.Fatalf("delta moved %d bytes (expected ~4MiB)", res.Report.Bytes)
	}
	got, err := os.ReadFile(filepath.Join(dst, "data.bin"))
	if err != nil || string(got) != string(body2) {
		t.Fatal("delta result content mismatch")
	}
}

// TestDryRun: the plan reports skips and sends without touching the dest.
func TestDryRun(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.bin"), make([]byte, 5<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()

	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "a.bin")},
		Compression: 1, Parallel: 2,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	stop()

	addr2, _, stop2 := startTestServer(t, dst, true, true)
	defer stop2()
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr2, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "a.bin")},
		Compression: 1, Parallel: 2, Preserve: protocol.PreserveDryRun,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if len(res.Plan) != 1 || res.Plan[0].Status != "skip" {
		t.Fatalf("plan wrong: %+v", res.Plan)
	}
	// nothing re-transferred
	if res.Report.Bytes != 0 {
		t.Fatalf("dry-run moved %d bytes", res.Report.Bytes)
	}
}

// TestDeltaZeroChunk: a chunk that becomes all-zero in the new version
// must be physically zeroed at the destination — the fresh-part hole
// optimization must not leave the old bytes behind (regression).
func TestDeltaZeroChunk(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	body := make([]byte, 12<<20)
	for i := range body {
		body[i] = byte(i%250) + 1 // no zero bytes
	}
	if err := os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")},
		Parallel: 2, Preserve: protocol.PreserveSparse,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	stop()

	// zero out chunk 1 (4-8 MiB)
	body2 := append([]byte(nil), body...)
	for i := 4 << 20; i < 8<<20; i++ {
		body2[i] = 0
	}
	if err := os.WriteFile(filepath.Join(src, "data.bin"), body2, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(filepath.Join(src, "data.bin"), time.Now(), time.Now().Add(time.Second))

	addr2, _, stop2 := startTestServer(t, dst, true, true)
	defer stop2()
	res = RunTransfer(context.Background(), ClientConfig{
		Addr: addr2, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")},
		Parallel: 2, Preserve: protocol.PreserveSparse,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "data.bin"))
	if err != nil || !bytes.Equal(got, body2) {
		t.Fatal("zeroed chunk kept the old bytes (delta zero-write regression)")
	}
}

// TestRebuildClaimsUntrusted: a leftover part WITHOUT its sidecar whose
// content does not match the source must not be silently adopted — the
// rebuilt claim goes out with hashes and the sender resends mismatches
// (regression: stale parts used to be trusted verbatim).
func TestRebuildClaimsUntrusted(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	body := make([]byte, 12<<20)
	for i := range body {
		body[i] = byte((i * 7) % 249)
	}
	if err := os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	// craft a stale, sidecar-less part at the destination (an interrupted
	// older session whose source has since changed)
	stale := make([]byte, 12<<20)
	for i := range stale {
		stale[i] = byte(i % 199)
	}
	if err := os.WriteFile(filepath.Join(dst, "data.bin.fs-part-deadbeef00000000"), stale, 0o600); err != nil {
		t.Fatal(err)
	}

	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")},
		Parallel: 2,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "data.bin"))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("stale sidecar-less part was adopted without verification")
	}
}

// TestDeltaPreservesSidecarSibling: a delta-adopted file must not clobber
// a legitimate sibling named <final>.json (the adopted sidecar used to
// land there and then get deleted — silent data loss).
func TestDeltaPreservesSidecarSibling(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	body := make([]byte, 12<<20)
	for i := range body {
		body[i] = byte(i % 253)
	}
	os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644)

	addr, _, stop := startTestServer(t, dst, true, true)
	if r := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")}, Parallel: 2,
	}); r.Err != nil {
		t.Fatal(r.Err)
	}
	stop()
	// an innocent bystander in the dest whose name collides with the
	// adopted sidecar's degraded path (<final>.json)
	if err := os.WriteFile(filepath.Join(dst, "data.bin.json"), []byte("precious sibling"), 0o644); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 1<<20; i++ {
		body[i] ^= 0xAA
	}
	os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644)
	os.Chtimes(filepath.Join(src, "data.bin"), time.Now(), time.Now().Add(time.Second))

	addr2, _, stop2 := startTestServer(t, dst, true, true)
	defer stop2()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr2, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")}, Parallel: 2,
	})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	sib, err := os.ReadFile(filepath.Join(dst, "data.bin.json"))
	if err != nil || string(sib) != "precious sibling" {
		t.Fatalf("sidecar sibling clobbered: %q %v", sib, err)
	}
	got, _ := os.ReadFile(filepath.Join(dst, "data.bin"))
	if !bytes.Equal(got, body) {
		t.Fatal("delta content wrong")
	}
}

// TestDeltaReadOnlyDestNoStall: a read-only destination file must fall
// through to a fresh part, not stall the whole transfer for 120s.
func TestDeltaReadOnlyDestNoStall(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	body := make([]byte, 8<<20)
	for i := range body {
		body[i] = byte(i % 247)
	}
	os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644)
	addr, _, stop := startTestServer(t, dst, true, true)
	if r := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")}, Parallel: 2,
	}); r.Err != nil {
		t.Fatal(r.Err)
	}
	stop()
	if err := os.Chmod(filepath.Join(dst, "data.bin"), 0o444); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1<<20; i++ {
		body[i] ^= 0x5A
	}
	os.WriteFile(filepath.Join(src, "data.bin"), body, 0o644)
	os.Chtimes(filepath.Join(src, "data.bin"), time.Now(), time.Now().Add(time.Second))

	addr2, _, stop2 := startTestServer(t, dst, true, true)
	defer stop2()
	done := make(chan ClientResult, 1)
	go func() {
		done <- RunTransfer(context.Background(), ClientConfig{
			Addr: addr2, Direction: protocol.DirPush, Paths: []string{filepath.Join(src, "data.bin")}, Parallel: 2,
		})
	}()
	select {
	case res := <-done:
		if res.Err != nil {
			t.Fatal(res.Err)
		}
		got, _ := os.ReadFile(filepath.Join(dst, "data.bin"))
		if !bytes.Equal(got, body) {
			t.Fatal("read-only delta content wrong")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("transfer stalled on a read-only destination file")
	}
}
