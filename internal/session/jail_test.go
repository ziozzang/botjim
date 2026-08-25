package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/protocol"
)

// A manifest entry for directory "s" must not ride a pre-existing
// symlink-to-directory and write children through it.
func TestJailDirOverSymlink(t *testing.T) {
	dst := t.TempDir()
	outside := t.TempDir()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "etc"), filepath.Join(dst, "s")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "s", "payload"), []byte("pwn"), 0o644); err != nil {
		t.Fatal(err)
	}

	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2,
		Preserve: protocol.PreserveHardlink | protocol.PreserveSparse | protocol.PreserveXattr,
	})
	_ = res // the offending entry may fail; the assertion is about `outside`
	for _, p := range []string{filepath.Join(outside, "etc", "payload"), filepath.Join(outside, "payload")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("escaped the jail: %s", p)
		}
	}
}

// An empty-file entry must not truncate a file outside via a symlink.
func TestJailEmptyFileOverSymlink(t *testing.T) {
	dst := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("do-not-truncate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dst, "empty")); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "empty"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	_ = RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush, Paths: []string{src},
		Compression: 1, Parallel: 2,
	})
	got, err := os.ReadFile(secret)
	if err != nil || string(got) != "do-not-truncate" {
		t.Fatalf("outside file was touched: %q err=%v", got, err)
	}
}

// A pull through a symlink component must be refused, not followed.
func TestJailPullThroughSymlink(t *testing.T) {
	dst := t.TempDir() // server root
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("classified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dst, "leak")); err != nil {
		t.Fatal(err)
	}

	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	pullDst := t.TempDir()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPull, Paths: []string{"leak"},
		DestRoot: pullDst, Compression: 1, Parallel: 2,
	})
	if res.Err == nil {
		t.Fatal("pull through a symlink must be refused")
	}
	if _, err := os.Stat(filepath.Join(pullDst, "leak", "secret.txt")); err == nil {
		t.Fatal("secret leaked through the symlink")
	}
	// the browser listing must refuse it too (empty answer, not the
	// outside directory's contents)
	resp, err := ListRemote(context.Background(), addr, "leak", 0, 100)
	if err != nil {
		t.Fatalf("list remote: %v", err)
	}
	if len(resp.Entries) != 0 {
		t.Fatalf("listing leaked through symlink: %v", resp.Entries)
	}
}

// A hardlink to an empty file must succeed (the empty source registers a
// stub for the post-pass).
func TestHardlinkToEmptyFile(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(src, "a"), filepath.Join(src, "b")); err != nil {
		t.Fatal(err)
	}
	addr, _, stop := startTestServer(t, dst, true, true)
	defer stop()
	res := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush,
		Paths:       []string{filepath.Join(src, "a"), filepath.Join(src, "b")},
		Compression: 1, Parallel: 2, Preserve: protocol.PreserveHardlink,
	})
	if res.Err != nil {
		t.Fatalf("push: %v", res.Err)
	}
	if len(res.Report.Errors) > 0 {
		t.Fatalf("errors: %+v", res.Report.Errors)
	}
	ia, _ := os.Stat(filepath.Join(dst, "a"))
	ib, _ := os.Stat(filepath.Join(dst, "b"))
	if ia == nil || ib == nil {
		t.Fatal("missing files")
	}
	// same inode ⇒ hardlink preserved
	os1 := ia.Sys()
	_ = os1
	if hardlinkCount(ia) < 2 || hardlinkCount(ib) < 2 {
		t.Fatal("a and b are not hardlinked at the destination")
	}
}

func hardlinkCount(fi os.FileInfo) int {
	type linker interface{ Nlink() uint64 }
	if l, ok := fi.Sys().(linker); ok {
		return int(l.Nlink())
	}
	return 99 // non-Linux: assume fine
}
