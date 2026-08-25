package sidecar

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/chunking"
	"github.com/ziozzang/botjim/internal/manifest"
)

func testEntry(size int64) manifest.Entry {
	return manifest.Entry{
		ID: 1, Kind: manifest.KindRegular, RelPath: "a/b.bin",
		Size:      size,
		ChunkSize: chunking.ChunkSizeFor(size),
		Mtime:     manifest.Timespec{Sec: 1715000000, Nsec: 42},
	}
}

func TestSidecarRoundtrip(t *testing.T) {
	dir := t.TempDir()
	e := testEntry(chunking.SmallChunk*2 + 10)
	sc := New(e, "abcd1234")
	h := chunking.ChunkSHA(e.RelPath, 0, []byte("data0"))
	sc.SetHave(0, h, false)
	sc.SetHave(1, chunking.ZeroHash, true)

	part := PartPath(filepath.Join(dir, "b.bin"), "abcd1234")
	if err := sc.SaveAtomic(part); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(MetaPath(filepath.Join(dir, "b.bin"), "abcd1234"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Nonce != "abcd1234" || !loaded.Have(0) || !loaded.Have(1) || loaded.Have(2) {
		t.Fatalf("roundtrip state: %+v", loaded)
	}
	if loaded.Hashes[0] == "" || loaded.Hashes[1] != "Z" || loaded.Hashes[2] != "" {
		t.Fatalf("hash markers: %v", loaded.Hashes)
	}
	if loaded.HaveCount() != 2 {
		t.Fatalf("have count %d", loaded.HaveCount())
	}
	if err := loaded.Validate(e, true); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRejectsChangedSource(t *testing.T) {
	sc := New(testEntry(1000), "n")
	if err := sc.Validate(testEntry(1000), true); err != nil {
		t.Fatalf("identical entry rejected: %v", err)
	}
	if err := sc.Validate(testEntry(1001), true); err == nil {
		t.Fatal("size change accepted")
	}
	changed := testEntry(1000)
	changed.Mtime.Nsec = 99
	if err := sc.Validate(changed, true); err == nil {
		t.Fatal("mtime change accepted (strict)")
	}
	if err := sc.Validate(changed, false); err != nil {
		t.Fatalf("size-only mode must ignore mtime: %v", err)
	}
}

func TestDiscoverNewestWins(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "f.bin")
	old := PartPath(final, "old0")
	newer := PartPath(final, "new0")
	for _, p := range []string{old, newer} {
		if err := os.WriteFile(p, make([]byte, 16), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fut := filepath.Join(dir, "other.fs-part-zzz")
	_ = os.WriteFile(fut, make([]byte, 16), 0o600)

	part, meta, stale := Discover(final)
	if part == "" || len(stale) != 1 {
		t.Fatalf("discover: part=%q stale=%v", part, stale)
	}
	if meta != "" {
		t.Fatalf("no sidecar written, but meta=%q", meta)
	}
}

func TestCorruptSidecarRejected(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "f")
	part := PartPath(final, "n1")
	_ = os.WriteFile(part, make([]byte, 4), 0o600)
	meta := MetaPath(final, "n1")
	_ = os.WriteFile(meta, []byte("{not json"), 0o600)
	if _, err := Load(meta); err == nil {
		t.Fatal("corrupt sidecar accepted")
	}
	p2, m2, _ := Discover(final)
	if p2 == "" || m2 == "" {
		t.Fatal("discover must still find the part")
	}
}

func TestSaveAtomicNeverLeavesTmp(t *testing.T) {
	dir := t.TempDir()
	sc := New(testEntry(10), "nn")
	part := PartPath(filepath.Join(dir, "x"), "nn")
	if err := sc.SaveAtomic(part); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("tmp left behind: %s", e.Name())
		}
	}
}
