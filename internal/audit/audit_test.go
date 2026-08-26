package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainVerifiesAndDetectsTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	j, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := j.Append("2026-08-26T00:00:00Z", "file-done", map[string]any{"path": "f", "n": i}); err != nil {
			t.Fatal(err)
		}
	}
	j.Close()

	n, brk, err := Verify(p)
	if err != nil || n != 5 || brk != "" {
		t.Fatalf("clean chain: n=%d brk=%q err=%v", n, brk, err)
	}

	// tamper: rewrite entry 3's detail
	b, _ := os.ReadFile(p)
	lines := strings.Split(string(b), "\n")
	mod := strings.Replace(lines[2], "f", "HACKED", 1)
	if mod == lines[2] {
		t.Fatal("tamper substitution failed")
	}
	lines[2] = mod
	os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o640)
	n, brk, _ = Verify(p)
	if n >= 3 || brk == "" {
		t.Fatalf("tamper not detected: n=%d brk=%q", n, brk)
	}

	// deletion: drop entry 2 → link break at the following entry
	b, _ = os.ReadFile(p)
	lines = strings.Split(string(b), "\n")
	kept := append(lines[:1], lines[2:]...)
	p2 := filepath.Join(t.TempDir(), "a2.log")
	os.WriteFile(p2, []byte(strings.Join(kept, "\n")), 0o640)
	n, brk, _ = Verify(p2)
	if n >= 2 || brk == "" {
		t.Fatalf("deletion not detected: n=%d brk=%q", n, brk)
	}
}

func TestResumeChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	j, _ := Open(p)
	j.Append("t", "a", nil)
	j.Close()
	j2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := j2.Append("t", "b", nil); err != nil {
		t.Fatal(err)
	}
	j2.Close()
	n, brk, _ := Verify(p)
	if n != 2 || brk != "" {
		t.Fatalf("resume chain: n=%d brk=%q", n, brk)
	}
	// sequence must continue, not restart
	es, _ := ReadAll(p)
	if es[1].Seq != 2 {
		t.Fatalf("seq: %+v", es)
	}
}

// TestTornTailRepair: a crash mid-Append must not swallow future entries
// — Open truncates the partial line so the next Append is readable.
func TestTornTailRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.log")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := j.Append(time.Now().UTC().Format(time.RFC3339), "send", fmt.Sprintf("run %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	j.Close()
	// simulate a crash mid-write: half a JSON line, no newline
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	f.WriteString(`{"seq":4,"ts":"2026-01-01T00:00:0`)
	f.Close()

	j2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := j2.Append(time.Now().UTC().Format(time.RFC3339), "send", "after crash"); err != nil {
		t.Fatal(err)
	}
	j2.Close()

	n, brk, err := Verify(path)
	if err != nil || brk != "" {
		t.Fatalf("verify: n=%d brk=%q err=%v", n, brk, err)
	}
	if n != 4 {
		t.Fatalf("entries visible after repair: %d, want 4 (3 + post-crash append)", n)
	}
}

// TestMidFileCorruptionIsNotRepaired: a complete-but-unparseable line in
// the MIDDLE of the journal is tampering evidence, not a torn tail —
// Open must refuse to append rather than truncate history away.
func TestMidFileCorruptionIsNotRepaired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.log")
	j, _ := Open(path)
	for i := 0; i < 5; i++ {
		if err := j.Append("2026-01-01T00:00:00Z", "e", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	j.Close()
	before, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(before), "\n"), "\n")
	lines[2] = "{ tampered, not json"
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640)
	tampered, _ := os.ReadFile(path)

	if _, err := Open(path); err == nil {
		t.Fatal("Open on a mid-file-corrupt journal must fail closed")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(tampered) {
		t.Fatalf("Open modified a corrupt journal: %d bytes -> %d (evidence destroyed)", len(tampered), len(after))
	}
}
