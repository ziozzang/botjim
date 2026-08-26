package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
