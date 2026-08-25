package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeJoinJail(t *testing.T) {
	root := t.TempDir()
	ok := []string{"a", "a/b", "deep/nest/ed/file", "with spaces", "유니코드/파일"}
	for _, rel := range ok {
		if _, err := SafeJoin(root, rel); err != nil {
			t.Errorf("SafeJoin(%q) rejected: %v", rel, err)
		}
	}
	bad := map[string]string{
		"":               "empty",
		"/abs":           "absolute",
		"/../etc/passwd": "absolute",
		"../escape":      "parent",
		"a/../../b":      "parent",
		"a//b":           "empty component",
		"./a":            "dot component",
		"a/../b":         "dot component",
		"a\x00b":         "NUL",
		strings4096Bad(): "too long",
		comp255Bad():     "component too long",
	}
	for rel := range bad {
		if _, err := SafeJoin(root, rel); err == nil {
			t.Errorf("SafeJoin(%q) accepted", rel)
		}
	}
}

func strings4096Bad() string {
	s := make([]byte, 4097)
	for i := range s {
		s[i] = 'x'
	}
	return string(s)
}

func comp255Bad() string {
	s := make([]byte, 256)
	for i := range s {
		s[i] = 'y'
	}
	return string(s)
}

func TestSafeJoinPrefixNotFooled(t *testing.T) {
	root := t.TempDir()
	// a directory whose name extends the root must not pass as inside
	if err := os.MkdirAll(filepath.Join(root+"-sibling"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeJoin(root, "x"); err != nil {
		t.Fatalf("normal join rejected: %v", err)
	}
}

func TestExpandArgLiteralFirst(t *testing.T) {
	dir := t.TempDir()
	// a literal file whose name contains a metacharacter
	lit := filepath.Join(dir, "foo*bar")
	if err := os.WriteFile(lit, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// and files a real glob would match
	for _, n := range []string{"fooA", "fooB"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ExpandArg(lit)
	if err != nil || len(got) != 1 || got[0] != lit {
		t.Fatalf("literal-first failed: %v err=%v", got, err)
	}
	got, err = ExpandArg(filepath.Join(dir, "foo?"))
	if err != nil || len(got) != 2 {
		t.Fatalf("glob failed: %v err=%v", got, err)
	}
	if _, err := ExpandArg(filepath.Join(dir, "zzz*nope")); err == nil {
		t.Fatal("zero-match glob accepted")
	}
}

func TestExpandArgDoublestar(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ExpandArg(filepath.Join(dir, "**", "*.txt"))
	if err != nil || len(got) != 1 {
		t.Fatalf("doublestar: %v err=%v", got, err)
	}
}
