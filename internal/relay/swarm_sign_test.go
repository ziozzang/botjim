package relay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerify(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "k1")
	if _, err := GenerateSwarmKey(kp); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(kp)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", fi.Mode().Perm())
	}
	priv, err := LoadSwarmKey(kp)
	if err != nil {
		t.Fatal(err)
	}

	m := &SwarmManifest{Version: 1, Artifact: "m", ManifestSHA: "aa", Files: []string{"a"}}
	m.Sign(priv)
	if !m.Signed() {
		t.Fatal("not signed after Sign")
	}
	if err := m.Verify(""); err != nil {
		t.Fatalf("valid sig rejected: %v", err)
	}

	// tamper → must fail
	m2 := *m
	m2.Artifact = "evil"
	if err := m2.Verify(""); err == nil {
		t.Fatal("tampered body accepted")
	}
	// pinned to the wrong key → must fail
	if err := m.Verify("ab" + m.PubKey[2:]); err == nil {
		t.Fatal("wrong pinned key accepted")
	}
	// unsigned spec + pinned key → must fail
	u := &SwarmManifest{Version: 1}
	if err := u.Verify(m.PubKey); err == nil {
		t.Fatal("unsigned spec accepted with pinned key")
	}
	if err := u.Verify(""); err != nil {
		t.Fatalf("unsigned spec without pin rejected: %v", err)
	}
}
