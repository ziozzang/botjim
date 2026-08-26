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

// TestVerifyShortPubKeyNoPanic: attacker-chosen short pubkey/sig values
// must error cleanly, never slice-panic.
func TestVerifyShortPubKeyNoPanic(t *testing.T) {
	// both halves present but malformed → rejected outright
	bad := SwarmManifest{PubKey: "ab", Sig: "cd"}
	if err := bad.Verify(""); err == nil {
		t.Fatal("malformed keypair accepted")
	}
	// a signature without a public key (or vice versa) is meaningless →
	// treated as unsigned (accepted without a pin, rejected with one)
	for i, orphan := range []SwarmManifest{{Sig: "ff"}, {PubKey: "00112233"}} {
		if err := orphan.Verify(""); err != nil {
			t.Fatalf("case %d: partial signature treated as signed: %v", i, err)
		}
		if err := orphan.Verify("aa"); err == nil {
			t.Fatalf("case %d: partial signature accepted with a pinned key", i)
		}
	}
	m := &SwarmManifest{PubKey: "ab", Sig: "cd"}
	if err := m.Verify("ab"); err == nil {
		t.Fatal("short key accepted when pinned")
	}
	// different-key error path with short keys must not panic either
	m2 := &SwarmManifest{PubKey: "abcd", Sig: "0011"}
	_ = m2.Verify("zzzz")
}
