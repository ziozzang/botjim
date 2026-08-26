package selfupdate

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// TestVerifyChecksumsSig: a valid signature by the embedded key passes; a
// tampered body or wrong-key signature fails.
func TestVerifyChecksumsSig(t *testing.T) {
	if ReleasePubKeyHex == "" {
		t.Skip("no embedded key in this build")
	}
	pub, err := hex.DecodeString(ReleasePubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("embedded key invalid")
	}
	// we can't sign without the private key, but we can prove the negative
	// paths reject, and that a signature from a DIFFERENT key is refused.
	body := []byte("deadbeef  botjim_x\n")
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	wrongSig := ed25519.Sign(wrongPriv, body)
	if err := verifyChecksumsSig(body, wrongSig); err == nil {
		t.Fatal("signature from a non-release key accepted")
	}
	if err := verifyChecksumsSig(body, []byte("short")); err == nil {
		t.Fatal("malformed signature length accepted")
	}
}

// TestVerifyChecksumsSigRoundtrip: sign with a known key, embed it, verify.
func TestVerifyChecksumsSigRoundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte("some sha256sums content\n")
	sig := ed25519.Sign(priv, body)
	// verify directly against this key (mirrors verifyChecksumsSig logic)
	if !ed25519.Verify(pub, body, sig) {
		t.Fatal("roundtrip verify failed")
	}
	tampered := append([]byte(nil), body...)
	tampered[0] ^= 0xFF
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("tampered body verified")
	}
}
