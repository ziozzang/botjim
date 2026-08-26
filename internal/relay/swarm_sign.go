package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Swarm spec signing: the seed signs the descriptor with an ed25519 key;
// joiners pin the signer's public key (--verify-key) so a swapped or
// tampered .swarm.json fails closed instead of feeding them attacker
// bytes. The signature covers the canonical JSON of the descriptor with
// the two signature fields cleared, which Go's encoder makes stable.

// Sign attaches the signer's public key and an ed25519 signature over
// UnsignedBody to the descriptor.
func (m *SwarmManifest) Sign(priv ed25519.PrivateKey) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return
	}
	m.PubKey = hex.EncodeToString(pub)
	m.Sig = hex.EncodeToString(ed25519.Sign(priv, m.UnsignedBody()))
}

// UnsignedBody returns the exact bytes the signature covers.
func (m *SwarmManifest) UnsignedBody() []byte {
	c := *m
	c.PubKey, c.Sig = "", ""
	b, err := json.Marshal(&c)
	if err != nil {
		return nil
	}
	return b
}

// Verify checks the descriptor's signature. expectedPub (hex, optional)
// additionally pins the signer; an unsigned descriptor verifies only
// when no key was pinned.
func (m *SwarmManifest) Verify(expectedPub string) error {
	if m.PubKey == "" || m.Sig == "" {
		if expectedPub != "" {
			return errors.New("spec is not signed but --verify-key pins a key")
		}
		return nil
	}
	if expectedPub != "" && !strings.EqualFold(m.PubKey, expectedPub) {
		return fmt.Errorf("signed by a different key (%s…)", m.PubKey[:16])
	}
	pub, err := hex.DecodeString(m.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("bad public key in spec")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("bad signature in spec")
	}
	if !ed25519.Verify(pub, m.UnsignedBody(), sig) {
		return errors.New("signature verification failed — the spec was modified or corrupted")
	}
	return nil
}

// Signed reports whether the descriptor carries a signature.
func (m *SwarmManifest) Signed() bool { return m.PubKey != "" && m.Sig != "" }

// DefaultSwarmKeyPath is the conventional signer key location.
func DefaultSwarmKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".botjim-swarm.key"
	}
	return filepath.Join(home, ".botjim", "keys", "swarm-ed25519")
}

// LoadSwarmKey reads a hex-encoded 64-byte ed25519 private key.
func LoadSwarmKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: not a hex key", path)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: expected %d bytes, got %d", path, ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// GenerateSwarmKey creates a fresh key at path (0600, parents created)
// and returns it.
func GenerateSwarmKey(path string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
