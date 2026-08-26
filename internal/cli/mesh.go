package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ziozzang/botjim/internal/relay"
)

// configPathEnv is the config this process reads/writes ($BOTJIM_CONFIG
// wins, matching every other config lookup).
func configPathEnv() string {
	if p := os.Getenv("BOTJIM_CONFIG"); p != "" {
		return p
	}
	return ConfigPath()
}

// saveConfig writes the config atomically (tmp + rename).
func saveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func ed25519PubHex(priv ed25519.PrivateKey) string {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

func ed25519SignHex(priv ed25519.PrivateKey, body []byte) string {
	return hex.EncodeToString(ed25519.Sign(priv, body))
}

func ed25519VerifyHex(pubHex string, body []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, body, sig)
}

// Mesh config propagation: the endpoints list is wrapped in a signed,
// versioned envelope (.botjim-mesh.json) that rides an ordinary sync
// push. A receiving server whose config pins the mesh public key
// validates the signature and a strictly-increasing version, then
// merges the endpoints into its own ~/.botjim/config.json — edit the
// list on one node, every node converges. No protocol changes: the
// envelope is just a file the engine already knows how to move.
//
// The envelope carries endpoint credentials (tokens), so propagate it
// only over encrypted sessions (--pass) or a trusted network — the
// same rule as the transfers themselves.

// MeshEnvelopeName is the reserved manifest path of the envelope.
const MeshEnvelopeName = ".botjim-mesh.json"

// meshEnvelope is the signed config carrier.
type meshEnvelope struct {
	Version   int64               `json:"version"`
	Origin    string              `json:"origin"`
	TS        string              `json:"ts"`
	Endpoints map[string]Endpoint `json:"endpoints"`
	PubKey    string              `json:"pubkey"`
	Sig       string              `json:"sig"`
}

// unsignedBody is the canonical bytes the signature covers.
func (m *meshEnvelope) unsignedBody() []byte {
	c := *m
	c.PubKey, c.Sig = "", ""
	b, err := json.Marshal(&c)
	if err != nil {
		return nil
	}
	return b
}

// applyMeshEnvelope reads the envelope at path, checks it against the
// pinned mesh key and version in the local config, and merges it in.
// Every check fails closed: unsigned, wrong key, stale version or
// tampered bytes leave the config untouched.
func applyMeshEnvelope(envelopePath string) error {
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		return err
	}
	var env meshEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("mesh envelope: bad JSON: %w", err)
	}
	cfgPath := configPathEnv()
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("mesh envelope: config: %w", err)
	}
	if cfg.Mesh == nil || cfg.Mesh.Key == "" {
		return fmt.Errorf("mesh envelope: no mesh key pinned — set mesh.key first")
	}
	if env.PubKey != cfg.Mesh.Key {
		return fmt.Errorf("mesh envelope: signed by an unpinned key (%.16s…)", env.PubKey)
	}
	if env.Version <= cfg.Mesh.Version {
		return fmt.Errorf("mesh envelope: stale (v%d ≤ local v%d)", env.Version, cfg.Mesh.Version)
	}
	if !ed25519VerifyHex(env.PubKey, env.unsignedBody(), env.Sig) {
		return fmt.Errorf("mesh envelope: signature verification failed")
	}
	// merge: envelope wins per name, node-local endpoints survive
	if cfg.Endpoints == nil {
		cfg.Endpoints = map[string]Endpoint{}
	}
	for name, ep := range env.Endpoints {
		cfg.Endpoints[name] = ep
	}
	cfg.Mesh.Version = env.Version
	cfg.Mesh.Origin = env.Origin
	if err := saveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("mesh envelope: %w", err)
	}
	return nil
}

// meshOnCommit returns the server-side commit hook when the local
// config pins a mesh key (nil otherwise).
func meshOnCommit(root string) func(rel string) {
	cfg := loadConfigQuiet()
	if cfg.Mesh == nil || cfg.Mesh.Key == "" {
		return nil
	}
	return func(rel string) {
		if rel != MeshEnvelopeName {
			return
		}
		if err := applyMeshEnvelope(filepath.Join(root, rel)); err != nil {
			fmt.Fprintf(os.Stderr, "mesh config rejected: %v\n", err)
			return
		}
		cfg, _ := LoadConfig(configPathEnv())
		fmt.Fprintf(os.Stderr, "mesh config updated to v%d from %s\n", cfg.Mesh.Version, cfg.Mesh.Origin)
	}
}

// cmdConfigPublish implements `botjim config publish`: wrap the current
// endpoints in a signed envelope with the next version, written to
// --out (default ./.botjim-mesh.json, ready to be sync-pushed).
func cmdConfigPublish(args []string) int {
	var (
		out     string
		keyPath string
	)
	fs := newFlagSet("config publish", "botjim config publish [--out FILE]",
		"Sign the endpoints list as a versioned mesh envelope.\nSync-push the file (or drop it in a watched dir) and every node\nwith the mesh key pinned merges it automatically.")
	fs.StringVar(&out, "out", MeshEnvelopeName, "envelope output path")
	fs.StringVar(&keyPath, "key", relay.DefaultMeshKeyPath(), "mesh signing key (created when missing)")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	cfgPath := configPathEnv()
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if len(cfg.Endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "error: no endpoints in the config to publish")
		return 3
	}
	if cfg.Mesh == nil {
		cfg.Mesh = &MeshConfig{}
	}
	priv, err := relay.LoadOrCreateEd25519Key(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	origin, _ := os.Hostname()
	if origin == "" {
		origin = "unknown"
	}
	env := &meshEnvelope{
		Version:   cfg.Mesh.Version + 1,
		Origin:    origin,
		TS:        time.Now().UTC().Format(time.RFC3339),
		Endpoints: cfg.Endpoints,
	}
	pub := ed25519PubHex(priv)
	sig := ed25519SignHex(priv, env.unsignedBody())
	env.PubKey, env.Sig = pub, sig
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	// remember our own version so we accept our own (and later) updates
	cfg.Mesh.Version = env.Version
	cfg.Mesh.Origin = origin
	if cfg.Mesh.Key == "" {
		cfg.Mesh.Key = pub
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not record mesh version:", err)
	}
	fmt.Fprintf(os.Stderr, "envelope: %s (v%d, %d endpoints, origin %s)\n", out, env.Version, len(env.Endpoints), env.Origin)
	fmt.Fprintf(os.Stderr, "mesh key: %s\nsync-push it (e.g. into a --watch dir); nodes pin it via mesh.key\n", pub)
	return 0
}
