package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"

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

// lockConfig takes an exclusive cross-process lock guarding config
// read-modify-write cycles (meshApplyMu only covers this process; two
// servers or a server plus `config publish` on one config would
// otherwise silently lose updates). Returns an unlock func.
func lockConfig(cfgPath string) (func(), error) {
	lf, err := os.OpenFile(cfgPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		lf.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(lf.Fd()), unix.LOCK_UN)
		_ = lf.Close()
	}, nil
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

// meshApplyMu serializes envelope application: the commit hook can fire
// from several concurrent session finalizers, and an interleaved
// read-modify-write of the config could regress the recorded version.
var meshApplyMu sync.Mutex

// applyMeshEnvelope reads the envelope at path, checks it against the
// pinned mesh key and version in the local config, and merges it in.
// Every check fails closed: unsigned, wrong key, stale version or
// tampered bytes leave the config untouched.
func applyMeshEnvelope(envelopePath string) error {
	meshApplyMu.Lock()
	defer meshApplyMu.Unlock()
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		return err
	}
	var env meshEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("mesh envelope: bad JSON: %w", err)
	}
	cfgPath := configPathEnv()
	unlock, err := lockConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("mesh envelope: lock: %w", err)
	}
	defer unlock()
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
	if env.Version == cfg.Mesh.Version && ed25519VerifyHex(env.PubKey, env.unsignedBody(), env.Sig) {
		return errMeshCurrent // re-delivery of the applied version: quiet no-op
	}
	if env.Version <= cfg.Mesh.Version {
		return fmt.Errorf("mesh envelope: stale (v%d ≤ local v%d)", env.Version, cfg.Mesh.Version)
	}
	if !ed25519VerifyHex(env.PubKey, env.unsignedBody(), env.Sig) {
		return fmt.Errorf("mesh envelope: signature verification failed")
	}
	// bootstrap replay guard: a freshly-pinned node (version 0) would
	// accept ANY old signed envelope — bound its age (TS is signed)
	if cfg.Mesh.Version == 0 {
		if ts, terr := time.Parse(time.RFC3339, env.TS); terr != nil || time.Since(ts) > 30*24*time.Hour {
			return fmt.Errorf("mesh envelope: refusing bootstrap from an envelope older than 30 days (ts %q) — republish on the key owner's node", env.TS)
		}
	}
	// merge: envelope wins per name, node-local endpoints survive; names
	// the mesh managed before that are ABSENT now were deleted on the
	// publisher — drop them here too, or revoked endpoints live forever
	if cfg.Endpoints == nil {
		cfg.Endpoints = map[string]Endpoint{}
	}
	for _, name := range cfg.Mesh.Managed {
		if _, still := env.Endpoints[name]; !still {
			delete(cfg.Endpoints, name)
		}
	}
	managed := make([]string, 0, len(env.Endpoints))
	for name, ep := range env.Endpoints {
		cfg.Endpoints[name] = ep
		managed = append(managed, name)
	}
	sort.Strings(managed)
	cfg.Mesh.Managed = managed
	cfg.Mesh.Version = env.Version
	cfg.Mesh.Origin = env.Origin
	if err := saveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("mesh envelope: %w", err)
	}
	return nil
}

// errMeshCurrent marks a benign re-delivery of the already-applied
// envelope version (sync --watch re-pushes are routine).
var errMeshCurrent = fmt.Errorf("mesh envelope already applied")

// meshOnCommit returns the server-side commit hook. It is always
// installed (a key pinned after server start must work without a
// restart); applyMeshEnvelope fails closed per call when no key is
// pinned yet.
func meshOnCommit(root string) func(rel string) {
	return func(rel string) {
		if rel != MeshEnvelopeName {
			return
		}
		path := filepath.Join(root, rel)
		err := applyMeshEnvelope(path)
		// the envelope carries every endpoint's token/pass: never leave
		// it in the jail where any client with this server's token could
		// pull it — one leaked token must not compromise the whole mesh
		if cfg := loadConfigQuiet(); cfg.Mesh != nil && cfg.Mesh.Key != "" {
			_ = os.Remove(path)
		}
		if err != nil {
			if err == errMeshCurrent {
				return // routine re-push of the applied version
			}
			fmt.Fprintf(os.Stderr, "mesh config rejected: %v\n", err)
			return
		}
		after, lerr := LoadConfig(configPathEnv())
		if lerr != nil || after.Mesh == nil {
			// never panic the server from a commit hook
			fmt.Fprintf(os.Stderr, "mesh config applied (could not re-read: %v)\n", lerr)
			return
		}
		fmt.Fprintf(os.Stderr, "mesh config updated to v%d from %s\n", after.Mesh.Version, after.Mesh.Origin)
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
	unlock, err := lockConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	defer unlock()
	// re-read under the lock: a server applying an envelope concurrently
	// may have bumped the version between our load and here
	if fresh, ferr := LoadConfig(cfgPath); ferr == nil {
		cfg = fresh
		if cfg.Mesh == nil {
			cfg.Mesh = &MeshConfig{}
		}
	}
	var priv ed25519.PrivateKey
	if cfg.Mesh.Key != "" {
		// pinned: never mint a new key here — load only
		priv, err = relay.LoadSwarmKey(keyPath)
	} else {
		priv, err = relay.LoadOrCreateEd25519Key(keyPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	// this node may be a SUBSCRIBER: publishing with a different key
	// would ship an envelope every pinned node (this one included)
	// rejects, while bumping the local version and blocking the next
	// legitimate envelope. Refuse unless the keys match.
	if cfg.Mesh != nil && cfg.Mesh.Key != "" {
		if pub := ed25519PubHex(priv); pub != cfg.Mesh.Key {
			fmt.Fprintln(os.Stderr, "error: this config pins a different mesh key than the signing key")
			fmt.Fprintf(os.Stderr, "pinned:   %.16s…\nsigning:  %.16s…\npublish from the key owner's node, or point --key at the pinned key\n", cfg.Mesh.Key, pub)
			return 3
		}
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
	// record the version BEFORE the envelope exists anywhere: a crash
	// between the two wastes one version number (harmless), while the
	// old order could emit two different envelopes with the SAME version
	// — permanent split-brain, every node rejecting the one it missed
	cfg.Mesh.Version = env.Version
	cfg.Mesh.Origin = origin
	if cfg.Mesh.Key == "" {
		cfg.Mesh.Key = pub
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error: could not record mesh version (refusing to emit the envelope):", err)
		return 2
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "envelope: %s (v%d, %d endpoints, origin %s)\n", out, env.Version, len(env.Endpoints), env.Origin)
	fmt.Fprintf(os.Stderr, "mesh key: %s\nsync-push it (e.g. into a --watch dir); nodes pin it via mesh.key\n", pub)
	return 0
}
