package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/relay"
)

func writeTestConfig(t *testing.T, path string, cfg *Config) {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMeshEnvelopeLifecycle(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mesh.key")
	cfgPath := filepath.Join(dir, "config.json")

	// publisher side: endpoints exist, key generated on publish
	writeTestConfig(t, cfgPath, &Config{
		Endpoints: map[string]Endpoint{"lab1": {Addr: "10.0.0.5:4761", Token: "t1"}},
	})
	t.Setenv("BOTJIM_CONFIG", cfgPath)
	envPath := filepath.Join(dir, MeshEnvelopeName)
	if code := cmdConfigPublish([]string{"--key", keyPath, "--out", envPath}); code != 0 {
		t.Fatalf("publish rc=%d", code)
	}

	// subscriber side: pins the publisher's public key
	pubA := loadPub(t, envPath)
	sub := &Config{Mesh: &MeshConfig{Key: pubA, Version: 0}}
	subPath := filepath.Join(dir, "sub.json")
	writeTestConfig(t, subPath, sub)

	// apply: endpoints merge in, version recorded
	if err := withConfigPath(subPath, func() error { return applyMeshEnvelope(envPath) }); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got, err := LoadConfig(subPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints["lab1"].Addr != "10.0.0.5:4761" || got.Endpoints["lab1"].Token != "t1" {
		t.Fatalf("merged endpoints wrong: %+v", got.Endpoints)
	}
	if got.Mesh.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Mesh.Version)
	}

	// replay: same version rejected as stale
	if err := withConfigPath(subPath, func() error { return applyMeshEnvelope(envPath) }); err == nil {
		t.Fatal("replay accepted")
	}

	// tamper: edit content, keep signature → rejected, config untouched
	tampered := readEnv(t, envPath)
	tampered.Endpoints["evil"] = Endpoint{Addr: "1.2.3.4:1"}
	tampered.Version = 99
	writeEnv(t, envPath, tampered)
	if err := withConfigPath(subPath, func() error { return applyMeshEnvelope(envPath) }); err == nil {
		t.Fatal("tampered envelope accepted")
	}
	got2, _ := LoadConfig(subPath)
	if _, ok := got2.Endpoints["evil"]; ok {
		t.Fatal("tampered endpoints leaked into the config")
	}
	if got2.Mesh.Version != 1 {
		t.Fatalf("version moved on rejection: %d", got2.Mesh.Version)
	}

	// unpinned key: a second publisher's envelope is refused
	other, err := relay.GenerateSwarmKey(filepath.Join(dir, "other.key"))
	if err != nil {
		t.Fatal(err)
	}
	foreign := &meshEnvelope{Version: 50, Origin: "attacker", Endpoints: map[string]Endpoint{"x": {Addr: "6.6.6.6:1"}}}
	foreign.PubKey = ed25519PubHex(other)
	foreign.Sig = ed25519SignHex(other, foreign.unsignedBody())
	writeEnv(t, envPath, foreign)
	if err := withConfigPath(subPath, func() error { return applyMeshEnvelope(envPath) }); err == nil {
		t.Fatal("envelope signed by an unpinned key accepted")
	}
}

// withConfigPath runs fn with BOTJIM_CONFIG pointed at path.
func withConfigPath(path string, fn func() error) error {
	old := os.Getenv("BOTJIM_CONFIG")
	os.Setenv("BOTJIM_CONFIG", path)
	defer os.Setenv("BOTJIM_CONFIG", old)
	return fn()
}

func loadPub(t *testing.T, envPath string) string {
	t.Helper()
	return readEnv(t, envPath).PubKey
}

func readEnv(t *testing.T, envPath string) *meshEnvelope {
	t.Helper()
	b, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	var env meshEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	return &env
}

func writeEnv(t *testing.T, envPath string, env *meshEnvelope) {
	t.Helper()
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
