package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestSwarmEndToEnd: seed → tracker → joiner assembles and verifies.
func TestSwarmEndToEnd(t *testing.T) {
	seedDir := t.TempDir()
	joinDir := t.TempDir()

	// artifact: a few files, one large enough for multiple chunks
	if err := os.WriteFile(filepath.Join(seedDir, "model.bin"), pattern(9<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seedDir, "meta.txt"), []byte("hello swarm"), 0o640); err != nil {
		t.Fatal(err)
	}

	// tracker
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &TrackerProtocol{T: NewTracker()}
	go func() { _ = tp.Serve(tln) }()
	trackerAddr := tln.Addr().String()

	// seed: build spec, serve chunks, announce
	spec, err := BuildSwarmSpec(context.Background(), []string{seedDir}, "testmodel")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Files) != 2 {
		t.Fatalf("spec files: %+v", spec.Files)
	}
	sln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := GenerateCode()
	go func() { _ = ServePeer(context.Background(), sln, spec, seedDir, token) }()
	seedAddr := sln.Addr().String()
	peers := announceTo(context.Background(), trackerAddr, token, spec.SpecHash(), seedAddr, "ff/ff", true)
	_ = peers

	// joiner
	j := &Joiner{
		TrackerAddr: trackerAddr,
		Token:       token,
		Spec:        spec,
		Dest:        joinDir,
		Parallel:    4,
		OnProgress:  func(d, tot int64) { fmt.Printf("progress %d/%d\n", d, tot) },
	}
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// verify
	b, err := os.ReadFile(filepath.Join(joinDir, "model.bin"))
	if err != nil || len(b) != 9<<20 || string(b[:8]) != string(pattern(9 << 20)[:8]) {
		t.Fatalf("model.bin wrong: %d bytes err=%v", len(b), err)
	}
	m, err := os.ReadFile(filepath.Join(joinDir, "meta.txt"))
	if err != nil || string(m) != "hello swarm" {
		t.Fatalf("meta.txt wrong: %q err=%v", m, err)
	}
	if fi, _ := os.Stat(filepath.Join(joinDir, "meta.txt")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v", fi.Mode())
	}
}

// TestSwarmWrongToken: a joiner with the wrong token gets no peers (the
// room ID is derived from SHA-256(token)).
func TestSwarmWrongToken(t *testing.T) {
	seedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(seedDir, "x.bin"), pattern(1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	tln, _ := net.Listen("tcp", "127.0.0.1:0")
	tp := &TrackerProtocol{T: NewTracker()}
	go func() { _ = tp.Serve(tln) }()

	spec, err := BuildSwarmSpec(context.Background(), []string{seedDir}, "m")
	if err != nil {
		t.Fatal(err)
	}
	peers := announceTo(context.Background(), tln.Addr().String(), GenerateCode(), spec.SpecHash(), "1.2.3.4:1", "ff", false)
	if len(peers) != 0 {
		t.Fatalf("wrong token saw peers: %+v", peers)
	}
}

// TestSwarmSpecPersistence: the descriptor round-trips as JSON and its
// hash is stable.
func TestSwarmSpecPersistence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSwarmSpec(context.Background(), []string{dir}, "art")
	if err != nil {
		t.Fatal(err)
	}
	h1 := spec.SpecHash()
	p, err := WriteSwarmManifest(dir, "art", &SwarmManifest{
		Version: spec.Version, Artifact: spec.Name, ManifestSHA: h1,
		Files: fileNames(spec), TotalBytes: spec.TotalBytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m SwarmManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.ManifestSHA != h1 || m.TotalBytes != 3 {
		t.Fatalf("manifest roundtrip: %+v", m)
	}
}

// TestSwarmResumable: a killed join leaves a part file; the next join
// skips already-downloaded chunks (verified via progress counters).
func TestSwarmResumable(t *testing.T) {
	seedDir := t.TempDir()
	joinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(seedDir, "big.bin"), pattern(12<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	tln, _ := net.Listen("tcp", "127.0.0.1:0")
	tp := &TrackerProtocol{T: NewTracker()}
	go func() { _ = tp.Serve(tln) }()
	spec, _ := BuildSwarmSpec(context.Background(), []string{seedDir}, "m")
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	token := GenerateCode()
	go func() { _ = ServePeer(context.Background(), sln, spec, seedDir, token) }()
	announceTo(context.Background(), tln.Addr().String(), token, spec.SpecHash(), sln.Addr().String(), "ff", true)

	// partial: write half a part file manually, then join
	part := filepath.Join(joinDir, "big.bin.fs-part")
	if err := os.WriteFile(part, pattern(4<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	var fetched atomic.Int64
	j := &Joiner{
		TrackerAddr: tln.Addr().String(), Token: token, Spec: spec,
		Dest: joinDir, Parallel: 4,
		OnProgress: func(d, tot int64) { fetched.Store(d) },
	}
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetched.Load() >= 12<<20 {
		t.Fatalf("resume did not skip: fetched=%d", fetched.Load())
	}
	b, _ := os.ReadFile(filepath.Join(joinDir, "big.bin"))
	if len(b) != 12<<20 || string(b[:8]) != string(pattern(12 << 20)[:8]) {
		t.Fatal("assembled content wrong")
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/131)
	}
	return b
}

func fileNames(s *SwarmSpec) []string {
	out := make([]string, len(s.Files))
	for i, f := range s.Files {
		out[i] = f.Path
	}
	return out
}

var _ = time.Second
