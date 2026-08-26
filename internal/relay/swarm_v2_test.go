package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/chunking"
)

// TestSwarmV2Catalog: the spec carries per-chunk hashes on the grid.
func TestSwarmV2Catalog(t *testing.T) {
	seedDir := t.TempDir()
	data := pattern(9 << 20) // 9MiB → 4/8/16 ladder gives >1 chunk
	if err := os.WriteFile(filepath.Join(seedDir, "model.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSwarmSpec(context.Background(), []string{seedDir}, "m")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Version != 2 {
		t.Fatalf("spec version %d, want 2", spec.Version)
	}
	f := spec.Files[0]
	grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
	if int64(len(f.Chunks)) != grid.Count() {
		t.Fatalf("catalog has %d entries, grid wants %d", len(f.Chunks), grid.Count())
	}
	for i := int64(0); i < grid.Count(); i++ {
		ch := sha256.Sum256(data[grid.Offset(i) : grid.Offset(i)+grid.Len(i)])
		if f.Chunks[i] != hex.EncodeToString(ch[:]) {
			t.Fatalf("chunk %d catalog hash mismatch", i)
		}
	}
	if f.SHA != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatal("whole-file hash mismatch")
	}
}

// TestSwarmLyingPeerBanned: a peer WITH the token (handshake passes)
// that serves bytes failing the v2 chunk catalog is banned for the
// session; the join still completes through the honest seed.
func TestSwarmLyingPeerBanned(t *testing.T) {
	seedDir := t.TempDir()
	joinDir := t.TempDir()
	data := pattern(9 << 20)
	if err := os.WriteFile(filepath.Join(seedDir, "model.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSwarmSpec(context.Background(), []string{seedDir}, "m")
	if err != nil {
		t.Fatal(err)
	}

	// the liar: same spec, same token, but corrupted bytes in EVERY
	// chunk (so whichever chunk it serves fails the catalog)
	liarDir := t.TempDir()
	lying := make([]byte, len(data))
	copy(lying, data)
	grid := chunking.Grid{Size: int64(len(data)), ChunkSize: chunking.ChunkSizeFor(int64(len(data)))}
	for i := int64(0); i < grid.Count(); i++ {
		lying[grid.Offset(i)] ^= 0xff
	}
	if err := os.WriteFile(filepath.Join(liarDir, "model.bin"), lying, 0o644); err != nil {
		t.Fatal(err)
	}

	tln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = (&TrackerProtocol{T: NewTracker()}).Serve(tln) }()

	token := GenerateCode()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = ServePeer(context.Background(), sln, spec, seedDir, token) }()
	lln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = ServePeer(context.Background(), lln, spec, liarDir, token) }()

	announceTo(context.Background(), tln.Addr().String(), token, spec.SpecHash(), sln.Addr().String(), "ff/ff", true)
	announceTo(context.Background(), tln.Addr().String(), token, spec.SpecHash(), lln.Addr().String(), "ff/ff", false)

	j := &Joiner{TrackerAddr: tln.Addr().String(), Token: token, Spec: spec, Dest: joinDir, Parallel: 2}
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(joinDir, "model.bin"))
	if err != nil || string(got) != string(data) {
		t.Fatalf("assembled bytes differ from the seed (err=%v)", err)
	}
	if !j.isBanned(lln.Addr().String()) {
		t.Fatal("lying peer was not banned")
	}
	if j.isBanned(sln.Addr().String()) {
		t.Fatal("honest seed got banned")
	}
}

// TestSwarmHTTPSource: the joiner assembles purely over HTTP Range from
// a static server when no swarm peer can serve.
func TestSwarmHTTPSource(t *testing.T) {
	seedDir := t.TempDir()
	joinDir := t.TempDir()
	data := pattern(9 << 20)
	if err := os.WriteFile(filepath.Join(seedDir, "model.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSwarmSpec(context.Background(), []string{seedDir}, "m")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir(seedDir))))
	hln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = (&http.Server{Handler: mux}).Serve(hln) }()

	tln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = (&TrackerProtocol{T: NewTracker()}).Serve(tln) }()
	token := GenerateCode()
	// nothing dialable announces: every peer fetch fails, the HTTP source
	// must carry the whole join
	announceTo(context.Background(), tln.Addr().String(), token, spec.SpecHash(), "127.0.0.1:1", "ff", false)

	j := &Joiner{
		TrackerAddr: tln.Addr().String(),
		Token:       token,
		Spec:        spec,
		Dest:        joinDir,
		Parallel:    4,
		HTTPBase:    "http://" + hln.Addr().String(),
	}
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(joinDir, "model.bin"))
	if err != nil || len(got) != len(data) {
		t.Fatalf("assembled %d bytes err=%v", len(got), err)
	}
	if string(got) != string(data) {
		t.Fatal("HTTP-assembled bytes differ")
	}
}
