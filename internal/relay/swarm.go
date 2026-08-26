// Swarm: token-joined distribution for one immutable artifact (an LLM
// model, a dataset). The design the user steered to:
//
//   - join BY TOKEN: the swarm token authenticates the tracker join
//     (the tracker matches SHA-256(token), never sees it) AND keys every
//     peer↔peer link (the e2ee record layer with the token as PSK — a
//     peer without the token cannot even complete the handshake)
//   - chunk-level: receivers fetch missing chunks from ANY source
//     (seed or peer) via the existing ChunkRequest machinery; every chunk
//     is hash-verified, so a malicious peer serving garbage is detected
//     and re-routed, never written
//   - manifest = swarm ID: the seed's manifest hash identifies the
//     artifact; anyone with the token and the tracker address can join
//     later (immutability makes late joins trivially correct)
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ziozzang/botjim/internal/chunking"
)

// DefaultSwarmPort is the tracker's default port.
const DefaultSwarmPort = 4763

// Tracker rooms: one room per (token-hash, manifest-hash). Peers announce
// their listen address and chunk catalog; joiners get the member list.
// Room peers expire if not re-announced.
const (
	announceEvery = 15 * time.Second
	peerTTL       = 60 * time.Second
	maxRoomPeers  = 256
	// maxAnnounceReturn caps how many peers a single announce hands back —
	// a random subset (seeds always included) for load/knowledge spread.
	maxAnnounceReturn = 64
)

// Peer is one swarm member as the tracker sees it.
type Peer struct {
	Addr   string // dialable host:port
	Have   string // hex chunk-bitmap of the member's catalog
	IsSeed bool
	Seen   time.Time
}

// Tracker rooms keyed by roomID = sha256(tokenID + manifestHash).
type Tracker struct {
	mu    sync.Mutex
	rooms map[string]map[string]*Peer // roomID → peerAddr → peer
}

func NewTracker() *Tracker {
	return &Tracker{rooms: map[string]map[string]*Peer{}}
}

// RoomID binds a token to an artifact.
func RoomID(codeID, manifestHash string) string {
	sum := sha256.Sum256([]byte("botjim-swarm-room/" + codeID + "/" + manifestHash))
	return hex.EncodeToString(sum[:])
}

// Announce registers a peer and returns the current member list.
func (t *Tracker) Announce(roomID, addr, have string, seed bool) []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	room, ok := t.rooms[roomID]
	if !ok {
		if len(t.rooms) >= 4096 {
			// sweep dead rooms before refusing: without this, abandoned
			// rooms accumulate until the tracker is full forever
			now := time.Now()
			for id, rm := range t.rooms {
				alive := false
				for _, p := range rm {
					if now.Sub(p.Seen) <= peerTTL {
						alive = true
						break
					}
				}
				if !alive {
					delete(t.rooms, id)
				}
			}
		}
		if len(t.rooms) >= 4096 {
			return nil // tracker genuinely full
		}
		room = map[string]*Peer{}
		t.rooms[roomID] = room
	}
	// expire stale peers. Seeds get a longer leash (their announce loop
	// refreshes every 15s), but a crashed seed must not be handed to
	// every future joiner forever.
	now := time.Now()
	for a, p := range room {
		ttl := peerTTL
		if p.IsSeed {
			ttl = 5 * peerTTL
		}
		if now.Sub(p.Seen) > ttl {
			delete(room, a)
		}
	}
	if p, exists := room[addr]; exists {
		p.Have = have
		p.Seen = now
	} else {
		if len(room) >= maxRoomPeers {
			// drop the stalest non-seed
			var oldest string
			var oldestAt time.Time
			for a, p := range room {
				if !p.IsSeed && (oldest == "" || p.Seen.Before(oldestAt)) {
					oldest, oldestAt = a, p.Seen
				}
			}
			if oldest != "" {
				delete(room, oldest)
			}
		}
		room[addr] = &Peer{Addr: addr, Have: have, IsSeed: seed, Seen: now}
	}
	// return a subset (seeds always included) so a large swarm spreads
	// load and knowledge instead of every joiner learning the same full
	// address-sorted list. Map iteration order is randomized by the
	// runtime, so successive announces hand out different non-seed peers.
	out := make([]Peer, 0, maxAnnounceReturn)
	for _, p := range room {
		if p.Addr != addr && p.IsSeed {
			out = append(out, *p)
		}
	}
	for _, p := range room {
		if len(out) >= maxAnnounceReturn {
			break
		}
		if p.Addr != addr && !p.IsSeed {
			out = append(out, *p)
		}
	}
	return out
}

// Serve runs the tracker until the listener closes. Wire (plaintext —
// peer links are separately e2ee; the tracker only sees addresses and
// bitmaps):
//
//	BOTSWARM1 announce <roomID> <addr> <haveHex> <seed>\n → members …\n END\n
type TrackerProtocol struct{ T *Tracker }

func (tp *TrackerProtocol) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go tp.handle(conn)
	}
}

func (tp *TrackerProtocol) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	line, err := readSwarmLine(conn)
	if err != nil {
		return
	}
	f := strings.Fields(line)
	if len(f) != 7 || f[0] != "BOTSWARM1" || f[1] != "announce" {
		fmt.Fprintf(conn, "ERR protocol\n")
		return
	}
	roomID, addr, haveHex, seedStr := f[2], f[3], f[4], f[6]
	if len(roomID) != 64 || !isHex(roomID) || len(haveHex) > 8192 || len(addr) > 256 {
		fmt.Fprintf(conn, "ERR args\n")
		return
	}
	host, port, aerr := net.SplitHostPort(addr)
	if aerr != nil {
		fmt.Fprintf(conn, "ERR addr\n")
		return
	}
	// wildcard/unspecified announce address: substitute the source IP the
	// tracker actually sees — "[::]:port" is undialable for everyone
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if rh, _, rerr := net.SplitHostPort(conn.RemoteAddr().String()); rerr == nil {
			addr = net.JoinHostPort(rh, port)
		}
	}
	seed := seedStr == "1"
	peers := tp.T.Announce(roomID, addr, haveHex, seed)
	var b strings.Builder
	fmt.Fprintf(&b, "OK %d\n", len(peers))
	for _, p := range peers {
		fmt.Fprintf(&b, "%s %s %d\n", p.Addr, p.Have, boolInt(p.IsSeed))
	}
	b.WriteString("END\n")
	_, _ = conn.Write([]byte(b.String()))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ManifestHash hashes a manifest file (the swarm ID).
func ManifestHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SwarmManifest is the portable descriptor: write it next to the data
// (model.swarm.json) and any peer with the token can join.
type SwarmManifest struct {
	Version     int         `json:"version"`
	Artifact    string      `json:"artifact"`     // display name
	ManifestSHA string      `json:"manifest_sha"` // the swarm ID
	Files       []string    `json:"files"`
	FileEntries []SwarmFile `json:"file_entries"` // sizes+hashes: joiners need no local data
	TotalBytes  int64       `json:"total_bytes"`
	Tracker     string      `json:"tracker,omitempty"`
	PubKey      string      `json:"pubkey,omitempty"` // signer's ed25519 public key (hex)
	Sig         string      `json:"sig,omitempty"`    // ed25519 signature over the unsigned body
}

// WriteSwarmManifest serializes the descriptor to dir/<name>.swarm.json.
func WriteSwarmManifest(dir, name string, m *SwarmManifest) (string, error) {
	p := filepath.Join(dir, name+".swarm.json")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(m); err != nil {
		return "", err
	}
	return p, nil
}

// SwarmManifestFrom builds the descriptor from a spec (with embedded
// per-file entries so joiners know every hash up front).
func SwarmManifestFrom(s *SwarmSpec, tracker string) *SwarmManifest {
	return &SwarmManifest{
		Version: s.Version, Artifact: s.Name, ManifestSHA: s.SpecHash(),
		Files: filePaths(s), FileEntries: s.Files, TotalBytes: s.TotalBytes(),
		Tracker: tracker,
	}
}

func filePaths(s *SwarmSpec) []string {
	out := make([]string, len(s.Files))
	for i, f := range s.Files {
		out[i] = f.Path
	}
	return out
}

// AnnounceOnce is a single tracker announcement (exported for the CLI loop).
func AnnounceOnce(ctx context.Context, tracker, token, specHash, self, have string, seed bool) []Peer {
	return announceTo(ctx, tracker, token, specHash, self, have, seed)
}

// ToSpec rebuilds a fetchable spec from the descriptor by hashing the
// local files under dir (the joiner side: it learns sizes/hashes only by
// fetching; this variant reads any that already exist and carries the
// rest as placeholders the joiner fills). V0.5 keeps descriptors from
// seeds; joiners get the full spec from the descriptor beside the data.
func (m *SwarmManifest) ToSpec(dir string) *SwarmSpec {
	if len(m.Files) == 0 {
		return nil
	}
	// placeholder spec: sizes/hashes come from the seed's descriptor
	// itself when it embeds them (see SwarmSpecFile below)
	return m.specFromEmbedded()
}

// specFromEmbedded reconstructs from embedded per-file entries when the
// descriptor carries them (v2 descriptors), else nil.
func (m *SwarmManifest) specFromEmbedded() *SwarmSpec {
	if len(m.Files) == 0 || m.FileEntries == nil {
		return nil
	}
	spec := &SwarmSpec{Version: m.Version, Name: m.Artifact}
	for _, fe := range m.FileEntries {
		// Chunks must survive the round-trip: SpecHash covers the chunk
		// catalog, so dropping it made every v2 descriptor fail the
		// hash check below ("descriptor carries no files") — and would
		// have disabled per-chunk verification even if it hadn't
		spec.Files = append(spec.Files, SwarmFile{Path: fe.Path, Size: fe.Size, Mode: fe.Mode, SHA: fe.SHA, Chunks: fe.Chunks})
	}
	if spec.SpecHash() != m.ManifestSHA {
		return nil // descriptor and entries disagree: refuse
	}
	return spec
}

// catalogHex encodes a have-bitmap as hex for announce lines.
func catalogHex(bitmap []byte) string { return hex.EncodeToString(bitmap) }

func chunkGridFor(size int64) chunking.Grid {
	return chunking.Grid{Size: size, ChunkSize: chunking.ChunkSizeFor(size)}
}

// SeedCatalog builds the seed's have-catalog: a full (all-ones) per-file
// bitmap sized to each file's real chunk count, '/'-joined — the same
// shape a joiner's catalog() produces, so rarest-first ordering counts
// the seed for every file (a flat "ffff" collapsed to one field and hid
// the seed for all files past the first).
func SeedCatalog(spec *SwarmSpec) string {
	parts := make([]string, 0, len(spec.Files))
	for _, f := range spec.Files {
		grid := chunkGridFor(f.Size)
		n := grid.Count()
		bm := make([]byte, (n+7)/8)
		for i := int64(0); i < n; i++ {
			bm[i/8] |= 1 << (uint(i) % 8)
		}
		parts = append(parts, catalogHex(bm))
	}
	return strings.Join(parts, "/")
}

// catalogDecode parses one back.
func catalogDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// readSwarmLine reads one line without buffering past it.
func readSwarmLine(conn net.Conn) (string, error) {
	br := make([]byte, 1)
	var sb strings.Builder
	for sb.Len() < 8192 {
		if _, err := io.ReadFull(conn, br); err != nil {
			return "", err
		}
		if br[0] == '\n' {
			return strings.TrimSpace(sb.String()), nil
		}
		sb.WriteByte(br[0])
	}
	return "", fmt.Errorf("line too long")
}
