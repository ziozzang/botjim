package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ziozzang/botjim/internal/chunking"
)

// chunkTask is one (file, chunk) fetch.
type chunkTask struct{ file, chunk int64 }

// Joiner assembles one artifact from the swarm: it announces to the
// tracker, fetches missing chunks from any peer that holds them (the
// token authenticates the tracker room and keys every peer link),
// writes into part files, and verifies each file against the spec's
// SHA-256 before it counts as done. Progress is resumable: existing
// part content is re-hashed and kept when it matches.
type Joiner struct {
	TrackerAddr string
	Token       string
	Spec        *SwarmSpec
	Dest        string
	Parallel    int
	OnProgress  func(done, total int64)
	// ServeAddr, when set, starts a chunk server on that address so other
	// joiners can fetch from this node (the mesh ramp: bytes enter each
	// LAN once). "" disables serving.
	ServeAddr string

	// HTTPBase, when set, lets the joiner fetch chunks over plain HTTP
	// Range requests (HF-style static hosting) in addition to peers:
	// URL = HTTPBase + file path. No auth on the wire — chunk SHA-256
	// from the v2 catalog is the integrity check.
	HTTPBase string

	// Stay keeps the node serving after the download completes (a seed).
	// Without it the joiner exits when done (one-shot pull).
	Stay bool

	mu       sync.Mutex
	rr       atomic.Int64        // round-robin cursor for peer rotation
	curPeers []Peer              // live member list, refreshed by re-announce
	parts    map[string]*os.File // rel path → part fd (lazy init)
	verified map[string]bool     // rel path → passed whole-file SHA
	avail    map[string][]bool   // rel path → per-chunk verified-and-serveable
	banned   map[string]bool     // peer addr → served a bad chunk
	serveLn  net.Listener
}

// markAvail records that chunk ci of file rel is written and verified, so
// the serve path may hand it to other peers (the mesh ramp).
func (j *Joiner) markAvail(rel string, ci int64, count int64) {
	j.mu.Lock()
	if j.avail == nil {
		j.avail = map[string][]bool{}
	}
	bm := j.avail[rel]
	if int64(len(bm)) != count {
		nb := make([]bool, count)
		copy(nb, bm)
		bm = nb
		j.avail[rel] = bm
	}
	if ci >= 0 && ci < count {
		bm[ci] = true
	}
	j.mu.Unlock()
}

// ReadPiece implements PieceSource: serve a chunk this joiner holds, from
// the finalized file if done, else from the still-open part file. Only
// chunks whose bytes were written AND verified (markAvail) are offered.
func (j *Joiner) ReadPiece(fileIdx, chunkIdx int64, buf []byte) (int, bool) {
	if fileIdx < 0 || fileIdx >= int64(len(j.Spec.Files)) {
		return 0, false
	}
	f := j.Spec.Files[fileIdx]
	grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
	n := grid.Len(chunkIdx)
	j.mu.Lock()
	final := j.verified[f.Path]
	var haveBit bool
	if bm := j.avail[f.Path]; chunkIdx >= 0 && chunkIdx < int64(len(bm)) {
		haveBit = bm[chunkIdx]
	}
	pf := j.parts[f.Path]
	j.mu.Unlock()
	if !final && !haveBit {
		return 0, false
	}
	// finalized file: read from its final path
	if final {
		abs := filepath.Join(j.Dest, f.Path)
		if got, err := readChunkAt(abs, buf[:n], grid.Offset(chunkIdx)); err == nil && int64(got) == n {
			return int(n), true
		}
		return 0, false
	}
	// in-progress: read from the open part fd (ReadAt is positional and
	// safe for concurrent readers on a shared *os.File)
	if pf != nil {
		if got, err := pf.ReadAt(buf[:n], grid.Offset(chunkIdx)); err == nil && int64(got) == n {
			return int(n), true
		}
	}
	// the part may have just been renamed to final (finalize race): retry
	// the final path once — same immutable bytes either way
	abs := filepath.Join(j.Dest, f.Path)
	if got, err := readChunkAt(abs, buf[:n], grid.Offset(chunkIdx)); err == nil && int64(got) == n {
		return int(n), true
	}
	return 0, false
}

func (j *Joiner) setPeers(p []Peer) {
	j.mu.Lock()
	j.curPeers = p
	j.mu.Unlock()
}

func (j *Joiner) peersSnapshot() []Peer {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Peer, len(j.curPeers))
	copy(out, j.curPeers)
	return out
}

// reannounceLoop refreshes the joiner's tracker TTL every announceEvery
// and merges any newly-joined peers into the live set, so a multi-minute
// download neither expires from its room nor stays blind to later peers.
// availCount totals serveable chunks across all files (progress signal).
func (j *Joiner) availCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	for _, bm := range j.avail {
		for _, b := range bm {
			if b {
				n++
			}
		}
	}
	return n
}

// reannounceLoop refreshes the tracker TTL and — crucially for a live mesh
// — re-announces SOON after new pieces land (not just every 15s), so peers
// learn what we can serve while a download is still in progress. It polls
// on a short tick: it announces when our piece count grew (bounded to at
// most once per minReannounce), and unconditionally every announceEvery to
// keep the room TTL fresh and pick up newly-joined peers.
func (j *Joiner) reannounceLoop(ctx context.Context) {
	const minReannounce = 1 * time.Second
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	lastCount := -1
	lastAnnounce := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		cur := j.availCount()
		grew := cur != lastCount
		since := time.Since(lastAnnounce)
		if (grew && since >= minReannounce) || since >= announceEvery {
			peers := j.announce(ctx, j.catalog())
			if len(peers) > 0 {
				j.setPeers(peers)
			}
			lastCount = cur
			lastAnnounce = time.Now()
		}
	}
}

// banPeer removes a peer that served bytes failing the chunk hash from
// all further fetches this session. One proven lie is enough: the record
// layer already excludes wire corruption, so a mismatch means the peer
// is wrong or malicious for this swarm.
func (j *Joiner) banPeer(addr string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.banned == nil {
		j.banned = map[string]bool{}
	}
	j.banned[addr] = true
}

func (j *Joiner) isBanned(addr string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.banned[addr]
}

// chunkOK verifies fetched bytes against the v2 chunk catalog. No
// catalog at all (v1 spec) defers to finalize-time verification; a
// catalog that does not cover this chunk is corrupt and fails closed.
func chunkOK(f SwarmFile, ci int64, data []byte) bool {
	if len(f.Chunks) == 0 {
		return true // v1: no catalog, finalize verifies the whole file
	}
	if ci < 0 || ci >= int64(len(f.Chunks)) {
		return false // catalog does not cover the grid — corrupt spec
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == f.Chunks[ci]
}

// Run drives one join to completion (all files verified) or ctx death.
func (j *Joiner) Run(ctx context.Context) error {
	if err := os.MkdirAll(j.Dest, 0o755); err != nil {
		return err
	}
	// exclusive lock on the dest: two swarm joins into the same directory
	// would corrupt each other's part files (and, with serving, hand out
	// half-written chunks). Refuse the second.
	lf, err := os.OpenFile(filepath.Join(j.Dest, ".botjim-swarm.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lf.Close()
		return fmt.Errorf("another swarm join is already writing to %s", j.Dest)
	}
	defer lf.Close() // lock held for the whole run (incl. --seed serving)
	if j.parts == nil {
		j.parts = map[string]*os.File{}
	}
	if j.verified == nil {
		j.verified = map[string]bool{}
	}
	// mesh: serve verified chunks to other joiners while we download
	if j.ServeAddr != "" {
		if err := j.startServing(ctx); err != nil {
			return err
		}
	}
	// build the chunk task list FIRST (scan local/resumed parts), seeding
	// the availability map, so the initial announce already advertises any
	// pieces we can serve
	var tasks []chunkTask
	var total, done int64
	for fi, f := range j.Spec.Files {
		grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
		total += f.Size
		have := j.localChunks(f, grid)
		for ci := int64(0); ci < grid.Count(); ci++ {
			if !have[ci] {
				tasks = append(tasks, chunkTask{file: int64(fi), chunk: ci})
			} else {
				j.markAvail(f.Path, ci, grid.Count()) // resumed piece: serveable
			}
		}
	}

	// initial announce: a cold-start race (joiner announces before the
	// seed's first announce lands) must not be fatal — retry a few cycles
	var peers []Peer
	for attempt := 0; attempt < 6; attempt++ {
		peers = j.announce(ctx, j.catalog())
		if len(peers) > 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if len(peers) == 0 {
		return fmt.Errorf("swarm: no peers for this token (is the seed running?)")
	}
	j.setPeers(peers)
	// keep refreshing our TTL in the room AND discover peers that joined
	// after us — without this the tracker expires us after peerTTL and our
	// captured peer list never grows
	go j.reannounceLoop(ctx)

	if j.OnProgress != nil {
		j.OnProgress(0, total)
	}

	// live piece-picker: rarest-first re-prioritized from the current peer
	// set, endgame duplication of the tail, per-chunk retry
	pk := newPicker(tasks)
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var errOnce sync.Once
	var fatal error
	workers := j.Parallel
	if workers < 1 {
		workers = 4
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if fctx.Err() != nil {
					return
				}
				peers := j.peersSnapshot()
				t, ok, _ := pk.pick(chunkRarity(j.Spec, peers))
				if !ok {
					if pk.allDone() {
						return
					}
					// nothing to pick right now (waiting on retries / all
					// in flight) — brief pause, then re-poll
					select {
					case <-fctx.Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
					continue
				}
				f := j.Spec.Files[t.file]
				grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
				data, err := j.fetchWithRetry(fctx, peers, f, t.file, t.chunk)
				if err != nil {
					if pk.fail(t) {
						errOnce.Do(func() {
							fatal = fmt.Errorf("%s chunk %d: %w", f.Path, t.chunk, err)
							cancel()
						})
					}
					continue
				}
				// first worker to complete this piece writes it; a losing
				// endgame duplicate discards its bytes
				if pk.complete(t) {
					if err := j.writeChunk(f, grid, t.chunk, data); err != nil {
						errOnce.Do(func() {
							fatal = fmt.Errorf("%s chunk %d: %w", f.Path, t.chunk, err)
							cancel()
						})
						continue
					}
					j.mu.Lock()
					done += grid.Len(t.chunk)
					d := done
					j.mu.Unlock()
					if j.OnProgress != nil {
						j.OnProgress(d, total)
					}
				}
			}
		}()
	}
	wg.Wait()
	if fatal != nil {
		return fatal
	}

	// finalize: truncate to size, verify whole-file hash, rename
	for _, f := range j.Spec.Files {
		if err := j.finalize(f); err != nil {
			return err
		}
	}
	// seed mode: stay up and keep serving the finished artifact to the
	// swarm until cancelled (torrent-style seeding). reannounceLoop keeps
	// our now-complete catalog fresh at the tracker.
	if j.Stay && j.ServeAddr != "" {
		if j.OnProgress != nil {
			j.OnProgress(total, total)
		}
		<-ctx.Done()
	}
	return nil
}

// fetchWithRetry tries every peer that announced the chunk (round-robin)
// and, when configured, the HTTP source, with a small backoff between
// rounds. Fetched bytes are verified against the chunk catalog before
// they count; a peer that fails it is banned for the session.
func (j *Joiner) fetchWithRetry(ctx context.Context, peers []Peer, f SwarmFile, fileIdx, chunkIdx int64) ([]byte, error) {
	grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
	var lastErr error
	// rotate the starting peer per call: load spreads across the mesh
	// instead of hammering whichever address sorts first, and every peer
	// gets exercised (a lying peer is caught within a few chunks)
	start := int(j.rr.Add(1))
	for round := 0; round < 3; round++ {
		for k := 0; k < len(peers); k++ {
			p := peers[(start+k)%len(peers)]
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if j.isBanned(p.Addr) {
				continue
			}
			data, err := PeerFetch(ctx, p.Addr, j.Spec.SpecHash(), j.Token, fileIdx, chunkIdx)
			if err != nil {
				lastErr = err
				if err == ErrChunkMiss {
					continue
				}
				continue // dead peer: try the next
			}
			if !chunkOK(f, chunkIdx, data) {
				j.banPeer(p.Addr)
				lastErr = fmt.Errorf("peer %s served a chunk failing its hash", p.Addr)
				continue
			}
			return data, nil
		}
		if j.HTTPBase != "" {
			data, err := httpFetchChunk(ctx, j.HTTPBase, f, grid, chunkIdx)
			if err == nil {
				if chunkOK(f, chunkIdx, data) {
					return data, nil
				}
				lastErr = fmt.Errorf("HTTP source served a chunk failing its hash")
			} else {
				lastErr = err
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(round+1) * 500 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no source served this chunk")
	}
	return nil, lastErr
}

// httpFetchChunk maps one chunk to an HTTP Range request against
// HTTPBase + file path (any static host works: nginx, S3, HF resolve).
func httpFetchChunk(ctx context.Context, base string, f SwarmFile, grid chunking.Grid, ci int64) ([]byte, error) {
	url := strings.TrimSuffix(base, "/") + "/" + f.Path
	off, n := grid.Offset(ci), grid.Len(ci)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+n-1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %s for %s", resp.Status, url)
	}
	// a 200 (not 206) means the host may have ignored Range and be sending
	// the WHOLE file. Only a 206, or a 200 whose Content-Length exactly
	// equals the chunk, is trustworthy — a chunked/unknown-length 200
	// (ContentLength < 0) would otherwise feed the file's first n bytes as
	// every chunk, silently corrupting v1 specs that verify only at finalize
	if resp.StatusCode == http.StatusOK {
		if resp.ContentLength < 0 || resp.ContentLength != n {
			return nil, fmt.Errorf("http: host ignored Range (200, length %d; expected a 206 chunk of %d)", resp.ContentLength, n)
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, n))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != n {
		return nil, fmt.Errorf("http: short read %d/%d", len(data), n)
	}
	return data, nil
}

// localChunks re-hashes existing part content for one file and returns
// which chunks verifiably match the spec (only chunks that hash to the
// same value over spec-known bytes can match — for zero chunks we
// re-request, same rule as the transfer engine's rebuild path).
func (j *Joiner) localChunks(f SwarmFile, grid chunking.Grid) []bool {
	have := make([]bool, grid.Count())
	// fast path: a verified final file needs nothing (and is serveable)
	if fi, err := os.Stat(filepath.Join(j.Dest, f.Path)); err == nil && fi.Size() == f.Size {
		sum, err := hashFile(filepath.Join(j.Dest, f.Path))
		if err == nil && sum == f.SHA {
			for i := range have {
				have[i] = true
			}
			j.mu.Lock()
			j.verified[f.Path] = true
			j.mu.Unlock()
			return have
		}
	}
	// part path: joiners use a single fixed part name (no cross-session
	// adoption races here — the swarm token scopes the room)
	part := j.partPath(f.Path)
	pf, err := os.Open(part)
	if err != nil {
		return have
	}
	defer pf.Close()
	buf := make([]byte, grid.ChunkSize)
	for i := int64(0); i < grid.Count(); i++ {
		n := grid.Len(i)
		if int64(cap(buf)) < n {
			buf = make([]byte, n)
		}
		got, err := pf.ReadAt(buf[:n], grid.Offset(i))
		if err != nil || int64(got) != n {
			continue
		}
		if len(f.Chunks) == 0 {
			// v1 spec: no catalog — non-zero bytes count provisionally,
			// finalize re-verifies the whole file
			if !chunking.AllZero(buf[:n]) {
				have[i] = true
			}
			continue
		}
		// v2: the catalog pins every chunk, zero chunks included
		if chunkOK(f, i, buf[:n]) {
			have[i] = true
		}
	}
	return have
}

func (j *Joiner) partPath(rel string) string {
	return filepath.Join(j.Dest, rel+".fs-part")
}

func (j *Joiner) writeChunk(f SwarmFile, grid chunking.Grid, ci int64, data []byte) error {
	if int64(len(data)) != grid.Len(ci) {
		return fmt.Errorf("size mismatch: got %d want %d", len(data), grid.Len(ci))
	}
	j.mu.Lock()
	pf, ok := j.parts[f.Path]
	if !ok {
		// open under the lock: two workers racing here would both open
		// the part and leak one fd
		part := j.partPath(f.Path)
		if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
			j.mu.Unlock()
			return err
		}
		var err error
		pf, err = os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			j.mu.Unlock()
			return err
		}
		_ = pf.Truncate(f.Size)
		j.parts[f.Path] = pf
	}
	j.mu.Unlock()
	if _, err := pf.WriteAt(data, grid.Offset(ci)); err != nil {
		return err
	}
	// the chunk was verified before writeChunk (fetchWithRetry → chunkOK)
	// and is now on disk: advertise it so peers can fetch it from us
	j.markAvail(f.Path, ci, grid.Count())
	return nil
}

// finalize closes the part, verifies the whole-file hash against the
// spec, applies the mode and renames into place.
func (j *Joiner) finalize(f SwarmFile) error {
	part := j.partPath(f.Path)
	j.mu.Lock()
	pf, ok := j.parts[f.Path]
	j.mu.Unlock()
	if !ok {
		// fully present already (skip path) — verify in place
		pf = nil
	}
	if pf != nil {
		_ = pf.Sync()
		_ = pf.Close()
		j.mu.Lock()
		delete(j.parts, f.Path)
		j.mu.Unlock()
	}
	sum, err := hashFile(part)
	if err != nil {
		return err
	}
	if sum != f.SHA {
		// wrong content: restart this file's part so the next run refetches
		_ = os.Remove(part)
		return fmt.Errorf("%s: hash mismatch (got %s…)", f.Path, sum[:12])
	}
	abs := filepath.Join(j.Dest, f.Path)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(part, os.FileMode(f.Mode)&0o777); err != nil {
		return err
	}
	if err := os.Rename(part, abs); err != nil {
		return err
	}
	j.mu.Lock()
	j.verified[f.Path] = true
	j.mu.Unlock()
	return nil
}

// startServing exposes verified chunks to the swarm on ServeAddr.
func (j *Joiner) startServing(ctx context.Context) error {
	host, port, err := net.SplitHostPort(j.ServeAddr)
	if err != nil || port == "" {
		host, port = j.ServeAddr, "0"
	}
	bind := net.JoinHostPort(host, port)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	j.mu.Lock()
	j.serveLn = ln
	j.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() { _ = ServePeer(ctx, ln, j.Spec, j, j.Token) }()
	return nil
}

// ServeListenAddr returns the bound serving address ("" when not serving).
func (j *Joiner) ServeListenAddr() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.serveLn == nil {
		return ""
	}
	return j.serveLn.Addr().String()
}

// orderRarestFirst sorts tasks ascending by how many peers hold each
// chunk (from announce bitmaps): the scarcest chunks move first so they
// propagate widest; common chunks mop up at the end.
type rarityKey struct{ f, c int64 }

// chunkRarity counts, per (file,chunk), how many peers advertise it — the
// piece-picker fetches the scarcest first so rare pieces propagate widest.
func chunkRarity(spec *SwarmSpec, peers []Peer) map[rarityKey]int {
	rarity := map[rarityKey]int{}
	for _, p := range peers {
		perFile := strings.Split(p.Have, "/")
		for fi := range spec.Files {
			if fi >= len(perFile) {
				continue
			}
			bm, err := catalogDecode(perFile[fi])
			if err != nil {
				continue
			}
			for ci := 0; ci < len(bm)*8; ci++ {
				if bm[ci/8]&(1<<(uint(ci)%8)) != 0 {
					rarity[rarityKey{int64(fi), int64(ci)}]++
				}
			}
		}
	}
	return rarity
}

func orderRarestFirst(tasks []chunkTask, spec *SwarmSpec, peers []Peer) []chunkTask {
	if len(peers) == 0 {
		return tasks
	}
	rarity := chunkRarity(spec, peers)
	sort.SliceStable(tasks, func(a, b int) bool {
		return rarity[rarityKey{tasks[a].file, tasks[a].chunk}] < rarity[rarityKey{tasks[b].file, tasks[b].chunk}]
	})
	return tasks
}

// catalog returns the joiner's current have-bitmap for the announce line
// (one concatenated hex per file, '/'-separated).
func (j *Joiner) catalog() string {
	var parts []string
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, f := range j.Spec.Files {
		grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
		count := grid.Count()
		bm := make([]byte, (count+7)/8)
		// serialize the in-memory availability map (populated by writeChunk
		// and the startup resume scan) instead of re-hashing the whole part
		// file from disk every 15s — for a 100GB artifact that re-read was
		// crippling. A finalized file counts as fully available.
		if j.verified[f.Path] {
			for i := int64(0); i < count; i++ {
				bm[i/8] |= 1 << (uint(i) % 8)
			}
		} else if avail := j.avail[f.Path]; avail != nil {
			for i := int64(0); i < count && i < int64(len(avail)); i++ {
				if avail[i] {
					bm[i/8] |= 1 << (uint(i) % 8)
				}
			}
		}
		parts = append(parts, catalogHex(bm))
	}
	return strings.Join(parts, "/")
}

// announce registers with the tracker and returns the member list.
func (j *Joiner) announce(ctx context.Context, have string) []Peer {
	return announceTo(ctx, j.TrackerAddr, j.Token, j.Spec.SpecHash(), j.ServeListenAddr(), have, false)
}

// listen is the peer's serving address (joiners serve too — swarm rule).
// v0.5: joiners announce a placeholder; serving-side listen lands with
// the serve loop below.
func (j *Joiner) listen() string { return j.ServeListenAddr() }

// announceTo is the tracker client shared by seed and joiner.
func announceTo(ctx context.Context, trackerAddr, token, specHash, selfAddr, have string, seed bool) []Peer {
	host, port, err := net.SplitHostPort(trackerAddr)
	if err != nil {
		host, port = trackerAddr, fmt.Sprint(DefaultSwarmPort)
	}
	room := RoomID(codeID(token), specHash)
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if len(have) > 8192 {
		have = have[:8192]
	}
	seedCh := "0"
	if seed {
		seedCh = "1"
	}
	if selfAddr == "" {
		selfAddr = "0.0.0.0:0"
	}
	fmt.Fprintf(conn, "BOTSWARM1 announce %s %s %s x %s\n", room, selfAddr, have, seedCh)
	var peers []Peer
	br := readLineReader(conn)
	head, err := br()
	if err != nil || head != "OK" && !strings.HasPrefix(head, "OK ") {
		return nil
	}
	for {
		line, err := br()
		if err != nil || line == "END" {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		peers = append(peers, Peer{Addr: f[0], Have: f[1], IsSeed: f[2] == "1"})
	}
	return peers
}

// readLineReader returns a closure reading one line at a time.
func readLineReader(conn net.Conn) func() (string, error) {
	return func() (string, error) { return readSwarmLine(conn) }
}
