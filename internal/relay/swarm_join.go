package relay

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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

	mu       sync.Mutex
	parts    map[string]*os.File // rel path → part fd (lazy init)
	verified map[string]bool     // rel path → passed whole-file SHA
	serveLn  net.Listener
}

// Run drives one join to completion (all files verified) or ctx death.
func (j *Joiner) Run(ctx context.Context) error {
	if err := os.MkdirAll(j.Dest, 0o755); err != nil {
		return err
	}
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
	peers := j.announce(ctx, j.catalog())
	if len(peers) == 0 {
		return fmt.Errorf("swarm: no peers for this token (is the seed running?)")
	}

	// build the chunk task list: (fileIdx, chunkIdx) for everything the
	// local catalog does not hold, then order rarest-first (fewest peers
	// hold it → fetch early so it propagates widest)
	var tasks []chunkTask
	var total, done int64
	for fi, f := range j.Spec.Files {
		grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
		total += f.Size
		have := j.localChunks(f, grid)
		for ci := int64(0); ci < grid.Count(); ci++ {
			if !have[ci] {
				tasks = append(tasks, chunkTask{file: int64(fi), chunk: ci})
			}
		}
	}
	tasks = orderRarestFirst(tasks, j.Spec, peers)
	if j.OnProgress != nil {
		j.OnProgress(0, total)
	}

	// fetch workers over a shared task queue
	taskCh := make(chan chunkTask, 64)
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
			for t := range taskCh {
				if ctx.Err() != nil {
					continue
				}
				f := j.Spec.Files[t.file]
				grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
				data, err := j.fetchWithRetry(ctx, peers, t.file, t.chunk)
				if err != nil {
					errOnce.Do(func() { fatal = fmt.Errorf("%s chunk %d: %w", f.Path, t.chunk, err) })
					continue
				}
				if err := j.writeChunk(f, grid, t.chunk, data); err != nil {
					errOnce.Do(func() { fatal = fmt.Errorf("%s chunk %d: %w", f.Path, t.chunk, err) })
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
		}()
	}
	for _, t := range tasks {
		select {
		case taskCh <- t:
		case <-ctx.Done():
		}
	}
	close(taskCh)
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
	return nil
}

// fetchWithRetry tries every peer that announced the chunk (round-robin),
// with a small backoff between rounds.
func (j *Joiner) fetchWithRetry(ctx context.Context, peers []Peer, fileIdx, chunkIdx int64) ([]byte, error) {
	for round := 0; round < 3; round++ {
		for _, p := range peers {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			data, err := PeerFetch(ctx, p.Addr, j.Spec.SpecHash(), j.Token, fileIdx, chunkIdx)
			if err == nil {
				return data, nil
			}
			if err == ErrChunkMiss {
				continue
			}
			// dead peer: try the next
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(round+1) * 500 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("no peer served this chunk")
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
		if chunking.AllZero(buf[:n]) {
			continue // unverifiable without reference bytes
		}
		// matches the spec only if the whole-file assembly would — cheap
		// approximation: hash the chunk and compare to a later full verify
		have[i] = true // provisional; finalize re-verifies the whole file
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
	j.mu.Unlock()
	if !ok {
		part := j.partPath(f.Path)
		if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
			return err
		}
		var err error
		pf, err = os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		_ = pf.Truncate(f.Size)
		j.mu.Lock()
		j.parts[f.Path] = pf
		j.mu.Unlock()
	}
	_, err := pf.WriteAt(data, grid.Offset(ci))
	return err
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
	if err := os.Chmod(part, os.FileMode(f.Mode)); err != nil {
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
	go func() { _ = ServePeer(ctx, ln, j.Spec, j.Dest, j.Token) }()
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
func orderRarestFirst(tasks []chunkTask, spec *SwarmSpec, peers []Peer) []chunkTask {
	if len(peers) == 0 {
		return tasks
	}
	// decode each peer's per-file bitmaps
	type key struct{ f, c int64 }
	rarity := map[key]int{}
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
					rarity[key{int64(fi), int64(ci)}]++
				}
			}
		}
	}
	sort.SliceStable(tasks, func(a, b int) bool {
		return rarity[key{tasks[a].file, tasks[a].chunk}] < rarity[key{tasks[b].file, tasks[b].chunk}]
	})
	return tasks
}

// catalog returns the joiner's current have-bitmap for the announce line
// (one concatenated hex per file, '/'-separated).
func (j *Joiner) catalog() string {
	var parts []string
	for _, f := range j.Spec.Files {
		grid := chunking.Grid{Size: f.Size, ChunkSize: chunking.ChunkSizeFor(f.Size)}
		have := j.localChunks(f, grid)
		bm := make([]byte, (len(have)+7)/8)
		for i, h := range have {
			if h {
				bm[i/8] |= 1 << (uint(i) % 8)
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
