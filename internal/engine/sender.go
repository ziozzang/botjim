package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ziozzang/botjim/internal/chunking"
	"github.com/ziozzang/botjim/internal/compress"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/manifest"
	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/transport"
)

// senderPendingCredit bounds how many manifest files may be in flight
// without have-information: the walker's memory ceiling on million-file
// trees.
const senderPendingCredit = 2048

// Sender streams a manifest and its chunk data over the session's streams.
type Sender struct {
	sess  *transport.Session
	ctrl  *protocol.CtrlStream
	opts  Options
	reg   *progress.Registry
	roots []string

	mu          sync.Mutex
	files       map[uint32]*txFile
	emittedIDs  map[uint32]bool // every entry ID the walker assigned
	resolvedIDs map[uint32]bool
	emitted     uint64 // entries handed to the walker emit (all kinds)
	resolved    uint64 // entries with a terminal outcome (echoed or local)
	gatesOpen   int
	gateCond    *sync.Cond

	manifestBytes uint64
	dirs          uint64
	hasHardlinks  bool

	taskCh  chan chunkTask
	kick    chan struct{}
	limiter *limiter
	dryRun  bool
	plan    []PlanRow
	readyQ  []uint32 // gate-opened files awaiting task enqueue
	report  Report
	batchMu sync.Mutex
	batch   []manifest.Entry
	batchSz int

	remoteErr atomic.Pointer[error]
	ctrlDone  chan struct{}
}

type chunkTask struct {
	fileID uint32
	idx    int64
}

type txFile struct {
	entry    manifest.Entry
	have     []byte // nil + !allSkip until HaveBitmap lands
	allSkip  bool
	fd       *os.File
	fdErr    error
	fdOnce   sync.Once
	nextTask int64
	count    int64
	inflight int // queued+processing chunk tasks (fd lifetime guard)
	retries  map[int64]int
	errored  bool
	resolved bool
}

// PlanRow is one file's dry-run verdict.
type PlanRow struct {
	Path   string
	Size   int64
	Chunks int64
	Have   int64 // chunks already at the destination
	Status string
}

// NewSender builds a sender core.
func NewSender(sess *transport.Session, ctrl *protocol.CtrlStream, opts Options, reg *progress.Registry, roots []string) *Sender {
	s := &Sender{
		sess: sess, ctrl: ctrl, opts: opts, reg: reg, roots: roots,
		files:       map[uint32]*txFile{},
		emittedIDs:  map[uint32]bool{},
		resolvedIDs: map[uint32]bool{},
		taskCh:      make(chan chunkTask, opts.Parallel*2),
		kick:        make(chan struct{}, 1),
		ctrlDone:    make(chan struct{}),
	}
	s.gateCond = sync.NewCond(&s.mu)
	if opts.LimitBPS > 0 {
		s.limiter = newLimiter(opts.LimitBPS)
	}
	if p := opts.Preserve; p&protocol.PreserveDryRun != 0 {
		s.dryRun = true
	}
	return s
}

// Plan returns the dry-run rows (only after Run completes with --dry-run).
func (s *Sender) Plan() []PlanRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PlanRow, len(s.plan))
	copy(out, s.plan)
	return out
}

// Run drives the sender until the transfer completes, is cancelled, or dies.
func (s *Sender) Run(ctx context.Context) (Report, error) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.readCtrl(wctx, cancel)
	go s.runScheduler(wctx)
	// If the context dies while the walker is parked on the credit cond,
	// zero the gate count and broadcast so it can escape.
	go func() {
		<-wctx.Done()
		s.mu.Lock()
		s.gatesOpen = 0
		s.gateCond.Broadcast()
		s.mu.Unlock()
	}()

	var wg sync.WaitGroup
	workerErrs := make(chan error, s.opts.Parallel)
	for i := 0; i < s.opts.Parallel; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := s.runWorker(wctx, uint64(idx)); err != nil && !isCtxErr(err) {
				select {
				case workerErrs <- err:
				default:
				}
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(workerErrs)
	}()

	s.reg.SetScanning(true)
	walker := &manifest.Walker{Opts: s.walkOpts(), Home: s.opts.RelHome}
	walker.OnSkip = func(sk manifest.Skipped) {
		s.reg.Emit("warn", sk.Path, sk.Why)
		s.report.Warnings = append(s.report.Warnings, fmt.Sprintf("skip %s: %s", sk.Path, sk.Why))
	}
	walkErr := s.walk(wctx, walker)
	s.flushBatch()
	if walkErr != nil && !isCtxErr(walkErr) {
		s.setFatal(fmt.Errorf("walk: %w", walkErr))
		s.sendError(protocol.ScopeTransfer, CodeProtocol, walkErr.Error())
		cancel()
	}
	s.mu.Lock()
	files, bytes, dirs, hl := s.emitted, s.manifestBytes, s.dirs, s.hasHardlinks
	s.mu.Unlock()
	if err := s.ctrl.Send(protocol.MsgManifestEnd, 0,
		protocol.ManifestEnd{Files: files, Bytes: bytes, Dirs: dirs, HasHardlinks: hl}.Encode()); err != nil && !isCtxErr(err) {
		s.setFatal(err)
	}
	s.reg.SetScanning(false)

	// Wait for every entry to resolve (receiver echoes a FileResult for each;
	// locally-failed files resolve in place), then release the workers. A
	// stalled peer is cut loose after the idle timeout.
	const idleTimeout = 120 * time.Second
	lastResolved := ^uint64(0)
	lastSent := uint64(0)
	lastMove := time.Now()
	for {
		s.mu.Lock()
		done := s.resolved >= files
		cancelled := s.report.Cancelled
		resolved := s.resolved
		s.mu.Unlock()
		sent := s.reg.Snapshot().SentBytes
		if resolved != lastResolved || sent != lastSent {
			lastResolved, lastSent = resolved, sent
			lastMove = time.Now()
		}
		if done || cancelled {
			break
		}
		if time.Since(lastMove) > idleTimeout {
			s.setFatal(fmt.Errorf("stalled: no progress for %s", idleTimeout))
			break
		}
		select {
		case <-wctx.Done():
		case <-s.ctrlDone:
		case <-time.After(50 * time.Millisecond):
			continue
		}
		break
	}
	cancel() // stop scheduler/workers/retry senders
	wg.Wait()
	for err := range workerErrs {
		if err != nil && !isCtxErr(err) {
			s.report.Warnings = append(s.report.Warnings, "worker: "+err.Error())
		}
	}

	s.mu.Lock()
	s.report.Bytes = s.reg.SentBytes()
	cancelled := s.report.Cancelled
	completed := s.resolved >= files && files > 0
	s.mu.Unlock()
	if perr := s.remoteErr.Load(); perr != nil {
		return s.report, *perr
	}
	if walkErr != nil && !isCtxErr(walkErr) {
		return s.report, walkErr
	}
	if wctx.Err() != nil && !cancelled && !completed {
		s.mu.Lock()
		s.report.Cancelled = true
		s.mu.Unlock()
	}
	return s.report, nil
}

func (s *Sender) walkOpts() manifest.WalkOpts {
	p := s.opts.Preserve
	return manifest.WalkOpts{
		Xattrs:     p&protocol.PreserveXattr != 0,
		Hardlinks:  p&protocol.PreserveHardlink != 0,
		Devices:    p&protocol.PreserveDevices != 0,
		UnameGname: p&protocol.PreserveUname != 0,
		Exclude:    s.opts.Exclude,
		Include:    s.opts.Include,
	}
}

// walk emits the manifest in batches, honoring the pending-credit ceiling.
func (s *Sender) walk(ctx context.Context, walker *manifest.Walker) error {
	return walker.Walk(ctx, s.roots, func(e manifest.Entry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.Lock()
		s.emitted++
		s.emittedIDs[e.ID] = true
		if e.Kind == manifest.KindDir {
			s.dirs++
		}
		if e.Kind == manifest.KindHardlink {
			s.hasHardlinks = true
		}
		if e.Kind == manifest.KindRegular {
			s.manifestBytes += uint64(e.Size)
			s.files[e.ID] = &txFile{entry: e, count: e.Grid().Count(), retries: map[int64]int{}}
			s.mu.Unlock()
			s.reg.AddFile(e.ID, e.RelPath, e.Size)
			s.mu.Lock()
		} else {
			s.mu.Unlock()
			s.reg.AddFile(e.ID, e.RelPath, 0)
			s.mu.Lock()
		}
		// credit is consumed by data-carrying files only: every regular
		// file gets exactly one HaveBitmap back, while dirs/symlinks/nodes
		// resolve via FileResult and would otherwise leak a slot forever
		if e.Kind == manifest.KindRegular {
			for s.gatesOpen >= senderPendingCredit {
				if ctx.Err() != nil {
					s.mu.Unlock()
					return ctx.Err()
				}
				s.gateCond.Wait()
			}
			s.gatesOpen++
		}
		s.mu.Unlock()
		s.appendBatch(e)
		return nil
	})
}

// appendBatch buffers one entry; full-or-large batches flush (zstd above
// the threshold).
func (s *Sender) appendBatch(e manifest.Entry) {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	enc := protocol.EncodeEntry(&e)
	if len(s.batch) >= 256 || s.batchSz+len(enc) > 1<<20 {
		s.flushBatchLocked()
	}
	s.batch = append(s.batch, e)
	s.batchSz += len(enc)
}

func (s *Sender) flushBatch() {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	s.flushBatchLocked()
}

func (s *Sender) flushBatchLocked() {
	if len(s.batch) == 0 {
		return
	}
	payload := protocol.ManifestBatch{Entries: s.batch}.Encode()
	flags := uint8(0)
	if z, ok := zstdCompressFrame(payload); ok {
		payload, flags = z, protocol.CtrlFlagZstd
	}
	if err := s.ctrl.Send(protocol.MsgManifestBatch, flags, payload); err != nil {
		return // connection failure surfaces through readCtrl
	}
	s.batch = nil
	s.batchSz = 0
}

// readCtrl processes control traffic from the receiver until the stream or
// context dies.
func (s *Sender) readCtrl(ctx context.Context, cancel context.CancelFunc) {
	defer close(s.ctrlDone)
	buf := make([]byte, 0, 64<<10)
	for {
		f, err := s.ctrl.Recv(buf)
		if err != nil {
			s.mu.Lock()
			complete := s.emitted > 0 && s.resolved >= s.emitted
			s.mu.Unlock()
			if ctx.Err() == nil && !complete {
				s.setFatal(fmt.Errorf("control stream: %w", err))
			}
			cancel()
			return
		}
		payload := f.Payload
		if f.Flags&protocol.CtrlFlagZstd != 0 {
			p, err := zstdDecompressFrame(payload, ctrlMaxFrame)
			if err != nil {
				s.setFatal(fmt.Errorf("batch decompress: %w", err))
				cancel()
				return
			}
			payload = p
		}
		switch f.Type {
		case protocol.MsgHaveBitmap:
			m, err := protocol.DecodeHaveBitmap(payload)
			if err != nil {
				s.setFatal(err)
				cancel()
				return
			}
			s.gateOpen(m)
		case protocol.MsgFileResult:
			m, err := protocol.DecodeFileResult(payload)
			if err != nil {
				s.setFatal(err)
				cancel()
				return
			}
			s.fileResult(m)
		case protocol.MsgChunkRetry:
			m, err := protocol.DecodeChunkRetry(payload)
			if err != nil {
				s.setFatal(err)
				cancel()
				return
			}
			s.retryChunk(m)
		case protocol.MsgError:
			m, err := protocol.DecodeErrMsg(payload)
			if err == nil && m.Scope == protocol.ScopeSession {
				s.setFatal(fmt.Errorf("remote: %s", m.Msg))
				cancel()
				return
			}
		case protocol.MsgCancel, protocol.MsgAbort:
			s.mu.Lock()
			s.report.Cancelled = true
			s.mu.Unlock()
			cancel()
			return
		case protocol.MsgDone, protocol.MsgGoodbye:
			cancel()
			return
		default:
			// unknown types from newer minors are tolerated
		}
	}
}

// gateOpen records a receiver have-bitmap and releases one credit.
func (s *Sender) gateOpen(m protocol.HaveBitmap) {
	s.mu.Lock()
	f, ok := s.files[m.FileID]
	if !ok {
		s.mu.Unlock()
		return
	}
	waiting := f.have == nil && !f.allSkip
	haveCount := int64(0)
	switch m.Status {
	case protocol.HaveAllSkip:
		f.allSkip = true
		s.report.SkippedBytes += uint64(f.entry.Size)
		s.reg.AddSkipped(f.entry.Size)
	case protocol.HavePartial:
		// the decoded payload aliases the control reader's reusable buffer:
		// copy the bitmap before the next frame overwrites it
		f.have = append([]byte(nil), m.Bitmap...)
		for _, b := range f.have {
			haveCount += int64(popcount8(b))
		}
		if len(m.Hashes) > 0 {
			// untrusted claim (delta adoption): verify each claimed chunk
			// against our own bytes, clear the mismatches
			cleared := s.verifyClaims(f, m.Hashes)
			haveCount -= cleared
			if cleared == 0 {
				// every claim verified: nothing will arrive, tell the
				// receiver to finalize the adopted file
				_ = s.ctrl.Send(protocol.MsgCommit, 0, protocol.Commit{FileID: m.FileID}.Encode())
			}
		}
	case protocol.HaveNone:
		f.have = []byte{}
	}
	if waiting {
		s.gatesOpen--
		s.gateCond.Signal()
	}
	if s.dryRun {
		row := PlanRow{Path: f.entry.RelPath, Size: f.entry.Size, Chunks: f.count, Have: haveCount, Status: "send"}
		if f.allSkip {
			row.Status = "skip"
			row.Have = f.count
		}
		s.plan = append(s.plan, row)
		// resolve immediately (under the lock): no data will flow
		if !f.errored && !f.resolved {
			f.resolved = true
			s.resolved++
			s.report.Files++
		}
		s.mu.Unlock()
		s.reg.FileStateUpdate(f.entry.ID, "done", "")
		return
	}
	if !f.errored && !f.resolved && !f.allSkip {
		s.readyQ = append(s.readyQ, m.FileID)
	}
	s.mu.Unlock()
	s.kickScheduler()
}

// verifyClaims re-hashes the sender's own claimed chunks and clears
// have-bits whose hash differs from the receiver's claim. Returns the
// number of cleared bits (claimed chunks that will be re-sent).
func (s *Sender) verifyClaims(f *txFile, hashes [][32]byte) int64 {
	grid := f.entry.Grid()
	e := f.entry
	fd, err := fsutil.OpenNoAtime(e.AbsPath)
	if err != nil {
		return 0 // cannot verify: trust nothing, clear all
	}
	defer fd.Close()
	buf := make([]byte, grid.ChunkSize)
	cleared := int64(0)
	claimed := 0
	for i := int64(0); i < grid.Count() && claimed < len(hashes); i++ {
		if !bitTest(f.have, i) {
			continue
		}
		h := hashes[claimed]
		claimed++
		n := grid.Len(i)
		if int64(cap(buf)) < n {
			buf = make([]byte, n)
		}
		chunk := buf[:n]
		got, err := fd.ReadAt(chunk, grid.Offset(i))
		if err != nil && !errors.Is(err, io.EOF) || int64(got) != n {
			clearBit(f.have, i)
			cleared++
			continue
		}
		if chunking.ChunkSHA(e.RelPath, i, chunk) != h {
			clearBit(f.have, i)
			cleared++
		}
	}
	// any claims beyond our count are protocol junk: clear remaining bits
	for i := int64(0); i < grid.Count() && claimed < len(hashes); i++ {
		if bitTest(f.have, i) {
			clearBit(f.have, i)
			cleared++
			claimed++
		}
	}
	return cleared
}

func clearBit(bitmap []byte, i int64) {
	if i/8 < int64(len(bitmap)) {
		bitmap[i/8] &^= 1 << (uint(i) % 8)
	}
}

func popcount8(b byte) int {
	n := 0
	for b != 0 {
		b &= b - 1
		n++
	}
	return n
}

// fileResult resolves an entry by receiver echo.
func (s *Sender) fileResult(m protocol.FileResult) {
	s.mu.Lock()
	// unknown or already-resolved IDs are dropped: counting them would let
	// a hostile receiver inflate the report and hold the stall timer open
	if !s.emittedIDs[m.FileID] || s.resolvedIDs[m.FileID] {
		s.mu.Unlock()
		return
	}
	f := s.files[m.FileID]
	if f != nil {
		// release walker credit when the outcome arrived before the bitmap
		if f.have == nil && !f.allSkip {
			s.gatesOpen--
			if s.gatesOpen < 0 {
				s.gatesOpen = 0
			}
			s.gateCond.Signal()
		}
		if m.Status == protocol.ResultError && !f.errored {
			f.errored = true
			s.report.Errors = append(s.report.Errors, FileError{Path: f.entry.RelPath, Code: m.Code, Msg: m.Msg})
			s.reg.FileStateUpdate(f.entry.ID, "error", m.Msg)
			s.reg.Emit("file-error", f.entry.RelPath, m.Msg)
		} else if !f.resolved {
			s.report.Files++
			if m.Status == protocol.ResultSkip {
				s.reg.FileStateUpdate(f.entry.ID, "skipped", "")
				s.reg.Emit("file-skip", f.entry.RelPath, "already at destination")
			} else {
				s.reg.FileStateUpdate(f.entry.ID, "done", "")
				s.reg.Emit("file-done", f.entry.RelPath, "")
			}
		}
	} else {
		// non-data entries (dirs, symlinks, nodes) have no useful log line
		if m.Status != protocol.ResultError {
			s.report.Files++
		}
		s.reg.FileStateUpdate(m.FileID, "done", "")
	}
	if f != nil {
		f.resolved = true
	}
	s.resolvedIDs[m.FileID] = true
	s.resolved++
	s.mu.Unlock()
	s.maybeCloseFD(f)
}

// maybeCloseFD closes a resolved file's fd once no task references it.
func (s *Sender) maybeCloseFD(f *txFile) {
	if f == nil {
		return
	}
	s.mu.Lock()
	if f.fd != nil && f.resolved && f.inflight == 0 {
		fd := f.fd
		f.fd = nil
		s.mu.Unlock()
		_ = fd.Close()
		return
	}
	s.mu.Unlock()
}

func (s *Sender) retryChunk(m protocol.ChunkRetry) {
	idx := int64(m.ChunkIdx)
	s.mu.Lock()
	f, ok := s.files[m.FileID]
	if !ok || f.errored || f.resolved {
		s.mu.Unlock()
		return
	}
	f.retries[idx]++
	over := f.retries[idx] > 3
	if !over {
		f.inflight++
	}
	s.mu.Unlock()
	if over {
		s.failFile(f, CodeIO, fmt.Sprintf("chunk %d: retries exhausted", idx))
		return
	}
	go func() {
		select {
		case s.taskCh <- chunkTask{fileID: m.FileID, idx: idx}:
		case <-s.ctrlDone:
		}
	}()
}

// failFile is a sender-local terminal failure; the receiver is told and the
// entry resolves in place (no echo is expected).
func (s *Sender) failFile(f *txFile, code uint16, msg string) {
	s.mu.Lock()
	if f.errored || f.resolved {
		s.mu.Unlock()
		return
	}
	f.errored = true
	if f.resolved || s.resolvedIDs[f.entry.ID] {
		s.mu.Unlock()
		return
	}
	f.resolved = true
	s.resolvedIDs[f.entry.ID] = true
	if f.have == nil && !f.allSkip {
		s.gatesOpen--
		if s.gatesOpen < 0 {
			s.gatesOpen = 0
		}
		s.gateCond.Signal()
	}
	s.resolved++
	s.report.Errors = append(s.report.Errors, FileError{Path: f.entry.RelPath, Code: code, Msg: msg})
	s.reg.FileStateUpdate(f.entry.ID, "error", msg)
	s.reg.Emit("file-error", f.entry.RelPath, msg)
	s.mu.Unlock()
	_ = s.ctrl.Send(protocol.MsgFileResult, 0,
		protocol.FileResult{FileID: f.entry.ID, Status: protocol.ResultError, Code: code, Msg: msg}.Encode())
	s.maybeCloseFD(f)
}

func (s *Sender) setFatal(err error) {
	s.remoteErr.CompareAndSwap(nil, &err)
}

func (s *Sender) sendError(scope uint8, code uint16, msg string) {
	_ = s.ctrl.Send(protocol.MsgError, 0, protocol.ErrMsg{Scope: scope, Code: code, Msg: msg}.Encode())
}

// runScheduler feeds missing (not-have) chunks of gated files to the workers.
// runScheduler feeds missing (not-have) chunks of gated files to the
// workers. Gate-opened files enter readyQ so the scheduler never rescans
// the whole file table (that made many-file transfers quadratic).
func (s *Sender) runScheduler(ctx context.Context) {
	var backlog []uint32
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.ctrlDone:
			return
		default:
		}
		if len(backlog) == 0 {
			s.mu.Lock()
			backlog = append(backlog, s.readyQ...)
			s.readyQ = s.readyQ[:0]
			s.mu.Unlock()
		}
		progressed := false
	remaining:
		for len(backlog) > 0 {
			id := backlog[0]
			s.mu.Lock()
			f := s.files[id]
			if f == nil || f.errored || f.resolved || f.allSkip || f.have == nil {
				s.mu.Unlock()
				backlog = backlog[1:]
				continue remaining
			}
			for f.nextTask < f.count {
				if bitTest(f.have, f.nextTask) {
					f.nextTask++
					s.reg.FileDoneBytes(f.entry.ID, f.entry.Grid().Len(f.nextTask-1))
					continue
				}
				select {
				case s.taskCh <- chunkTask{fileID: f.entry.ID, idx: f.nextTask}:
					f.nextTask++
					f.inflight++
					progressed = true
				default:
					s.mu.Unlock()
					break remaining // channel full: keep the head for later
				}
			}
			s.mu.Unlock()
			backlog = backlog[1:]
		}
		if !progressed || len(backlog) > 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.ctrlDone:
				return
			case <-s.kick:
			case <-time.After(5 * time.Millisecond):
			}
		} else {
			// drained everything; wait for the next gate opening
			select {
			case <-ctx.Done():
				return
			case <-s.ctrlDone:
				return
			case <-s.kick:
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}

func (s *Sender) kickScheduler() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// runWorker owns one data stream for its whole life.
func (s *Sender) runWorker(ctx context.Context, index uint64) error {
	conn, err := s.sess.OpenStream()
	if err != nil {
		return err
	}
	ds, err := protocol.NewDataStream(conn, index)
	if err != nil {
		_ = conn.Close()
		return err
	}
	codec, err := compress.New(s.opts.Compression, s.opts.ZstdLevel)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if codec != nil {
		defer codec.Close()
	}
	var buf, zbuf []byte
	for {
		var task chunkTask
		var ok bool
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		case task, ok = <-s.taskCh:
			if !ok {
				_ = conn.Close()
				return nil
			}
		}
		if err := s.sendChunk(ctx, ds, codec, task, &buf, &zbuf); err != nil {
			if isCtxErr(err) {
				s.taskDone(task.fileID)
				_ = conn.Close()
				return err
			}
			s.mu.Lock()
			f := s.files[task.fileID]
			s.mu.Unlock()
			if f != nil {
				s.failFile(f, CodeSourceChanged, err.Error())
			}
		}
		s.taskDone(task.fileID)
	}
}

// sendChunk reads, hashes, compresses and writes one chunk. The scheduler
// already filtered have-bits; retries land here directly.
func (s *Sender) sendChunk(ctx context.Context, ds *protocol.DataStream, codec compress.Codec, task chunkTask, bufp, zbufp *[]byte) error {
	s.mu.Lock()
	f := s.files[task.fileID]
	s.mu.Unlock()
	if f == nil || f.errored || f.resolved {
		return nil
	}
	e := f.entry
	grid := e.Grid()
	if task.idx < 0 || task.idx >= grid.Count() {
		return fmt.Errorf("chunk %d out of range (count %d)", task.idx, grid.Count())
	}
	f.fdOnce.Do(func() {
		fd, err := fsutil.OpenNoAtime(e.AbsPath)
		if err != nil {
			f.fdErr = err
			return
		}
		f.fd = fd
	})
	if f.fdErr != nil {
		return fmt.Errorf("open: %w", f.fdErr)
	}
	if f.fd == nil {
		return fmt.Errorf("source vanished: %s", e.AbsPath)
	}
	n := grid.Len(task.idx)
	if int64(cap(*bufp)) < n {
		*bufp = make([]byte, n)
	}
	raw := (*bufp)[:n]
	got, err := f.fd.ReadAt(raw, grid.Offset(task.idx))
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if int64(got) != n {
		return fmt.Errorf("source changed: short read %d/%d (chunk %d)", got, n, task.idx)
	}
	flags := uint8(0)
	var payload []byte
	if s.opts.Preserve&protocol.PreserveSparse != 0 && isAllZero(raw) {
		s.reg.AddSent(n)
		s.reg.FileDoneBytes(e.ID, n)
		s.reg.FileStateUpdate(e.ID, "active", "")
		if err := s.limiter.acquire(ctx, n); err != nil {
			return err
		}
		return ds.WriteChunk(protocol.ChunkHeader{FileID: e.ID, ChunkIdx: uint64(task.idx), Flags: protocol.ChunkFlagZero, PayloadLen: 0}, nil)
	}
	if codec != nil {
		out, wasRaw := codec.Compress(*zbufp, raw)
		if wasRaw {
			flags |= protocol.ChunkFlagRaw
			payload = raw
		} else {
			payload = out
			*zbufp = out
		}
	} else {
		flags |= protocol.ChunkFlagRaw
		payload = raw
	}
	s.reg.AddSent(n)
	s.reg.FileDoneBytes(e.ID, n)
	s.reg.FileStateUpdate(e.ID, "active", "")
	if err := s.limiter.acquire(ctx, n); err != nil {
		return err
	}
	return ds.WriteChunk(protocol.ChunkHeader{FileID: e.ID, ChunkIdx: uint64(task.idx), Flags: flags, PayloadLen: uint64(len(payload))}, payload)
}

func isCtxErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// taskDone drops one in-flight reference and closes the fd when resolved.
func (s *Sender) taskDone(fileID uint32) {
	s.mu.Lock()
	f := s.files[fileID]
	if f == nil {
		s.mu.Unlock()
		return
	}
	if f.inflight > 0 {
		f.inflight--
	}
	fd := (*os.File)(nil)
	if f.fd != nil && f.resolved && f.inflight == 0 {
		fd = f.fd
		f.fd = nil
	}
	s.mu.Unlock()
	if fd != nil {
		_ = fd.Close()
	}
}

func bitTest(bitmap []byte, i int64) bool {
	if i < 0 || i/8 >= int64(len(bitmap)) {
		return false
	}
	return bitmap[i/8]&(1<<(uint(i)%8)) != 0
}

func isAllZero(b []byte) bool {
	for i := 0; i+8 <= len(b); i += 8 {
		if b[i]|b[i+1]|b[i+2]|b[i+3]|b[i+4]|b[i+5]|b[i+6]|b[i+7] != 0 {
			return false
		}
	}
	for i := len(b) &^ 7; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
