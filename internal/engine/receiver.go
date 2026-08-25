package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/chunking"
	"github.com/ziozzang/botjim/internal/compress"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/manifest"
	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/sidecar"
	"github.com/ziozzang/botjim/internal/transport"
)

// Receiver assembles incoming chunks into part files, finalizes them with
// full attribute restoration, and runs the post-pass (hardlinks, directory
// attributes) before reporting Done.
type Receiver struct {
	sess  *transport.Session
	ctrl  *protocol.CtrlStream
	opts  Options
	reg   *progress.Registry
	root  string
	nonce string

	mu           sync.Mutex
	files        map[uint32]*rxFile
	caseSeen     map[string]string
	cleanDirs    map[string]bool
	total        uint64 // ManifestEnd.Files
	resolved     uint64 // FileResults sent
	manifestDone bool
	postRan      bool
	hardlinks    []hardlinkJob
	dirs         []manifest.Entry
	report       Report
	aborted      bool

	rehashCh   chan manifest.Entry
	finalizeCh chan uint32
	kick       chan struct{}
	doneOnce   sync.Once
	doneSent   atomic.Bool
	ctrlDone   chan struct{}
}

type rxFile struct {
	entry       manifest.Entry
	abs         string
	partPath    string
	part        *os.File
	sc          *sidecar.Sidecar
	dirty       bool
	finalQueued bool
	resolved    bool
	errored     bool
	empty       bool
	mu          sync.Mutex // guards sc/dirty/retries
	retries     map[uint64]int
}

type hardlinkJob struct {
	entry manifest.Entry
	refID uint32
}

// NewReceiver builds a receiver core rooted at root (absolute, resolved).
func NewReceiver(sess *transport.Session, ctrl *protocol.CtrlStream, opts Options, reg *progress.Registry, root string) *Receiver {
	return &Receiver{
		sess: sess, ctrl: ctrl, opts: opts, reg: reg, root: root, nonce: opts.Nonce,
		files:      map[uint32]*rxFile{},
		caseSeen:   map[string]string{},
		cleanDirs:  map[string]bool{},
		rehashCh:   make(chan manifest.Entry, 64),
		finalizeCh: make(chan uint32, 128),
		kick:       make(chan struct{}, 1),
		ctrlDone:   make(chan struct{}),
	}
}

// Run drives the receiver until the transfer completes or the connection dies.
func (r *Receiver) Run(ctx context.Context) (Report, error) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// rehash workers (resume verification is IO bound)
	var rwg sync.WaitGroup
	for i := 0; i < r.opts.Parallel; i++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			for e := range r.rehashCh {
				r.prepareRegular(wctx, e)
				r.kickCompletion()
			}
		}()
	}

	// finalizer (single — completion order and rename atomicity)
	finErr := make(chan error, 1)
	go func() { finErr <- r.runFinalizer(wctx) }()

	// completion watcher
	go r.watchCompletion(wctx, cancel)

	// control reader
	ctrlErr := make(chan error, 1)
	go func() { ctrlErr <- r.readCtrl(wctx, cancel) }()

	// data accept loop (this goroutine)
	accErr := r.acceptLoop(wctx)

	// sidecar flush on the way out
	r.flushAllSidecars()

	cancel()
	close(r.rehashCh)
	rwg.Wait()
	r.drainFinalize()

	var retErr error
	for _, ch := range []chan error{ctrlErr, finErr, accErrCh(accErr)} {
		if err := <-ch; err != nil && !isCtxErr(err) && retErr == nil {
			retErr = err
		}
	}

	r.mu.Lock()
	report := r.report
	cancelled := report.Cancelled
	completed := r.manifestDone && r.total > 0 && r.resolved >= r.total
	r.mu.Unlock()
	if wctx.Err() != nil && !cancelled && !completed && retErr == nil {
		retErr = wctx.Err()
	}
	return report, retErr
}

func accErrCh(err error) chan error {
	ch := make(chan error, 1)
	ch <- err
	return ch
}

// readCtrl processes manifest and control traffic from the sender.
func (r *Receiver) readCtrl(ctx context.Context, cancel context.CancelFunc) error {
	defer close(r.ctrlDone)
	buf := make([]byte, 0, 64<<10)
	for {
		f, err := r.ctrl.Recv(buf)
		if err != nil {
			if r.doneSent.Load() {
				return nil // peer hung up after our Done/Goodbye: clean end
			}
			return err
		}
		payload := f.Payload
		if f.Flags&protocol.CtrlFlagZstd != 0 {
			p, err := zstdDecompressFrame(payload, ctrlMaxFrame)
			if err != nil {
				return fmt.Errorf("batch decompress: %w", err)
			}
			payload = p
		}
		switch f.Type {
		case protocol.MsgManifestBatch:
			batch, err := protocol.DecodeManifestBatch(payload)
			if err != nil {
				return err
			}
			for _, e := range batch.Entries {
				r.processEntry(ctx, e)
			}
		case protocol.MsgManifestEnd:
			m, err := protocol.DecodeManifestEnd(payload)
			if err != nil {
				return err
			}
			r.mu.Lock()
			r.total = m.Files
			r.manifestDone = true
			r.mu.Unlock()
			r.kickCompletion()
		case protocol.MsgFileResult:
			// sender-side failure for a file it could not read
			m, err := protocol.DecodeFileResult(payload)
			if err != nil {
				return err
			}
			r.senderFileError(m)
		case protocol.MsgCancel:
			r.mu.Lock()
			r.report.Cancelled = true
			r.mu.Unlock()
			r.flushAllSidecars()
			return nil
		case protocol.MsgAbort:
			r.mu.Lock()
			r.report.Cancelled = true
			r.aborted = true
			r.mu.Unlock()
			r.abortParts()
			return nil
		case protocol.MsgError:
			m, err := protocol.DecodeErrMsg(payload)
			if err == nil && m.Scope == protocol.ScopeSession {
				return fmt.Errorf("remote: %s", m.Msg)
			}
		case protocol.MsgGoodbye:
			r.flushAllSidecars()
			return nil
		default:
		}
	}
}

// processEntry handles one manifest entry as it streams in.
func (r *Receiver) processEntry(ctx context.Context, e manifest.Entry) {
	if ctx.Err() != nil {
		return
	}
	r.reg.AddFile(e.ID, e.RelPath, e.Size)
	abs, err := fsutil.SafeJoin(r.root, e.RelPath)
	if err != nil {
		r.failEntry(e, CodeInvalidPath, err.Error())
		return
	}
	if err := r.checkParents(e.RelPath); err != nil {
		r.failEntry(e, CodeInvalidPath, err.Error())
		return
	}
	if prev, dup := r.caseSeen[strings.ToLower(e.RelPath)]; dup && prev != e.RelPath {
		r.failEntry(e, CodeInvalidPath, fmt.Sprintf("case collision with %q (case-insensitive target?)", prev))
		return
	}
	r.mu.Lock()
	r.caseSeen[strings.ToLower(e.RelPath)] = e.RelPath
	r.mu.Unlock()

	switch e.Kind {
	case manifest.KindDir:
		if err := os.MkdirAll(abs, 0o700); err != nil && !os.IsExist(err) {
			r.failEntry(e, CodeIO, err.Error())
			return
		}
		r.mu.Lock()
		r.cleanDirs[e.RelPath] = true
		r.dirs = append(r.dirs, e)
		r.mu.Unlock()
		r.okEntry(e, "")
	case manifest.KindSymlink:
		if err := attrs.MakeSymlink(abs, e); err != nil {
			r.failEntry(e, CodeIO, err.Error())
			return
		}
		for _, w := range attrs.ApplyPath(abs, e, r.opts.OwnerPolicy) {
			r.warn(w.String())
		}
		r.mu.Lock()
		r.cleanDirs[e.RelPath] = false // a symlink: children must be refused
		r.mu.Unlock()
		r.okEntry(e, "")
	case manifest.KindFIFO, manifest.KindCharDev, manifest.KindBlockDev:
		if err := attrs.MakeNode(abs, e); err != nil {
			r.failEntry(e, CodePerm, err.Error())
			return
		}
		for _, w := range attrs.ApplyPath(abs, e, r.opts.OwnerPolicy) {
			r.warn(w.String())
		}
		r.okEntry(e, "")
	case manifest.KindHardlink:
		r.mu.Lock()
		r.hardlinks = append(r.hardlinks, hardlinkJob{entry: e, refID: e.LinkRefID})
		r.mu.Unlock()
		// resolved during the post-pass
	case manifest.KindRegular:
		select {
		case r.rehashCh <- e:
		case <-ctx.Done():
		}
	default:
		r.failEntry(e, CodeProtocol, fmt.Sprintf("unsupported kind %v", e.Kind))
	}
}

// prepareRegular runs resume discovery + verification for one file.
func (r *Receiver) prepareRegular(ctx context.Context, e manifest.Entry) {
	abs, err := fsutil.SafeJoin(r.root, e.RelPath)
	if err != nil {
		r.failEntry(e, CodeInvalidPath, err.Error())
		return
	}
	grid := e.Grid()

	// already-complete shortcut (size + mtime)
	if fi, err := os.Lstat(abs); err == nil && fi.Mode().IsRegular() {
		mtimeOK := r.opts.Resume == 1 || fi.ModTime().Equal(time.Unix(e.Mtime.Sec, int64(e.Mtime.Nsec)))
		if fi.Size() == e.Size && mtimeOK && r.opts.Resume != 2 {
			r.sendHave(e.ID, protocol.HaveAllSkip, nil)
			r.reg.AddSkipped(e.Size)
			r.reg.FileStateUpdate(e.ID, "skipped", "")
			r.okEntry(e, "")
			return
		}
	}

	// empty file: nothing streams, finalize inline
	if grid.Count() == 0 {
		r.writeEmpty(abs, e)
		r.sendHave(e.ID, protocol.HaveNone, nil)
		return
	}

	f := &rxFile{entry: e, abs: abs, retries: map[uint64]int{}}
	strict := r.opts.Resume == 0

	// resume discovery
	if r.opts.Resume == 2 {
		r.removeParts(abs)
	}
	part, meta, stale := sidecar.Discover(abs)
	for _, s := range stale {
		_ = os.Remove(s)
		_ = os.Remove(sidecar.MetaPathForPart(s))
	}
	var sc *sidecar.Sidecar
	scHadSidecar := false
	partExisted := part != ""
	if part != "" {
		if meta != "" {
			if loaded, err := sidecar.Load(meta); err == nil {
				if loaded.Validate(e, strict) == nil {
					sc = loaded
					scHadSidecar = true
				}
			}
		}
		if sc == nil {
			// part without usable sidecar: rebuild from the file itself
			sc = sidecar.New(e, nonceOf(part))
		}
	} else {
		part = sidecar.PartPath(abs, r.nonce)
		sc = sidecar.New(e, r.nonce)
	}
	f.partPath = part
	f.sc = sc

	// open (or create) the part file
	pf, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		r.failEntry(e, CodeIO, "part: "+err.Error())
		return
	}
	if err := pf.Truncate(e.Size); err != nil {
		_ = pf.Close()
		r.failEntry(e, CodeIO, "truncate: "+err.Error())
		return
	}
	f.part = pf

	// verify have-bits by re-hashing the part (bitmap is a hint; data rules).
	// a part without a usable sidecar is fully rehashed to rebuild it.
	resumed := int64(0)
	if !sc.FullyWritten && (sc.HaveCount() > 0 || (partExisted && !scHadSidecar)) {
		resumed = r.rehashPart(f, e, grid)
	}
	r.sendHave(e.ID, protocol.HavePartial, sc.Bitmap())

	r.mu.Lock()
	r.files[e.ID] = f
	r.mu.Unlock()
	if resumed > 0 {
		r.reg.AddSkipped(resumed)
		r.reg.FileDoneBytes(e.ID, resumed)
	}
	r.reg.FileStateUpdate(e.ID, "active", "")

	// fully-resumed or FullyWritten sidecar: straight to finalize
	if sc.Complete() {
		r.queueFinalize(e.ID)
	}
}

// rehashPart re-verifies every have-marked chunk of a resumed part. When the
// sidecar was rebuilt from scratch this rehashes the whole file to discover
// what is actually there (the deterministic grid makes this possible). It
// returns the byte total of chunks kept.
func (r *Receiver) rehashPart(f *rxFile, e manifest.Entry, grid chunking.Grid) int64 {
	keptBytes := int64(0)
	total := grid.Count()
	// sidecar-less rebuild: claim every chunk, adopt what hashes cleanly
	if f.sc.HaveCount() == 0 {
		have := make([]byte, (total+7)/8)
		for i := int64(0); i < total; i++ {
			have[i/8] |= 1 << (uint(i) % 8)
		}
		f.sc.AdoptBitmap(have)
		for i := range f.sc.Hashes {
			f.sc.Hashes[i] = ""
		}
	}
	buf := make([]byte, grid.ChunkSize)
	for i := int64(0); i < total; i++ {
		if !f.sc.Have(i) {
			continue
		}
		n := grid.Len(i)
		if int64(cap(buf)) < n {
			buf = make([]byte, n)
		}
		chunk := buf[:n]
		got, err := f.part.ReadAt(chunk, grid.Offset(i))
		if err != nil && !errors.Is(err, io.EOF) {
			f.sc.ClearHave(i)
			continue
		}
		if int64(got) != n {
			f.sc.ClearHave(i)
			continue
		}
		if chunking.AllZero(chunk) {
			f.sc.SetHave(i, chunking.ZeroHash, true)
			keptBytes += n
			continue
		}
		h := chunking.ChunkSHA(e.RelPath, i, chunk)
		want := f.sc.Hashes[i]
		if want == "" {
			// rebuilt sidecar: adopt the on-disk data as-is
			f.sc.SetHave(i, h, false)
			keptBytes += n
			continue
		}
		if want != hexHash(h) {
			f.sc.ClearHave(i)
			continue
		}
		keptBytes += n
	}
	f.mu.Lock()
	f.dirty = true
	f.mu.Unlock()
	return keptBytes
}

// writeEmpty creates a zero-length final file with its attributes.
func (r *Receiver) writeEmpty(abs string, e manifest.Entry) {
	fd, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		r.failEntry(e, CodeIO, err.Error())
		return
	}
	defer fd.Close()
	for _, w := range attrs.ApplyFile(fd, abs, e, r.opts.OwnerPolicy) {
		r.warn(w.String())
	}
	r.reg.FileStateUpdate(e.ID, "done", "")
	r.okEntry(e, "")
}

// acceptLoop drains accepted data streams into chunk handlers.
func (r *Receiver) acceptLoop(ctx context.Context) error {
	var wg sync.WaitGroup
	for {
		conn, err := r.sess.AcceptStreamCtx(ctx)
		if err != nil {
			wg.Wait()
			if isCtxErr(err) {
				return ctx.Err()
			}
			return nil // session ended
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			r.handleStream(ctx, c)
		}(conn)
	}
}

func (r *Receiver) handleStream(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ds, _, err := protocol.AcceptDataStream(conn)
	if err != nil {
		return
	}
	codec, err := compress.New(r.opts.Compression, r.opts.ZstdLevel)
	if err != nil {
		return
	}
	if codec != nil {
		defer codec.Close()
	}
	var dbuf []byte
	for {
		hdr, payload, err := ds.ReadChunk()
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				r.warn(fmt.Sprintf("stream: %v", err))
			}
			return
		}
		if err := r.absorbChunk(codec, hdr, payload, &dbuf); err != nil {
			r.retryOrFail(hdr, err)
		}
	}
}

// absorbChunk decompresses, verifies and writes one chunk.
func (r *Receiver) absorbChunk(codec compress.Codec, hdr protocol.ChunkHeader, payload []byte, dbufp *[]byte) error {
	r.mu.Lock()
	f := r.files[hdr.FileID]
	r.mu.Unlock()
	if f == nil || f.errored || f.resolved {
		return nil // stale chunk after resolution: drop quietly
	}
	grid := f.entry.Grid()
	if int64(hdr.ChunkIdx) >= grid.Count() {
		return fmt.Errorf("chunk %d out of range", hdr.ChunkIdx)
	}
	idx := int64(hdr.ChunkIdx)
	expected := grid.Len(idx)

	if hdr.Flags&protocol.ChunkFlagZero != 0 {
		if expected == 0 {
			return nil
		}
		f.mu.Lock()
		f.sc.SetHave(idx, chunking.ZeroHash, true)
		f.dirty = true
		f.mu.Unlock()
		r.reg.AddSent(expected)
		r.reg.FileDoneBytes(hdr.FileID, expected)
		r.maybeComplete(f, hdr.FileID)
		return nil
	}

	var data []byte
	if hdr.Flags&protocol.ChunkFlagRaw != 0 {
		if int64(len(payload)) != expected {
			return fmt.Errorf("raw chunk %d: %d bytes, expected %d", idx, len(payload), expected)
		}
		data = payload
	} else {
		out, err := codec.Decompress(*dbufp, payload, int(expected))
		if err != nil {
			return fmt.Errorf("chunk %d decompress: %w", idx, err)
		}
		data = out
		*dbufp = out
		if int64(len(data)) != expected {
			return fmt.Errorf("chunk %d: %d bytes, expected %d", idx, len(data), expected)
		}
	}
	if _, err := f.part.WriteAt(data, grid.Offset(idx)); err != nil {
		return fmt.Errorf("chunk %d write: %w", idx, err)
	}
	h := chunking.ChunkSHA(f.entry.RelPath, idx, data)
	f.mu.Lock()
	f.sc.SetHave(idx, h, false)
	f.dirty = true
	f.mu.Unlock()
	r.reg.AddSent(expected)
	r.reg.FileDoneBytes(hdr.FileID, expected)
	r.maybeComplete(f, hdr.FileID)
	return nil
}

// maybeComplete queues finalize when the last missing chunk lands.
func (r *Receiver) maybeComplete(f *rxFile, id uint32) {
	f.mu.Lock()
	complete := f.sc.Complete()
	queued := f.finalQueued
	if complete && !queued {
		f.finalQueued = true
	}
	f.mu.Unlock()
	if complete && !queued {
		r.queueFinalize(id)
	}
}

func (r *Receiver) queueFinalize(id uint32) {
	select {
	case r.finalizeCh <- id:
	default:
		go func() { r.finalizeCh <- id }()
	}
}

// runFinalizer turns complete part files into final files.
func (r *Receiver) runFinalizer(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case id, ok := <-r.finalizeCh:
			if !ok {
				return nil
			}
			r.finalize(id)
			r.kickCompletion()
		}
	}
}

func (r *Receiver) finalize(id uint32) {
	r.mu.Lock()
	f := r.files[id]
	r.mu.Unlock()
	if f == nil || f.resolved || f.errored {
		return
	}
	e := f.entry
	if r.opts.Fsync {
		if err := f.part.Sync(); err != nil {
			r.failFile(f, CodeIO, "fsync: "+err.Error())
			return
		}
	}
	for _, w := range attrs.ApplyFile(f.part, f.partPath, e, r.opts.OwnerPolicy) {
		r.warn(w.String())
	}
	if err := f.part.Close(); err != nil {
		r.failFile(f, CodeIO, "close: "+err.Error())
		return
	}
	f.part = nil
	if err := os.Rename(f.partPath, f.abs); err != nil {
		r.failFile(f, CodeIO, "rename: "+err.Error())
		return
	}
	// record completion, then drop the sidecar and any stale siblings
	f.sc.FullyWritten = true
	_ = f.sc.SaveAtomic(f.partPath)
	_ = os.Remove(sidecar.MetaPathForPart(f.partPath))
	_, _, stale := sidecar.Discover(f.abs)
	for _, s := range stale {
		_ = os.Remove(s)
		_ = os.Remove(sidecar.MetaPathForPart(s))
	}
	f.dirty = false
	r.reg.FileStateUpdate(e.ID, "done", "")
	r.okEntryLocked(f, e)
}

// watchCompletion triggers the post-pass and the Done/Goodbye handshake.
func (r *Receiver) watchCompletion(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.ctrlDone:
			// sender is gone; finish what landed (post-pass if manifest done)
		loop:
			for {
				select {
				case <-r.kick:
					continue loop
				case <-time.After(50 * time.Millisecond):
					break loop
				}
			}
			r.maybePostPass(true)
			return
		case <-r.kick:
		case <-time.After(50 * time.Millisecond):
		}
		r.mu.Lock()
		manifestDone := r.manifestDone
		total := r.total
		resolved := r.resolved
		hl := uint64(len(r.hardlinks))
		postRan := r.postRan
		r.mu.Unlock()
		if manifestDone && !postRan && resolved+hl >= total {
			r.maybePostPass(false)
		}
		if manifestDone && r.resolved >= total && r.postRan {
			r.mu.Lock()
			done := protocol.Done{
				Files:  r.report.Files,
				Bytes:  r.report.Bytes,
				Errors: uint32(len(r.report.Errors)),
			}
			r.mu.Unlock()
			r.doneOnce.Do(func() {
				r.doneSent.Store(true)
				_ = r.ctrl.Send(protocol.MsgDone, 0, done.Encode())
				_ = r.ctrl.Send(protocol.MsgGoodbye, 0, nil)
			})
			cancel()
			return
		}
	}
}

// maybePostPass creates hardlinks and applies directory attributes in
// deep-reverse order (children writes dirty parent mtimes).
func (r *Receiver) maybePostPass(final bool) {
	r.mu.Lock()
	if r.postRan {
		r.mu.Unlock()
		return
	}
	r.postRan = true
	jobs := append([]hardlinkJob(nil), r.hardlinks...)
	dirs := append([]manifest.Entry(nil), r.dirs...)
	report := &r.report
	r.mu.Unlock()

	for _, j := range jobs {
		e := j.entry
		abs, err := fsutil.SafeJoin(r.root, e.RelPath)
		if err != nil {
			r.failEntry(e, CodeInvalidPath, err.Error())
			continue
		}
		r.mu.Lock()
		ref := r.files[j.refID]
		r.mu.Unlock()
		if ref == nil || ref.errored {
			r.failEntry(e, CodeIO, "hardlink source failed")
			continue
		}
		if err := attrs.MakeHardlink(ref.abs, abs); err != nil {
			if errors.Is(err, unix.EXDEV) {
				// cross-mount: degrade to a full local copy
				if err := copyFileLocal(ref.abs, abs); err != nil {
					r.failEntry(e, CodeIO, "hardlink copy fallback: "+err.Error())
					continue
				}
			} else {
				r.failEntry(e, CodeIO, "link: "+err.Error())
				continue
			}
		}
		for _, w := range attrs.ApplyPath(abs, e, r.opts.OwnerPolicy) {
			r.warn(w.String())
		}
		r.reg.FileStateUpdate(e.ID, "done", "")
		r.okEntry(e, "")
		_ = report
	}

	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].RelPath) > len(dirs[j].RelPath) })
	for i := len(dirs) - 1; i >= 0; i-- {
		e := dirs[i]
		abs, err := fsutil.SafeJoin(r.root, e.RelPath)
		if err != nil {
			continue
		}
		for _, w := range attrs.ApplyPath(abs, e, r.opts.OwnerPolicy) {
			r.warn(w.String())
		}
	}
	if !final {
		r.kickCompletion()
	}
}

// ---- small helpers ----

func (r *Receiver) sendHave(fileID uint32, status uint8, bitmap []byte) {
	_ = r.ctrl.Send(protocol.MsgHaveBitmap, 0, protocol.HaveBitmap{FileID: fileID, Status: status, Bitmap: bitmap}.Encode())
}

// okEntry records success and echoes FileResult.
func (r *Receiver) okEntry(e manifest.Entry, _ string) {
	r.mu.Lock()
	r.report.Files++
	r.report.Bytes += uint64(e.Size)
	r.resolved++
	r.mu.Unlock()
	_ = r.ctrl.Send(protocol.MsgFileResult, 0, protocol.FileResult{FileID: e.ID, Status: protocol.ResultOK}.Encode())
	r.kickCompletion()
}

func (r *Receiver) okEntryLocked(f *rxFile, e manifest.Entry) {
	r.mu.Lock()
	if !f.resolved {
		f.resolved = true
		r.report.Files++
		r.report.Bytes += uint64(e.Size)
		r.resolved++
	}
	r.mu.Unlock()
	_ = r.ctrl.Send(protocol.MsgFileResult, 0, protocol.FileResult{FileID: e.ID, Status: protocol.ResultOK}.Encode())
	r.kickCompletion()
}

func (r *Receiver) failEntry(e manifest.Entry, code uint16, msg string) {
	r.mu.Lock()
	r.report.Errors = append(r.report.Errors, FileError{Path: e.RelPath, Code: code, Msg: msg})
	r.resolved++
	if f := r.files[e.ID]; f != nil {
		f.errored = true
		f.resolved = true
	}
	r.mu.Unlock()
	r.reg.FileStateUpdate(e.ID, "error", msg)
	_ = r.ctrl.Send(protocol.MsgFileResult, 0, protocol.FileResult{FileID: e.ID, Status: protocol.ResultError, Code: code, Msg: msg}.Encode())
	r.kickCompletion()
}

func (r *Receiver) failFile(f *rxFile, code uint16, msg string) {
	r.mu.Lock()
	if f.errored || f.resolved {
		r.mu.Unlock()
		return
	}
	f.errored = true
	f.resolved = true
	r.report.Errors = append(r.report.Errors, FileError{Path: f.entry.RelPath, Code: code, Msg: msg})
	r.resolved++
	r.mu.Unlock()
	if f.part != nil {
		_ = f.part.Close()
		f.part = nil
	}
	r.reg.FileStateUpdate(f.entry.ID, "error", msg)
	_ = r.ctrl.Send(protocol.MsgFileResult, 0, protocol.FileResult{FileID: f.entry.ID, Status: protocol.ResultError, Code: code, Msg: msg}.Encode())
	r.kickCompletion()
}

// senderFileError handles a FileResult(error) sent by the sender (source
// unreadable). The partial is kept for a future re-run.
func (r *Receiver) senderFileError(m protocol.FileResult) {
	r.mu.Lock()
	f := r.files[m.FileID]
	if f != nil && !f.resolved && !f.errored {
		f.errored = true
		f.resolved = true
		if f.part != nil {
			_ = f.part.Close()
			f.part = nil
		}
		r.report.Errors = append(r.report.Errors, FileError{Path: f.entry.RelPath, Code: m.Code, Msg: "sender: " + m.Msg})
	} else if f == nil {
		r.report.Errors = append(r.report.Errors, FileError{Path: fmt.Sprintf("file#%d", m.FileID), Code: m.Code, Msg: "sender: " + m.Msg})
	}
	r.resolved++
	r.mu.Unlock()
	r.reg.FileStateUpdate(m.FileID, "error", m.Msg)
	r.kickCompletion()
}

// retryOrFail sends a ChunkRetry or escalates to a file error after three
// attempts on the same chunk.
func (r *Receiver) retryOrFail(hdr protocol.ChunkHeader, err error) {
	r.mu.Lock()
	f := r.files[hdr.FileID]
	r.mu.Unlock()
	if f == nil || f.errored || f.resolved {
		return
	}
	f.mu.Lock()
	f.retries[hdr.ChunkIdx]++
	n := f.retries[hdr.ChunkIdx]
	f.mu.Unlock()
	if n > 3 {
		r.failFile(f, CodeIO, fmt.Sprintf("chunk %d: %v", hdr.ChunkIdx, err))
		return
	}
	_ = r.ctrl.Send(protocol.MsgChunkRetry, 0, protocol.ChunkRetry{FileID: hdr.FileID, ChunkIdx: hdr.ChunkIdx, Reason: 1}.Encode())
}

// checkParents refuses entries below a symlink created during this transfer
// (the classic manifest-side jailbreak).
func (r *Receiver) checkParents(rel string) error {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		prefix := strings.Join(parts[:i], "/")
		r.mu.Lock()
		clean, seen := r.cleanDirs[prefix]
		r.mu.Unlock()
		if seen {
			if !clean {
				return fmt.Errorf("parent %q is a symlink", prefix)
			}
			continue
		}
		abs, err := fsutil.SafeJoin(r.root, prefix)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			continue // will be created by a later manifest entry
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			r.mu.Lock()
			r.cleanDirs[prefix] = false
			r.mu.Unlock()
			return fmt.Errorf("parent %q is a symlink", prefix)
		}
		if fi.IsDir() {
			r.mu.Lock()
			r.cleanDirs[prefix] = true
			r.mu.Unlock()
		}
	}
	return nil
}

// flushAllSidecars persists every dirty sidecar (graceful shutdown path).
func (r *Receiver) flushAllSidecars() {
	r.mu.Lock()
	fs := make([]*rxFile, 0, len(r.files))
	for _, f := range r.files {
		fs = append(fs, f)
	}
	r.mu.Unlock()
	for _, f := range fs {
		f.mu.Lock()
		if f.dirty && f.part != nil && f.partPath != "" {
			_ = f.sc.SaveAtomic(f.partPath)
			f.dirty = false
		}
		f.mu.Unlock()
	}
}

// abortParts deletes partials for an aborted transfer.
func (r *Receiver) abortParts() {
	r.mu.Lock()
	fs := make([]*rxFile, 0, len(r.files))
	for _, f := range r.files {
		fs = append(fs, f)
	}
	r.mu.Unlock()
	for _, f := range fs {
		f.mu.Lock()
		if f.part != nil {
			_ = f.part.Close()
			f.part = nil
		}
		pp := f.partPath
		f.mu.Unlock()
		if pp != "" {
			_ = os.Remove(pp)
			_ = os.Remove(sidecar.MetaPathForPart(pp))
		}
	}
}

func (r *Receiver) removeParts(abs string) {
	part, meta, stale := sidecar.Discover(abs)
	for _, p := range append([]string{part}, stale...) {
		if p != "" {
			_ = os.Remove(p)
			_ = os.Remove(sidecar.MetaPathForPart(p))
		}
	}
	if meta != "" {
		_ = os.Remove(meta)
	}
}

func (r *Receiver) warn(msg string) {
	r.mu.Lock()
	r.report.Warnings = append(r.report.Warnings, msg)
	r.mu.Unlock()
	r.reg.Emit("warn", "", msg)
}

func (r *Receiver) kickCompletion() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

func (r *Receiver) drainFinalize() {
	for {
		select {
		case id := <-r.finalizeCh:
			r.finalize(id)
		default:
			return
		}
	}
}

func nonceOf(partPath string) string {
	base := filepath.Base(partPath)
	if i := strings.Index(base, sidecar.PartPrefix); i >= 0 {
		return base[i+len(sidecar.PartPrefix):]
	}
	return "0000"
}

func hexHash(h [32]byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexd[b>>4]
		out[i*2+1] = hexd[b&0xF]
	}
	return string(out)
}

func copyFileLocal(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
