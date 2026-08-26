// Package session glues transport, protocol and engine into the two roles a
// botjim process can play: a waiting server (accept loop + per-connection
// engine + browser listing) and a client (dial, negotiate, run one transfer,
// or browse). The engines themselves are direction-agnostic; this package
// decides which core runs on which side.
package session

import (
	"bufio"
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

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/compress"
	"github.com/ziozzang/botjim/internal/engine"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/relay"
	"github.com/ziozzang/botjim/internal/transport"
)

// Wire the record-layer hooks once: every botjim process (and test) that
// uses sessions gets --pass encryption via the relay's proven construction.
func init() {
	transport.CipherFactory = relay.EncryptConn
	transport.PassphraseSecret = relay.PassphraseSecret
}

// ServerConfig configures a listening server.
type ServerConfig struct {
	Root        string // absolute, symlink-resolved jail
	Parallel    int
	Fsync       bool
	NoSuid      bool
	OwnerPolicy attrs.OwnerPolicy
	AllowPush   bool
	AllowPull   bool
	Features    uint64
	Token       string   // require --token auth from clients
	Pass        string   // require record-layer encryption from clients
	Cloak       string   // cloaked (WebSocket) mode: demux by first bytes
	Exclude     []string // walker exclusions
	Include     []string // walker inclusions
	LimitBPS    int64    // send-rate cap (0 = unlimited)	// OnCommit, when set, fires after each file lands verified (mesh
	// config propagation uses it to accept .botjim-mesh.json).
	OnCommit func(rel string)
}

// Server accepts connections and runs receiver/sender cores per session.
type Server struct {
	cfg ServerConfig

	mu      sync.Mutex
	regs    []*progress.Registry
	conns   int
	logs    []string
	lastErr error
	ctx     context.Context
	cancel  context.CancelFunc

	// cumulative counters for /metrics (atomic; no lock on the hot path)
	sessTotal  atomic.Int64
	filesTotal atomic.Int64
	bytesTotal atomic.Int64
	errTotal   atomic.Int64
}

// ServerStats is a point-in-time snapshot for monitoring.
type ServerStats struct {
	Sessions int64
	Files    int64
	Bytes    int64
	Errors   int64
	Active   int
}

// Stats returns the cumulative + live counters.
func (s *Server) Stats() ServerStats {
	s.mu.Lock()
	active := s.conns
	s.mu.Unlock()
	return ServerStats{
		Sessions: s.sessTotal.Load(),
		Files:    s.filesTotal.Load(),
		Bytes:    s.bytesTotal.Load(),
		Errors:   s.errTotal.Load(),
		Active:   active,
	}
}

// NewServer prepares a server for cfg.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Features == 0 {
		cfg.Features = protocol.FeatAll
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, ctx: ctx, cancel: cancel}
}

// Stop cancels all live sessions.
func (s *Server) Stop() { s.cancel() }

// Stopped reports whether the server is shutting down.
func (s *Server) Stopped() bool { return s.ctx.Err() != nil }

// Regs snapshots the live per-connection registries (TUI polling).
func (s *Server) Regs() []*progress.Registry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*progress.Registry, len(s.regs))
	copy(out, s.regs)
	return out
}

// Conns returns the number of live connections.
func (s *Server) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// Log records a server-side line for the dashboard.
func (s *Server) Log(format string, args ...any) {
	s.mu.Lock()
	s.logs = append(s.logs, time.Now().Format("15:04:05 ")+fmt.Sprintf(format, args...))
	if len(s.logs) > 500 {
		s.logs = s.logs[len(s.logs)-500:]
	}
	s.mu.Unlock()
}

// Logs returns recent log lines.
func (s *Server) Logs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.logs))
	copy(out, s.logs)
	return out
}

// Serve runs the accept loop until the listener or context dies.
func (s *Server) Serve(ln net.Listener) error {
	go func() {
		<-s.ctx.Done()
		_ = ln.Close()
	}()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handleConn(raw)
	}
}

// ServeConn runs one connection through the full server lifecycle —
// handshake, per-connection engine, teardown. The relay receiver (`botjim
// recv`) drives this directly on its paired pipe.
func (s *Server) ServeConn(raw net.Conn) { s.handleConn(raw) }

func (s *Server) handleConn(raw net.Conn) {
	remote := raw.RemoteAddr().String()
	// cloak demux: HTTP-looking connections upgrade inside ServeCloak;
	// plain FSY1 bytes go straight through
	// require CloakPlain too: without it a sniffed-but-plain (FSY1) client's
	// buffered handshake bytes would be stranded in br and lost. hooks.go
	// installs all cloak hooks together, so this is only a safety guard.
	if s.cfg.Cloak != "" && transport.CloakServe != nil && transport.CloakPlain != nil {
		// the sniff blocks until 4 bytes arrive: bound it, or an idle
		// connection parks this goroutine forever
		_ = raw.SetReadDeadline(time.Now().Add(15 * time.Second))
		br := bufio.NewReader(raw)
		if transport.CloakSniff(br) {
			wrapped := transport.CloakServe(raw, br, s.cfg.Cloak)
			if wrapped == nil {
				return // decoy answered; not our session
			}
			raw = wrapped
		} else {
			// not HTTP: replay the sniffed bytes to the plain path —
			// they live in br's buffer now, not on the socket
			raw = transport.CloakPlain(raw, br)
		}
		_ = raw.SetReadDeadline(time.Time{}) // AcceptSec sets its own
	}
	sess, err := transport.AcceptSec(raw, s.cfg.Features, nil, transport.SecOpts{Token: s.cfg.Token, Pass: s.cfg.Pass})
	if err != nil {
		s.Log("%s handshake: %v", remote, err)
		_ = raw.Close()
		return
	}
	s.mu.Lock()
	s.conns++
	s.mu.Unlock()
	s.sessTotal.Add(1)
	defer func() {
		_ = sess.Close()
		s.mu.Lock()
		s.conns--
		s.mu.Unlock()
	}()

	// first stream is the control stream; the opener tags it with a kind
	// byte, which we consume and verify before framing
	conn, err := sess.AcceptStreamCtx(s.ctx)
	if err != nil {
		return
	}
	kind := make([]byte, 1)
	if _, err := io.ReadFull(conn, kind); err != nil || kind[0] != protocol.StreamKindCtrl {
		_ = conn.Close()
		return
	}
	ctrl := protocol.NewCtrlStream(conn)

	for {
		frame, err := ctrl.Recv(nil)
		if err != nil {
			return
		}
		switch frame.Type {
		case protocol.MsgInitTransfer:
			init, err := protocol.DecodeInitTransfer(frame.Payload)
			if err != nil {
				_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodeProtocol, err.Error()))
				return
			}
			report, err := s.runTransfer(sess, ctrl, init, remote)
			if err != nil {
				s.Log("%s transfer: %v", remote, err)
				s.errTotal.Add(1)
			}
			s.filesTotal.Add(int64(report.Files))
			s.bytesTotal.Add(int64(report.Bytes))
			s.errTotal.Add(int64(len(report.Errors)))
			// after one transfer the connection may send another or leave
		case protocol.MsgListReq:
			s.serveList(ctrl, frame.Payload)
		case protocol.MsgGoodbye:
			return
		case protocol.MsgError:
			if m, err := protocol.DecodeErrMsg(frame.Payload); err == nil {
				s.Log("%s error: %s", remote, m.Msg)
			}
			return
		default:
			_ = ctrl.Send(protocol.MsgError, 0, protocol.ErrMsg{
				Scope: protocol.ScopeSession, Code: engine.CodeProtocol,
				Msg: fmt.Sprintf("unexpected control message 0x%02x", frame.Type)}.Encode())
			return
		}
	}
}

// runTransfer validates the request, acks it and runs the right core.
func (s *Server) runTransfer(sess *transport.Session, ctrl *protocol.CtrlStream, init protocol.InitTransfer, remote string) (engine.Report, error) {
	switch init.Dir {
	case protocol.DirPush:
		if !s.cfg.AllowPush {
			_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodePerm, "push not allowed on this server"))
			return engine.Report{}, fmt.Errorf("push refused")
		}
	case protocol.DirPull:
		if !s.cfg.AllowPull {
			_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodePerm, "pull not allowed on this server"))
			return engine.Report{}, fmt.Errorf("pull refused")
		}
	default:
		_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodeProtocol, "bad direction"))
		return engine.Report{}, fmt.Errorf("bad direction")
	}
	if init.Parallel < 1 || int(init.Parallel) > 64 {
		_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodeProtocol, "bad parallel"))
		return engine.Report{}, fmt.Errorf("bad parallel %d", init.Parallel)
	}
	// pull roots are validated before the ack: the client acts on the
	// first TransferAck it sees, so a later refusal would be invisible
	var pullRoots []string
	if init.Dir == protocol.DirPull {
		for _, p := range init.Paths {
			abs, err := fsutil.SafeJoin(s.cfg.Root, p)
			if err == nil {
				err = fsutil.CheckNoSymlinkComponents(s.cfg.Root, p)
			}
			if err == nil {
				if _, lerr := os.Lstat(abs); lerr != nil {
					err = lerr
				}
			}
			if err != nil {
				_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodeInvalidPath, fmt.Sprintf("pull path %q: %v", p, err)))
				return engine.Report{}, fmt.Errorf("pull path %q: %w", p, err)
			}
			pullRoots = append(pullRoots, abs)
		}
		if len(pullRoots) == 0 {
			_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(false, engine.CodeProtocol, "pull with no paths"))
			return engine.Report{}, fmt.Errorf("pull with no paths")
		}
	}
	_ = ctrl.Send(protocol.MsgTransferAck, 0, ack(true, 0, ""))

	par := int(init.Parallel)
	if s.cfg.Parallel > 0 && par > s.cfg.Parallel {
		par = s.cfg.Parallel // the server, not the client, caps its streams
	}
	opts := engine.Options{
		Direction:   init.Dir,
		Compression: clampAlg(init.Compression),
		ZstdLevel:   int(init.ZstdLevel),
		Parallel:    par,
		Resume:      init.Resume,
		Preserve:    init.Preserve,
		Fsync:       s.cfg.Fsync,
		NoSuid:      s.cfg.NoSuid,
		OwnerPolicy: s.cfg.OwnerPolicy,
		Nonce:       sess.HS.NonceHex(),
		Exclude:     s.cfg.Exclude,
		Include:     s.cfg.Include,
		LimitBPS:    s.cfg.LimitBPS,
		OnCommit:    s.cfg.OnCommit,
	}
	reg := progress.New()
	s.mu.Lock()
	s.regs = append(s.regs, reg)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		for i, r := range s.regs {
			if r == reg {
				s.regs = append(s.regs[:i], s.regs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	if init.Dir == protocol.DirPush {
		s.Log("%s push start (parallel %d, %s)", remote, opts.Parallel, algName(opts.Compression))
		recv := engine.NewReceiver(sess, ctrl, opts, reg, s.cfg.Root)
		report, err := recv.Run(ctx)
		s.Log("%s push done: %d files, %d bytes, %d errors (cancelled=%v)", remote, report.Files, report.Bytes, len(report.Errors), report.Cancelled)
		return report, err
	}

	roots := pullRoots
	s.Log("%s pull start (parallel %d, %s)", remote, opts.Parallel, algName(opts.Compression))
	opts.RelHome = s.cfg.Root // "." pulls mirror the jail root's content
	send := engine.NewSender(sess, ctrl, opts, reg, roots)
	report, err := send.Run(ctx)
	s.Log("%s pull done: %d files, %d bytes, %d errors (cancelled=%v)", remote, report.Files, report.Bytes+report.SkippedBytes, len(report.Errors), report.Cancelled)
	return report, err
}

// serveList answers a browser listing request inside the jail.
func (s *Server) serveList(ctrl *protocol.CtrlStream, payload []byte) {
	req, err := protocol.DecodeListReq(payload)
	if err != nil {
		return
	}
	base := s.cfg.Root
	if req.Path != "" && req.Path != "." {
		p, err := fsutil.SafeJoin(s.cfg.Root, req.Path)
		if err == nil {
			err = fsutil.CheckNoSymlinkComponents(s.cfg.Root, req.Path)
		}
		if err != nil {
			_ = ctrl.Send(protocol.MsgListResp, 0, emptyList().Encode())
			return
		}
		base = p
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		_ = ctrl.Send(protocol.MsgListResp, 0, emptyList().Encode())
		return
	}
	names := make([]string, 0, len(entries))
	byName := map[string]os.DirEntry{}
	for _, de := range entries {
		names = append(names, de.Name())
		byName[de.Name()] = de
	}
	sortStrings(names)
	limit := int(req.Limit)
	if limit <= 0 || limit > 4096 {
		limit = 1024
	}
	resp := protocol.ListResp{Total: uint32(len(names))}
	for i, n := range names {
		if i < int(req.Offset) {
			continue
		}
		if len(resp.Entries) >= limit {
			resp.Truncated = true
			break
		}
		de := byName[n]
		le := protocol.ListEntry{Name: n, IsDir: de.IsDir()}
		if fi, err := de.Info(); err == nil {
			le.Size = uint64(fi.Size())
			le.MtimeMS = fi.ModTime().UnixMilli()
			le.Mode = uint16(fi.Mode().Perm())
			if fi.Mode()&os.ModeSymlink != 0 {
				le.Mode = 0o777 | uint16(1<<15) // marker bit for symlink
			}
		}
		resp.Entries = append(resp.Entries, le)
	}
	_ = ctrl.Send(protocol.MsgListResp, 0, resp.Encode())
}

// ---- client side ----

// ClientConfig configures one client run.
type ClientConfig struct {
	Addr        string
	Conn        net.Conn // pre-paired connection (relay); Addr is display-only then
	Token       string
	Pass        string
	Cloak       string
	Exclude     []string
	Include     []string
	LimitBPS    int64
	Direction   uint8 // protocol.DirPush / DirPull
	Paths       []string
	DestRoot    string // pull destination (client side)
	Compression uint8
	ZstdLevel   int
	Parallel    int
	Resume      uint8
	Preserve    uint16
	Fsync       bool
	NoSuid      bool
	OwnerPolicy attrs.OwnerPolicy
	Timeout     time.Duration
}

// ClientResult is what a client run produced.
type ClientResult struct {
	Report         engine.Report
	Plan           []engine.PlanRow // dry-run rows (Populated with --dry-run)
	ManifestDigest string           // SHA-256 over the sent manifest (receipts)
	Err            error
}

// RunTransfer dials, negotiates and runs one transfer with a fresh registry.
func RunTransfer(ctx context.Context, cfg ClientConfig) ClientResult {
	return RunWithProgress(ctx, cfg, progress.New())
}

// RunWithRetries wraps RunWithProgress with automatic re-dial on
// connection loss: resume sidecars make each attempt continue where the
// last died, so a flaky link converges instead of failing the run.
// Backoff: 1s, 2s, 4s … capped at 30s.Attempts is bounded by retries+1.
func RunWithRetries(ctx context.Context, cfg ClientConfig, reg *progress.Registry, retries int) ClientResult {
	var last ClientResult
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			reg.Emit("info", "", fmt.Sprintf("retry %d/%d after %s", attempt, retries, backoff))
			select {
			case <-ctx.Done():
				return last
			case <-time.After(backoff):
			}
		}
		last = RunWithProgress(ctx, cfg, reg)
		if last.Err == nil {
			return last
		}
		// only connection-class errors are retryable; refusals are final
		if !retryableErr(last.Err) {
			return last
		}
	}
	return last
}

// retryableErr reports whether the error looks like a transport failure
// (worth another dial) rather than a peer refusal or protocol violation.
func retryableErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, fatal := range []string{
		"refused", "not allowed", "token", "--pass", "encryption",
		"protocol", "major mismatch", "not a botjim peer",
	} {
		if strings.Contains(msg, fatal) {
			return false
		}
	}
	return true
}

// RunWithProgress is RunTransfer with a caller-owned progress registry.
func RunWithProgress(ctx context.Context, cfg ClientConfig, reg *progress.Registry) ClientResult {
	var sess *transport.Session
	var err error
	sec := transport.SecOpts{Token: cfg.Token, Pass: cfg.Pass, Cloak: cfg.Cloak}
	if cfg.Conn != nil {
		sess, err = transport.DialConnSec(cfg.Conn, protocol.FeatAll, nil, sec)
	} else {
		sess, err = transport.DialSec(ctx, cfg.Addr, protocol.FeatAll, nil, sec)
	}
	if err != nil {
		return ClientResult{Err: err}
	}
	finished := make(chan struct{})
	defer close(finished)
	// A cancelled caller context must tear the connection down: engine
	// control readers block on the peer, and only closing the session
	// unwinds them. The receiver flushes its sidecars on disconnect.
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-finished:
		}
	}()
	defer sess.Close()

	ctrlConn, err := openControl(sess)
	if err != nil {
		return ClientResult{Err: err}
	}
	ctrl := protocol.NewCtrlStream(ctrlConn)

	init := protocol.InitTransfer{
		Dir:         cfg.Direction,
		Compression: cfg.Compression,
		ZstdLevel:   uint8(cfg.ZstdLevel),
		Preserve:    cfg.Preserve,
		Parallel:    uint8(cfg.Parallel),
		Resume:      cfg.Resume,
		Paths:       cfg.Paths, // pull: server-relative roots
	}
	if err := ctrl.Send(protocol.MsgInitTransfer, 0, init.Encode()); err != nil {
		return ClientResult{Err: err}
	}
	// the ack must come promptly; a server that never answers is a hard error
	_ = ctrlConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	frame, err := ctrl.Recv(nil)
	_ = ctrlConn.SetReadDeadline(time.Time{})
	if err != nil {
		return ClientResult{Err: fmt.Errorf("waiting for ack: %w", err)}
	}
	if frame.Type != protocol.MsgTransferAck {
		return ClientResult{Err: fmt.Errorf("expected ack, got 0x%02x", frame.Type)}
	}
	ackMsg, err := protocol.DecodeTransferAck(frame.Payload)
	if err != nil {
		return ClientResult{Err: err}
	}
	if !ackMsg.OK {
		return ClientResult{Err: fmt.Errorf("server refused: %s", ackMsg.Msg)}
	}

	opts := engine.Options{
		Direction:   cfg.Direction,
		Compression: cfg.Compression,
		ZstdLevel:   cfg.ZstdLevel,
		Parallel:    cfg.Parallel,
		Resume:      cfg.Resume,
		Preserve:    cfg.Preserve,
		Fsync:       cfg.Fsync,
		NoSuid:      cfg.NoSuid,
		OwnerPolicy: cfg.OwnerPolicy,
		Nonce:       sess.HS.NonceHex(),
		Exclude:     cfg.Exclude,
		Include:     cfg.Include,
		LimitBPS:    cfg.LimitBPS,
	}

	if cfg.Direction == protocol.DirPush {
		sender := engine.NewSender(sess, ctrl, opts, reg, cfg.Paths)
		report, err := sender.Run(ctx)
		digest, _ := sender.ManifestDigest()
		return ClientResult{Report: report, Plan: sender.Plan(), ManifestDigest: digest, Err: err}
	}

	if err := os.MkdirAll(cfg.DestRoot, 0o755); err != nil {
		return ClientResult{Err: err}
	}
	root, err := fsutil.ResolveRoot(cfg.DestRoot)
	if err != nil {
		return ClientResult{Err: err}
	}
	recv := engine.NewReceiver(sess, ctrl, opts, reg, root)
	report, err := recv.Run(ctx)
	return ClientResult{Report: report, Err: err}
}

// ListRemote asks a server for a directory listing (browser, pull mode).
func ListRemote(ctx context.Context, addr, path string, offset uint32, limit uint16) (*protocol.ListResp, error) {
	sess, err := transport.Dial(ctx, addr, protocol.FeatAll, nil)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	ctrlConn, err := openControl(sess)
	if err != nil {
		return nil, err
	}
	ctrl := protocol.NewCtrlStream(ctrlConn)
	req := protocol.ListReq{Path: path, Offset: offset, Limit: limit}
	if err := ctrl.Send(protocol.MsgListReq, 0, req.Encode()); err != nil {
		return nil, err
	}
	frame, err := ctrl.Recv(nil)
	if err != nil {
		return nil, err
	}
	if frame.Type != protocol.MsgListResp {
		return nil, fmt.Errorf("expected list response, got 0x%02x", frame.Type)
	}
	resp, err := protocol.DecodeListResp(frame.Payload)
	if err != nil {
		return nil, err
	}
	_ = ctrl.Send(protocol.MsgGoodbye, 0, nil)
	return &resp, nil
}

// ---- small helpers ----

func openControl(sess *transport.Session) (net.Conn, error) {
	conn, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{protocol.StreamKindCtrl}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func ack(ok bool, code uint16, msg string) []byte {
	return protocol.TransferAck{OK: ok, ErrCode: code, Msg: msg}.Encode()
}

func emptyList() protocol.ListResp { return protocol.ListResp{} }

func clampAlg(a uint8) uint8 {
	if a > compress.AlgLz4 {
		return compress.AlgNone
	}
	return a
}

func algName(a uint8) string {
	switch a {
	case compress.AlgZstd:
		return "zstd"
	case compress.AlgLz4:
		return "lz4"
	}
	return "none"
}

func sortStrings(ss []string) { sort.Strings(ss) }

// JoinRemote joins listing path parts for ListRemote.
func JoinRemote(parts ...string) string {
	return strings.TrimPrefix(filepath.Join(parts...), "/")
}
