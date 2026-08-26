package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/audit"
	"github.com/ziozzang/botjim/internal/compress"
	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/tui"
)

// buildClientConfig assembles the session config shared by the direct path
// and the browser.
func buildClientConfig(f *flags, addr string, alg uint8, resume uint8, owners attrs.OwnerPolicy, paths []string) (session.ClientConfig, *progress.Registry) {
	dir := uint8(protocol.DirPush)
	if f.pull {
		dir = protocol.DirPull
	}
	reg := progress.New()
	if f.dryRun {
		p := preserveBits(f)
		p |= protocol.PreserveDryRun
		return session.ClientConfig{
			Addr: addr, Direction: dir, Paths: paths, DestRoot: f.dest,
			Compression: alg, ZstdLevel: compress.NormalizeZstdLevel(f.zstdLvl),
			Parallel: f.parallel, Resume: resume, Preserve: p,
			Fsync: !f.noFsync, OwnerPolicy: owners,
			Token: f.token, Pass: f.pass,
			Exclude: f.exclude, Include: f.include, LimitBPS: f.limitB,
		}, reg
	}
	return session.ClientConfig{
		Addr:        addr,
		Direction:   dir,
		Paths:       paths,
		DestRoot:    f.dest,
		Compression: alg,
		ZstdLevel:   compress.NormalizeZstdLevel(f.zstdLvl),
		Parallel:    f.parallel,
		Resume:      resume,
		Preserve:    preserveBits(f),
		Fsync:       !f.noFsync,
		OwnerPolicy: owners,
		Token:       f.token,
		Pass:        f.pass,
		Cloak:       f.cloak,
		Exclude:     f.exclude,
		Include:     f.include,
		LimitBPS:    f.limitB,
	}, reg
}

// runBrowser opens the midnight-commander-style picker when no paths were
// given, then transfers the selection.
func runBrowser(ctx context.Context, f *flags, addr string, alg uint8, resume uint8, owners attrs.OwnerPolicy) int {
	if !stderrIsTerminal() {
		fmt.Fprintln(os.Stderr, "browser needs a terminal; pass explicit PATHs for non-interactive use")
		return 3
	}
	// send-and-return loop: after each transfer the picker reopens where
	// it was left, until the user quits with q
	startDir := ""
	for {
		sel, lastDir, err := tui.RunBrowser(ctx, tui.BrowserConfig{
			Addr:     addr,
			Pull:     f.pull,
			Dest:     f.dest,
			StartDir: startDir,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "browser:", err)
			return 2
		}
		startDir = lastDir
		if len(sel) == 0 {
			return 0
		}
		cfg, reg := buildClientConfig(f, addr, alg, resume, owners, sel)
		logPath := openTransferLog(f, reg)
		reg.Emit("info", "", fmt.Sprintf("transfer start (%s, %d paths)", directionName(f.pull), len(sel)))
		rctx, cancel := context.WithCancel(ctx)
		ui := newClientUI(f, reg, f.pull)
		ui.waitKey = true
		res := ui.Run(rctx, cancel, func() session.ClientResult {
			return session.RunWithProgress(rctx, cfg, reg)
		})
		cancel()
		reg.Emit("info", "", fmt.Sprintf("transfer end: %d files, %d bytes, %d errors",
			res.Report.Files, res.Report.Bytes, len(res.Report.Errors)))

		rep := res.Report
		fmt.Fprintf(os.Stderr, "%d files, %s transferred\n", rep.Files, humanBytes(rep.Bytes))
		for _, fe := range rep.Errors {
			fmt.Fprintf(os.Stderr, "  error: %s: %s\n", fe.Path, fe.Msg)
		}
		if logPath != "" {
			fmt.Fprintf(os.Stderr, "transfer log: %s\n", logPath)
		}
		if res.Err != nil {
			fmt.Fprintln(os.Stderr, "transfer error:", res.Err)
		}
		closeTransferLog()
		// let the previous bubbletea program finish restoring the
		// terminal before the next one claims it (sequential-program race)
		time.Sleep(250 * time.Millisecond)
	}
}

func directionName(pull bool) string {
	if pull {
		return "pull"
	}
	return "push"
}

// openTransferLog wires the registry's persistent event sink; the path is
// reported back for the final summary. --log-file overrides the default
// location under the user cache dir.
// jsonEvents selects NDJSON event output for the current command.
var jsonEvents bool

func openTransferLog(f *flags, reg *progress.Registry) string {
	path := f.logFile
	if path == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		path = filepath.Join(dir, "botjim", "transfers.log")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ""
	}
	w, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ""
	}
	transferLogMu.Lock()
	transferLogFile = w
	transferLogMu.Unlock()
	reg.SetLogWriter(lockingWriter{w})
	if jsonEvents {
		attachJSON(reg)
	}
	// hash-chained audit journal (same events, tamper-evident)
	if f.audit {
		ap := f.auditFile
		if ap == "" {
			dir, _ := os.UserCacheDir()
			ap = filepath.Join(dir, "botjim", "audit.log")
		}
		if j, err := audit.Open(ap); err == nil {
			transferAuditMu.Lock()
			transferAudit = j
			transferAuditMu.Unlock()
			reg.SetEventSink(func(e progress.Event) {
				j.Append(e.At.Format(time.RFC3339Nano), e.Kind, map[string]string{
					"path": e.Path, "msg": e.Msg,
				})
			})
		}
	}
	return path
}

var (
	transferLogMu   sync.Mutex
	transferLogFile *os.File
	transferAuditMu sync.Mutex
	transferAudit   *audit.Journal
)

type lockingWriter struct{ w io.Writer }

func (l lockingWriter) Write(p []byte) (int, error) {
	transferLogMu.Lock()
	defer transferLogMu.Unlock()
	return l.w.Write(p)
}

func closeTransferLog() {
	transferLogMu.Lock()
	if transferLogFile != nil {
		_ = transferLogFile.Close()
		transferLogFile = nil
	}
	transferLogMu.Unlock()
	transferAuditMu.Lock()
	if transferAudit != nil {
		_ = transferAudit.Close()
		transferAudit = nil
	}
	transferAuditMu.Unlock()
}
