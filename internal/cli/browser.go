package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/ziozzang/botjim/internal/attrs"
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
	}, reg
}

// runBrowser opens the midnight-commander-style picker when no paths were
// given, then transfers the selection.
func runBrowser(ctx context.Context, f *flags, addr string, alg uint8, resume uint8, owners attrs.OwnerPolicy) int {
	if !stderrIsTerminal() {
		fmt.Fprintln(os.Stderr, "browser needs a terminal; pass explicit PATHs for non-interactive use")
		return 3
	}
	sel, err := tui.RunBrowser(ctx, tui.BrowserConfig{
		Addr: addr,
		Pull: f.pull,
		Dest: f.dest,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "browser:", err)
		return 2
	}
	if len(sel) == 0 {
		return 0
	}
	cfg, reg := buildClientConfig(f, addr, alg, resume, owners, sel)
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ui := newClientUI(f, reg, f.pull)
	res := ui.Run(rctx, cancel, func() session.ClientResult {
		return session.RunWithProgress(rctx, cfg, reg)
	})

	rep := res.Report
	fmt.Fprintf(os.Stderr, "%d files, %s transferred\n", rep.Files, humanBytes(rep.Bytes))
	for _, fe := range rep.Errors {
		fmt.Fprintf(os.Stderr, "  error: %s: %s\n", fe.Path, fe.Msg)
	}
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "transfer error:", res.Err)
		return 2
	}
	if len(rep.Errors) > 0 {
		return 1
	}
	return 0
}
