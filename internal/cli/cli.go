// Package cli parses botjim's command line and dispatches to the server,
// client (push/pull), browser, update or version modes.
//
// Usage:
//
//	botjim -s [flags]                          server (waits, dashboard)
//	botjim -c HOST[:port] [PATH...]            push PATHs to the server
//	botjim -c HOST[:port] --pull [RPATH...]    pull RPATHs from the server
//	botjim -c HOST[:port]                      browser (pick & push/pull)
//	botjim update [--check|--force|--version V]
package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/compress"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/transport"
	"github.com/ziozzang/botjim/internal/version"
)

// DefaultPort is botjim's TCP port.
const DefaultPort = 4761

// flags is one parsed invocation.
type flags struct {
	server    bool
	client    string
	port      int
	bind      string
	root      string
	dest      string
	pull      bool
	compressA string
	zstdLvl   int
	parallel  int
	owners    string
	noXattr   bool
	noSparse  bool
	devices   bool
	oneFS     bool
	resume    string
	noFsync   bool
	stopErr   bool
	noTUI     bool
	quiet     bool
	verbose   bool
	probe     bool
	logFile   string
	rest      []string
}

func parse(args []string) (*flags, error) {
	f := &flags{}
	fs := flag.NewFlagSet("botjim", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(fs) }
	fs.BoolVar(&f.server, "s", false, "run as server (wait for connections)")
	fs.StringVar(&f.client, "c", "", "connect to HOST[:port] as client")
	fs.IntVar(&f.port, "p", DefaultPort, "port (server listen / client connect)")
	fs.StringVar(&f.bind, "bind", "", "server bind address (default all interfaces)")
	fs.StringVar(&f.root, "root", ".", "server root directory (jail for all transfers)")
	fs.StringVar(&f.dest, "dest", ".", "client destination directory (pull)")
	fs.BoolVar(&f.pull, "pull", false, "pull from the server instead of pushing")
	fs.StringVar(&f.compressA, "compress", "zstd", "compression: zstd | lz4 | none")
	fs.IntVar(&f.zstdLvl, "zstd-level", 3, "zstd level 1(fastest)..4(best)")
	fs.IntVar(&f.parallel, "parallel", 8, "parallel data streams (1..32)")
	fs.StringVar(&f.owners, "map-owners", "none", "ownership: none | numeric | name")
	fs.BoolVar(&f.noXattr, "no-xattr", false, "do not transfer extended attributes")
	fs.BoolVar(&f.noSparse, "no-sparse", false, "do not detect zero chunks (no holes)")
	fs.BoolVar(&f.devices, "devices", false, "transfer fifo/device nodes (needs privileges)")
	fs.BoolVar(&f.oneFS, "one-file-system", false, "do not cross filesystem boundaries")
	fs.StringVar(&f.resume, "resume", "on", "resume mode: on | size | fresh")
	fs.BoolVar(&f.noFsync, "no-fsync", false, "skip fsync before finalize")
	fs.BoolVar(&f.stopErr, "stop-on-error", false, "abort the transfer on the first file error")
	fs.BoolVar(&f.noTUI, "no-tui", false, "disable TUI (single-line progress)")
	fs.BoolVar(&f.quiet, "q", false, "quiet (errors only)")
	fs.BoolVar(&f.verbose, "v", false, "verbose")
	fs.BoolVar(&f.probe, "probe", false, "probe the server (RTT/version) and exit")
	fs.StringVar(&f.logFile, "log-file", "", "append diagnostics to this file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	f.rest = fs.Args()
	return f, nil
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `botjim %s — files, ferried intact

usage:
  botjim -s [flags]                            server (waits; live dashboard)
  botjim -c HOST[:port] [PATH...]              push PATHs to the server
  botjim -c HOST[:port] --pull [RPATH...]      pull RPATHs from the server
  botjim -c HOST[:port]                        browse & pick (TUI)
  botjim update [--check] [--force]            self-update from GitHub
  botjim version

`, version.Version)
	fs.PrintDefaults()
}

// Main runs one invocation and returns the process exit code.
func Main(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			if args[0] == "version" && len(args) > 1 {
				fmt.Fprintln(os.Stderr, "usage: botjim version")
				return 3
			}
			fmt.Printf("botjim %s (%s/%s)\nhttps://github.com/%s\n", version.Version, osName(), archName(), version.Repo)
			return 0
		case "help", "--help", "-h":
			f, _ := parse(nil)
			_ = f
			fs := flag.NewFlagSet("botjim", flag.ContinueOnError)
			fs.SetOutput(os.Stderr)
			usage(fs)
			return 0
		case "update":
			return updateCmd(args[1:])
		}
	}

	f, err := parse(args)
	if err != nil {
		return 3
	}
	if f.server == (f.client != "") {
		fmt.Fprintln(os.Stderr, "error: exactly one of -s or -c HOST is required")
		usage(flag.NewFlagSet("botjim", flag.ContinueOnError))
		return 3
	}
	if f.parallel < 1 || f.parallel > 32 {
		fmt.Fprintln(os.Stderr, "error: --parallel must be 1..32")
		return 3
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		// second Ctrl-C exits immediately; sidecars are periodic so at most a
		// couple of seconds of bitmap are lost, and re-hash repairs that.
		<-ctx.Done()
		stop()
		c2 := make(chan os.Signal, 1)
		signal.Notify(c2, os.Interrupt, syscall.SIGTERM)
		<-c2
		os.Exit(2)
	}()

	if f.server {
		if err := runServer(ctx, f); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			return 2
		}
		return 0
	}
	return runClient(ctx, f)
}

func hostPort(host string, port int) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil // already host:port (or [v6]:port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func algID(name string) (uint8, error) {
	switch name {
	case "zstd":
		return compress.AlgZstd, nil
	case "lz4":
		return compress.AlgLz4, nil
	case "none":
		return compress.AlgNone, nil
	}
	return 0, fmt.Errorf("unknown compression %q (zstd|lz4|none)", name)
}

func resumeMode(s string) (uint8, error) {
	switch s {
	case "on", "strict":
		return 0, nil
	case "size":
		return 1, nil
	case "fresh":
		return 2, nil
	}
	return 0, fmt.Errorf("unknown resume mode %q (on|size|fresh)", s)
}

func ownerPolicy(s string) (attrs.OwnerPolicy, error) {
	switch s {
	case "none":
		return attrs.OwnerNone, nil
	case "numeric":
		return attrs.OwnerNumeric, nil
	case "name":
		return attrs.OwnerName, nil
	}
	return 0, fmt.Errorf("unknown owner policy %q (none|numeric|name)", s)
}

func preserveBits(f *flags) uint16 {
	p := uint16(protocol.PreserveXattr | protocol.PreserveHardlink | protocol.PreserveSparse)
	if f.noXattr {
		p &^= protocol.PreserveXattr
	}
	if f.noSparse {
		p &^= protocol.PreserveSparse
	}
	if f.devices {
		p |= protocol.PreserveDevices
	}
	if f.owners != "none" {
		p |= protocol.PreserveOwners
	}
	if f.owners == "name" {
		p |= protocol.PreserveUname
	}
	return p
}

// runServer starts the listener and dashboard.
func runServer(ctx context.Context, f *flags) error {
	if err := os.MkdirAll(f.root, 0o755); err != nil {
		return err
	}
	root, err := fsutil.ResolveRoot(f.root)
	if err != nil {
		return err
	}
	bind := f.bind
	if bind == "" {
		bind = fmt.Sprintf(":%d", f.port)
	} else if !strings.Contains(bind, ":") {
		bind = fmt.Sprintf("%s:%d", bind, f.port)
	}
	owners, err := ownerPolicy(f.owners)
	if err != nil {
		return err
	}
	ln, err := transport.Listen(bind)
	if err != nil {
		return err
	}
	srv := session.NewServer(session.ServerConfig{
		Root:        root,
		Parallel:    f.parallel,
		Fsync:       !f.noFsync,
		OwnerPolicy: owners,
		AllowPush:   true,
		AllowPull:   true,
	})
	fmt.Fprintf(os.Stderr, "botjim %s serving %s on %s (plain V1 — use on trusted networks)\n", version.Version, root, bind)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	ui := newServerUI(srv, f)
	ui.Run(ctx) // blocks: dashboard on TTY, ctx wait otherwise

	srv.Stop()
	time.Sleep(300 * time.Millisecond) // let sessions flush sidecars
	select {
	case err := <-done:
		return err
	default:
		return nil
	}
}

// runClient performs one push/pull (or opens the browser with no paths).
func runClient(ctx context.Context, f *flags) int {
	addr, err := hostPort(f.client, f.port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	alg, err := algID(f.compressA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	resume, err := resumeMode(f.resume)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	owners, err := ownerPolicy(f.owners)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}

	if f.probe {
		return probeCmd(ctx, addr)
	}

	var paths []string
	if !f.pull {
		paths, err = fsutil.ExpandArgs(f.rest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 3
		}
	} else {
		paths = f.rest // server-relative, validated by the server
	}

	if len(paths) == 0 {
		return runBrowser(ctx, f, addr, alg, resume, owners)
	}

	dir := uint8(protocol.DirPush)
	if f.pull {
		dir = protocol.DirPull
	}
	cfg, reg := buildClientConfig(f, addr, alg, resume, owners, paths)
	logPath := openTransferLog(f, reg)
	if logPath != "" {
		defer closeTransferLog()
	}
	reg.Emit("info", "", fmt.Sprintf("transfer start (%s, %d paths)", directionName(f.pull), len(paths)))
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ui := newClientUI(f, reg, dir == protocol.DirPull)
	res := ui.Run(rctx, cancel, func() session.ClientResult {
		return session.RunWithProgress(rctx, cfg, reg)
	})
	reg.Emit("info", "", fmt.Sprintf("transfer end: %d files, %d bytes, %d errors",
		res.Report.Files, res.Report.Bytes, len(res.Report.Errors)))

	rep := res.Report
	fmt.Fprintf(os.Stderr, "\n%d files, %s transferred", rep.Files, humanBytes(rep.Bytes))
	if rep.SkippedBytes > 0 {
		fmt.Fprintf(os.Stderr, ", %s skipped (already present)", humanBytes(rep.SkippedBytes))
	}
	fmt.Fprintln(os.Stderr)
	if logPath != "" {
		fmt.Fprintf(os.Stderr, "transfer log: %s\n", logPath)
	}
	for _, fe := range rep.Errors {
		fmt.Fprintf(os.Stderr, "  error: %s: %s\n", fe.Path, fe.Msg)
	}
	for _, w := range rep.Warnings {
		if f.verbose {
			fmt.Fprintf(os.Stderr, "  warn: %s\n", w)
		}
	}
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "transfer error:", res.Err)
		if rep.Cancelled {
			return 1
		}
		return 2
	}
	if len(rep.Errors) > 0 {
		return 1
	}
	return 0
}

func probeCmd(ctx context.Context, addr string) int {
	start := time.Now()
	sess, err := transportDialProbe(ctx, addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe failed:", err)
		return 2
	}
	defer sess.Close()
	rtt, err := sess.RTT()
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: session ok, ping failed:", err)
		return 0
	}
	fmt.Printf("%s reachable: handshake %.1fms, ping %.1fms, features %#x\n",
		addr, float64(time.Since(start).Microseconds())/1000, float64(rtt.Microseconds())/1000, sess.HS.FeatureBits)
	return 0
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
