package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/engine"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/session"
)

// cmdSend implements `botjim send` / `botjim pull` (legacy alias: `botjim -c`).
// Direct mode connects to a listening server; --via RELAY routes the
// transfer through a relay instead, end-to-end encrypted, the peer running
// `botjim recv`.
func cmdSend(args []string, pull bool) int {
	name := "send"
	if pull {
		name = "pull"
	}
	f := &flags{pull: pull}
	fs := newFlagSet(name,
		fmt.Sprintf("botjim %s [flags] HOST[:port] [PATH...]", name),
		summaryFor(pull))
	fs.StringVar(&f.via, "via", "", "relay through RELAY[:port] instead of connecting directly\n(the peer runs 'botjim recv'; end-to-end encrypted)")
	fs.StringVar(&f.code, "code", "", "relay pairing code (send: generated when omitted)")
	fs.StringVar(&f.token, "token", "", "shared-secret token the server requires")
	fs.StringVar(&f.pass, "pass", "", "encrypt the session with this passphrase\n(the server must use the same --pass)")
	fs.StringVar(&f.limit, "limit", "", "cap the send rate (e.g. 100M, 500K; 0 = unlimited)")
	fs.IntVar(&f.retries, "retries", 0, "auto-reconnect attempts on connection loss\n(each resumes where the last died; backoff 1s,2s,4s…30s)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "plan only: show what would transfer, send nothing")
	addFilterFlags(fs, f)
	addTransferFlags(fs, f)
	addCommonFlags(fs, f)
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if f.via != "" {
		// relay mode: --via carries the address; every positional is a PATH
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "error: --via needs explicit PATHs after the flags")
			fs.Usage()
			return 3
		}
		f.client = f.via // display only; the relay dialer parses it
		f.rest = fs.Args()
	} else {
		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "error: %s needs HOST[:port] (or --via RELAY)\n", name)
			fs.Usage()
			return 3
		}
		f.client = fs.Arg(0)
		f.rest = fs.Args()[1:]
	}

	ctx := signalContext()
	return runClient(ctx, f)
}

func summaryFor(pull bool) string {
	if pull {
		return "Pull RPATHs from a botjim server into --dest.\n" +
			"Quoted patterns are globbed internally (** recurses); no paths\n" +
			"opens the remote browser picker."
	}
	return "Push PATHs to a botjim server. Shell-expanded globs are taken\n" +
		"as-is; quoted patterns are globbed internally (** recurses); no\n" +
		"paths opens the MC-style picker. With --via, the peer runs 'botjim recv'."
}

// runClient performs one send/pull (or opens the browser with no paths).
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
	if f.parallel < 1 || f.parallel > 32 {
		fmt.Fprintln(os.Stderr, "error: --parallel must be 1..32")
		return 3
	}
	if v, err := parseSize(f.limit); err != nil {
		fmt.Fprintln(os.Stderr, "error: --limit:", err)
		return 3
	} else {
		f.limitB = v
	}
	if f.pass != "" && len(f.pass) < 12 {
		fmt.Fprintln(os.Stderr, "warning: --pass shorter than 12 chars is weak (scrypt-stretched but guessable)")
	}

	if f.probe {
		if f.via != "" {
			fmt.Fprintln(os.Stderr, "error: --probe is direct-mode only")
			return 3
		}
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
		if f.via != "" {
			fmt.Fprintln(os.Stderr, "error: --via needs explicit PATHs (the picker is direct-mode only)")
			return 3
		}
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

	if f.via != "" {
		if f.pull {
			fmt.Fprintln(os.Stderr, "error: --via supports send (push) in this release")
			return 3
		}
		code := f.code
		if code == "" {
			code = GenerateCode()
		} else if err := ValidateCode(code); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 3
		}
		fmt.Fprintf(os.Stderr, "relay: %s\ncode:  %s\n", f.via, FormatCode(code))
		fmt.Fprintln(os.Stderr, "      share the code with the receiver out-of-band (they run 'botjim recv')")
		conn, err := Offer(ctx, f.via, code)
		if err != nil {
			fmt.Fprintln(os.Stderr, "relay error:", err)
			return 2
		}
		cfg.Conn = conn
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ui := newClientUI(f, reg, dir == protocol.DirPull)
	if f.via != "" {
		ui.waitKey = false // single-shot: a relay slot carries one transfer
	}
	res := ui.Run(rctx, cancel, func() session.ClientResult {
		return session.RunWithRetries(rctx, cfg, reg, f.retries)
	})
	reg.Emit("info", "", fmt.Sprintf("transfer end: %d files, %d bytes, %d errors",
		res.Report.Files, res.Report.Bytes, len(res.Report.Errors)))

	rep := res.Report
	if f.dryRun {
		printPlan(res.Plan)
	}
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

// printPlan renders the dry-run table: what a real run would move.
func printPlan(rows []engine.PlanRow) {
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "dry-run: nothing to transfer")
		return
	}
	var send, skip, missing int64
	w := 0
	for _, r := range rows {
		if len(r.Path) > w {
			w = len(r.Path)
		}
	}
	if w > 56 {
		w = 56
	}
	for _, r := range rows {
		status := "send"
		detail := fmt.Sprintf("%d/%d chunks", r.Chunks-r.Have, r.Chunks)
		switch r.Status {
		case "skip":
			status = "skip"
			detail = "up to date"
			skip += r.Size
		default:
			missing += r.Size / max64(r.Chunks, 1) * (r.Chunks - r.Have)
			send++
		}
		fmt.Fprintf(os.Stderr, "  %-*s %-4s %s\n", w, truncStr(r.Path, w), status, detail)
	}
	fmt.Fprintf(os.Stderr, "\nplan: %d to send (~%s), %s already present\n",
		send, humanBytes(uint64(missing)), humanBytes(uint64(skip)))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ = attrs.OwnerNone
