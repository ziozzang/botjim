package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/ziozzang/botjim/internal/attrs"
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

var _ = attrs.OwnerNone
