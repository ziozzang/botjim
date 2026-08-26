// Package cli parses botjim's command line and dispatches to the server,
// send/pull, update or version subcommands. Every command has its own
// --help; the historical -s/-c flag forms still work as aliases.
//
// Usage:
//
//	botjim server [flags]                        wait for transfers (dashboard)
//	botjim send HOST[:port] [PATH...]            push PATHs to the server
//	botjim pull HOST[:port] [RPATH...]           pull RPATHs from the server
//	botjim send HOST[:port]                      no paths: MC-style picker
//	botjim update [--check] [--force]            self-update from GitHub
//	botjim version
//	botjim help [command]
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

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/version"
)

// DefaultPort is botjim's TCP port.
const DefaultPort = 4761

// flags is one parsed invocation. Commands fill the subset they own; the
// shared transfer fields are registered by addTransferFlags.
type flags struct {
	server    bool
	client    string // host[:port] (send/pull target)
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
	via       string // relay address for --via transfers
	code      string // relay pairing code
	token     string // shared-secret auth
	pass      string // passphrase record-layer encryption
	limit     string // bandwidth cap (e.g. 100M)
	limitB    int64  // parsed
	retries   int    // auto-reconnect attempts
	audit     bool
	auditFile string
	cloak     string
	jsonOut   bool
	deleteDst bool
	exclude   []string // walker exclusions
	include   []string // walker inclusions (when set, only these)
	dryRun    bool
}

// stringList is a repeatable string flag (--exclude a --exclude b).
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// addFilterFlags registers --exclude/--include.
func addFilterFlags(fs *flag.FlagSet, f *flags) {
	fs.Var((*stringList)(&f.exclude), "exclude", "skip paths matching this glob (repeatable;\na bare name matches any component, 'a/b' matches the whole path)")
	fs.Var((*stringList)(&f.include), "include", "transfer ONLY paths matching this glob (repeatable)")
}

// newFlagSet builds a command's parser with a usage header.
func newFlagSet(name, usageLine, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s\n\n%s\n\n", usageLine, summary)
		fs.PrintDefaults()
	}
	return fs
}

// addCommonFlags registers flags every command accepts.
func addCommonFlags(fs *flag.FlagSet, f *flags) {
	fs.BoolVar(&f.noTUI, "no-tui", false, "disable the TUI (single-line progress)")
	fs.BoolVar(&f.quiet, "q", false, "quiet (errors only)")
	fs.BoolVar(&f.verbose, "v", false, "verbose")
	fs.StringVar(&f.logFile, "log-file", "", "append the transfer log to this file\n(default ~/.cache/botjim/transfers.log)")
	fs.BoolVar(&f.audit, "audit", false, "record a tamper-evident hash-chained audit journal")
	fs.BoolVar(&f.jsonOut, "json", false, "emit NDJSON transfer events on stdout (for scripts/CI)")
	fs.BoolVar(&f.deleteDst, "delete", false, "mirror: delete destination files missing from the manifest (jail-scoped)")
	fs.StringVar(&f.cloak, "cloak", "", "disguise the session as HTTP/websocket traffic on this path\n(e.g. /cdn/data; both sides need the same path)")
	fs.StringVar(&f.auditFile, "audit-file", "", "audit journal path (default ~/.cache/botjim/audit.log)")
}

// addTransferFlags registers the flags send/pull (and the legacy client) accept.
func addTransferFlags(fs *flag.FlagSet, f *flags) {
	fs.IntVar(&f.port, "p", DefaultPort, "port to connect to")
	fs.StringVar(&f.dest, "dest", ".", "destination directory (pull)")
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
	fs.BoolVar(&f.probe, "probe", false, "probe the server (RTT/version) and exit")
}

// Main runs one invocation and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		topLevelUsage()
		return 3
	}
	switch args[0] {
	case "server":
		return cmdServer(args[1:])
	case "relay":
		return cmdRelay(args[1:])
	case "swarm":
		return cmdSwarm(args[1:])
	case "audit":
		return cmdAudit(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "completion":
		return cmdCompletion(args[1:])
	case "man":
		return cmdMan(args[1:])
	case "recv":
		return cmdRecv(args[1:])
	case "send":
		return cmdSend(args[1:], false)
	case "pull":
		return cmdSend(args[1:], true)
	case "update":
		return updateCmd(args[1:])
	case "version", "--version", "-v":
		if args[0] == "version" && len(args) > 1 {
			fmt.Fprintln(os.Stderr, "usage: botjim version")
			return 3
		}
		fmt.Printf("botjim %s (%s/%s)\nhttps://github.com/%s\n", version.Version, osName(), archName(), version.Repo)
		return 0
	case "help", "--help", "-h":
		return helpCmd(args[1:])
	case "-s": // legacy alias from v0.1.x
		return cmdServer(args[1:])
	case "-c": // legacy alias from v0.1.x
		pull := false
		var rest []string
		for _, a := range args[1:] {
			if a == "--pull" {
				pull = true
				continue
			}
			rest = append(rest, a)
		}
		return cmdSend(rest, pull)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		topLevelUsage()
		return 3
	}
}

func topLevelUsage() {
	fmt.Fprint(os.Stderr, `botjim — files, ferried intact

usage:
  botjim server [flags]                        wait for transfers (dashboard)
  botjim send HOST[:port] [PATH...]            push PATHs to the server
  botjim pull HOST[:port] [RPATH...]           pull RPATHs from the server
  botjim send HOST[:port]                      no paths: MC-style picker

  botjim swarm seed/join/track/verify         token-joined swarm distribution
  botjim audit verify|tail FILE               hash-chain journal reader
  botjim config path|show                     ~/.botjim/config.json defaults
  botjim serve [DIR]                          HTTP+Range bridge for any downloader
  botjim completion bash|zsh|fish             shell completions
  botjim man                                  botjim(1) roff page
  botjim relay                                 run the pairing broker
  botjim send --via RELAY PATH...              push through a relay (prints a code)
  botjim recv --via RELAY --code CODE          receive a relay push

  botjim update [--check] [--force]            self-update from GitHub
  botjim version

Each command takes --help for its full option list.
(-s / -c from earlier releases still work as aliases.)

`)
}

func helpCmd(args []string) int {
	if len(args) == 0 {
		topLevelUsage()
		return 0
	}
	switch args[0] {
	case "server":
		cmdServer([]string{"--help"})
	case "send":
		cmdSend([]string{"--help"}, false)
	case "relay":
		cmdRelay([]string{"--help"})
	case "swarm":
		cmdSwarm([]string{"--help"})
	case "recv":
		cmdRecv([]string{"--help"})
	case "pull":
		cmdSend([]string{"--help"}, true)
	case "update":
		updateCmd([]string{"--help"})
	default:
		fmt.Fprintf(os.Stderr, "no help for %q\n", args[0])
		topLevelUsage()
		return 3
	}
	return 0
}

// parseHelp handles flag.ErrHelp: usage was already printed by the FlagSet.
func parseHelp(err error) bool { return err == flag.ErrHelp }

// signalContext sets up SIGINT/SIGTERM handling with the double-interrupt
// hard exit shared by every long-running command.
func signalContext() context.Context {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	return ctx
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
		return 1, nil
	case "lz4":
		return 2, nil
	case "none":
		return 0, nil
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
