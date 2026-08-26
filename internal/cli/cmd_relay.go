package cli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/progress"
	"github.com/ziozzang/botjim/internal/relay"
	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/transport"
	"github.com/ziozzang/botjim/internal/version"
)

// DefaultRelayPort is the broker's default port.
const DefaultRelayPort = 4762

// cmdRelay implements `botjim relay` — the broker. It pairs peers by code
// hash and pipes them; it never sees a code or a plaintext byte.
func cmdRelay(args []string) int {
	var (
		port     int
		bind     string
		ttlMins  float64
		spoolMax string
		spoolMem string
		spoolDir string
		noDisk   bool
	)
	fs := newFlagSet("relay",
		"botjim relay [flags]",
		"Run the pairing broker. Peers connect out to it, pair on a code\n"+
			"(the broker sees only its hash) and then transfer end-to-end\n"+
			"encrypted — the relay shuffles opaque bytes.")
	fs.IntVar(&port, "p", DefaultRelayPort, "port to listen on")
	fs.StringVar(&bind, "bind", "", "bind address (default: all interfaces)")
	fs.Float64Var(&ttlMins, "wait", 10, "minutes an unmatched offer waits before dropping")
	fs.StringVar(&spoolMax, "spool-max", "2G", "per-direction transfer buffer (e.g. 512M, 2G);\nsenders can run ahead of receivers within this budget")
	fs.StringVar(&spoolMem, "spool-mem", "256M", "bytes kept in memory before the spool spills to disk")
	fs.StringVar(&spoolDir, "spool-dir", "", "spill directory for spooled transfers (default: system temp)")
	fs.BoolVar(&noDisk, "no-spool-disk", false, "never touch disk: buffer in memory only")
	fs.Bool("no-tui", false, "unused; the relay logs to stdout")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "error: relay takes no positional arguments")
		return 3
	}
	addr := bind
	if addr == "" {
		addr = fmt.Sprintf(":%d", port)
	} else if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	ln, err := transport.Listen(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay error:", err)
		return 2
	}
	b := relay.NewBroker()
	if ttlMins > 0 {
		b.TTL = time.Duration(ttlMins * float64(time.Minute))
	}
	if v, err := parseSize(spoolMax); err != nil {
		fmt.Fprintln(os.Stderr, "error: --spool-max:", err)
		return 3
	} else if v > 0 {
		b.SpoolMax = v
	}
	if v, err := parseSize(spoolMem); err != nil {
		fmt.Fprintln(os.Stderr, "error: --spool-mem:", err)
		return 3
	} else if v > 0 {
		b.SpoolMem = v
	}
	if noDisk {
		b.SpoolDir = "" // memory-only buffering
	} else if spoolDir != "" {
		b.SpoolDir = spoolDir
	}
	b.Logger = func(f string, a ...any) {
		fmt.Printf("relay: "+f+"\n", a...)
	}
	fmt.Fprintf(os.Stderr, "botjim %s relay on %s — pairs peers, never sees content\n", version.Version, addr)
	ctx := signalContext()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	if err := b.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "relay error:", err)
		return 2
	}
	return 0
}

// cmdRecv implements `botjim recv` — claim a relay slot and receive the
// pushed files into --dest, playing the server role over the paired pipe.
func cmdRecv(args []string) int {
	f := &flags{}
	fs := newFlagSet("recv",
		"botjim recv [flags] --code CODE",
		"Claim a relay slot and receive what the sender pushes into --dest.\n"+
			"Runs the full receiver (attributes, resume, jail) over the\n"+
			"end-to-end encrypted pairing — the relay sees only ciphertext.")
	fs.StringVar(&f.code, "code", "", "pairing code from the sender (required)")
	fs.StringVar(&f.via, "via", "", "relay address RELAY[:port] (default port 4762)")
	fs.StringVar(&f.dest, "dest", ".", "directory to receive into (the local jail)")
	fs.StringVar(&f.owners, "map-owners", "none", "ownership policy for received files:\nnone | numeric | name")
	fs.IntVar(&f.parallel, "parallel", 8, "max data streams (caps the sender's request)")
	fs.BoolVar(&f.noFsync, "no-fsync", false, "skip fsync before finalize")
	addCommonFlags(fs, f)
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if f.code == "" {
		fmt.Fprintln(os.Stderr, "error: --code is required (the sender prints one)")
		return 3
	}
	if err := relay.ValidateCode(f.code); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	via := f.via
	if via == "" {
		fmt.Fprintln(os.Stderr, "error: --via RELAY is required")
		return 3
	}
	if f.parallel < 1 || f.parallel > 64 {
		fmt.Fprintln(os.Stderr, "error: --parallel must be 1..64")
		return 3
	}
	owners, err := ownerPolicy(f.owners)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}

	ctx := signalContext()
	fmt.Fprintf(os.Stderr, "waiting for the sender through %s…\n", via)
	conn, err := relay.Take(ctx, via, f.code)
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay error:", err)
		return 2
	}

	if err := os.MkdirAll(f.dest, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	root, err := fsutil.ResolveRoot(f.dest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	srv := session.NewServer(session.ServerConfig{
		Root:        root,
		Parallel:    f.parallel,
		Fsync:       !f.noFsync,
		OwnerPolicy: owners,
		AllowPush:   true,
	})
	reg := progress.New()
	logPath := openTransferLog(f, reg)
	if logPath != "" {
		defer closeTransferLog()
	}
	reg.Emit("info", "", "relay pairing established")
	srv.ServeConn(conn)
	reg.Emit("info", "", "relay transfer finished")
	fmt.Fprintf(os.Stderr, "done — files are under %s\n", root)
	if logPath != "" {
		fmt.Fprintf(os.Stderr, "transfer log: %s\n", logPath)
	}
	return 0
}

// parseSize accepts "2G", "512M", "4K" or a plain byte count.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'G':
		mult, s = 1<<30, s[:len(s)-1]
	case 'M':
		mult, s = 1<<20, s[:len(s)-1]
	case 'K':
		mult, s = 1<<10, s[:len(s)-1]
	case 'B':
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}
