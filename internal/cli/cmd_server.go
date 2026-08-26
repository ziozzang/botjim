package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/attrs"
	"github.com/ziozzang/botjim/internal/discover"
	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/session"
	"github.com/ziozzang/botjim/internal/transport"
	"github.com/ziozzang/botjim/internal/version"
)

// cmdServer implements `botjim server` (alias: the legacy `botjim -s`).
func cmdServer(args []string) int {
	f := &flags{}
	fs := newFlagSet("server",
		"botjim server [flags]",
		"Wait for transfers. Everything clients push lands under --root\n"+
			"(the jail); pulls read from it too. Live dashboard on a terminal.")
	fs.IntVar(&f.port, "p", DefaultPort, "port to listen on")
	fs.StringVar(&f.bind, "bind", "", "bind address (default: all interfaces)")
	fs.StringVar(&f.root, "root", ".", "root directory — the jail for all transfers")
	fs.StringVar(&f.owners, "map-owners", "none", "ownership policy for received files:\nnone | numeric | name")
	fs.IntVar(&f.parallel, "parallel", 8, "max data streams per connection (caps client requests)")
	fs.BoolVar(&f.noFsync, "no-fsync", false, "skip fsync before finalize")
	fs.StringVar(&f.token, "token", "", "require this shared-secret token from clients")
	fs.StringVar(&f.pass, "pass", "", "require record-layer encryption with this passphrase\n(clients must use the same --pass)")
	fs.BoolVar(&f.discover, "discover", false, "announce this server on the LAN multicast group\n('botjim peers' lists it; opt-in — reveals name/addr/root/version)")
	addCommonFlags(fs, f)
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "error: server takes no positional arguments")
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

	applyConfigFromDefaults(f, args)
	ctx := signalContext()
	if err := runServer(ctx, f, owners); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 2
	}
	return 0
}

// runServer starts the listener and dashboard.
func runServer(ctx context.Context, f *flags, owners attrs.OwnerPolicy) error {
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
		Token:       f.token,
		Pass:        f.pass,
		Cloak:       f.cloak,
	})
	fmt.Fprintf(os.Stderr, "botjim %s serving %s on %s (plain V1 — use on trusted networks)\n", version.Version, root, bind)
	if f.discover {
		advPort := f.port
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.Port > 0 {
			advPort = ta.Port
		}
		host, _ := os.Hostname()
		if host == "" {
			host = "botjim"
		}
		go discover.Announce(ctx, discover.Beacon{Name: host, Port: advPort, Root: root, Ver: version.Version}, 3*time.Second)
		fmt.Fprintf(os.Stderr, "announcing on the LAN: botjim peers\n")
	}

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
