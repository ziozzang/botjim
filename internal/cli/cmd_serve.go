package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/ziozzang/botjim/internal/transport"
	"github.com/ziozzang/botjim/internal/version"
	"github.com/ziozzang/botjim/internal/webfs"
)

// cmdServe implements `botjim serve` — plain HTTP with Range support over
// a directory: the bridge for browsers/curl/HF downloaders.
func cmdServe(args []string) int {
	var (
		port int
		bind string
		root string
	)
	fs := newFlagSet("serve", "botjim serve [flags] [DIR]",
		"Serve DIR over HTTP with Range support — lets any browser or\ndownloader (curl, wget, HF-style tools) consume the directory\nwithout botjim on the other end.")
	fs.IntVar(&port, "p", 8080, "port to listen on")
	fs.StringVar(&bind, "bind", "", "bind address (default: all interfaces)")
	fs.StringVar(&root, "root", ".", "directory to serve (also positional)")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fmt.Fprintln(os.Stderr, "error: not a directory:", root)
		return 3
	}
	addr := bind
	if addr == "" {
		addr = fmt.Sprintf(":%d", port)
	} else if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	ln, err := transport.Listen(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "botjim %s serving %s on http://%s (Range supported)\n", version.Version, root, ln.Addr())
	ctx := signalContext()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	if err := webfs.Serve(ln, root); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	return 0
}
