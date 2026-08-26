package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ziozzang/botjim/internal/discover"
)

// cmdPeers implements `botjim peers` — listen on the LAN discovery
// group for a few seconds and list the botjim servers announcing there
// (servers opt in with --discover).
func cmdPeers(args []string) int {
	var (
		wait   time.Duration
		asJSON bool
	)
	fs := newFlagSet("peers", "botjim peers [--wait DURATION]",
		"Discover botjim servers on the local network (servers must run\nwith --discover). Prints NAME ADDRESS VERSION ROOT, one per line.")
	fs.DurationVar(&wait, "wait", 3*time.Second, "how long to listen")
	fs.BoolVar(&asJSON, "json", false, "emit one JSON object per peer")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	fmt.Fprintf(os.Stderr, "listening for %s…\n", wait)
	peers, err := discover.Listen(signalContext(), wait)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "no botjim servers found (they must run with --discover)")
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, p := range peers {
			_ = enc.Encode(p)
		}
		return 0
	}
	fmt.Printf("%-16s %-24s %-8s %s\n", "NAME", "ADDRESS", "VERSION", "ROOT")
	for _, p := range peers {
		root := p.Root
		if root == "" {
			root = "-"
		}
		fmt.Printf("%-16s %-24s %-8s %s\n", truncStr(p.Name, 16), p.Addr, p.Ver, root)
	}
	return 0
}
