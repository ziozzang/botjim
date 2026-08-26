package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ziozzang/botjim/internal/audit"
)

// cmdAudit implements `botjim audit verify|tail` — the hash-chained
// journal's reader. verify walks the chain and reports the intact prefix;
// tail prints the last entries.
func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprint(os.Stderr, `usage:
  botjim audit verify FILE        check the hash chain, report the intact prefix
  botjim audit tail FILE [N]      print the last N entries (default 20)
`)
		if len(args) >= 1 {
			return 0
		}
		return 3
	}
	switch args[0] {
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: botjim audit verify FILE")
			return 3
		}
		n, brk, err := audit.Verify(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		if brk == "" {
			fmt.Printf("OK: %d entries, chain intact\n", n)
			return 0
		}
		fmt.Printf("BROKEN after %d entries: %s\n", n, brk)
		return 1
	case "tail":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: botjim audit tail FILE [N]")
			return 3
		}
		n := 20
		if len(args) >= 3 {
			if v, err := strconv.Atoi(args[2]); err == nil && v > 0 {
				n = v
			}
		}
		entries, err := audit.ReadAll(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		start := len(entries) - n
		if start < 0 {
			start = 0
		}
		for _, e := range entries[start:] {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand %q\n", args[0])
		return 3
	}
}
