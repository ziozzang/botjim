package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// cmdEndpoints implements `botjim endpoints` — list named endpoints from
// the config (and, with --discover, the LAN).
func cmdEndpoints(args []string) int {
	cfg := loadConfigQuiet()
	if len(cfg.Endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "no endpoints in", ConfigPath())
		fmt.Fprintln(os.Stderr, `add one:
  { "endpoints": { "lab1": { "addr": "10.0.0.5:4761", "token": "..." } } }`)
		return 0
	}
	names := make([]string, 0, len(cfg.Endpoints))
	for n := range cfg.Endpoints {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e := cfg.Endpoints[n]
		sec := ""
		if e.Token != "" {
			sec += " token"
		}
		if e.Pass != "" {
			sec += " pass"
		}
		if e.Cloak != "" {
			sec += " cloak=" + e.Cloak
		}
		fmt.Printf("%-16s %s%s\n", n, e.Addr, sec)
	}
	return 0
}

var _ = json.Marshal
