package cli

import (
	"fmt"
	"os"
	"strings"
)

// The command table completions are generated from.
var completionCommands = []struct{ name, opts string }{
	{"server", "--bind --root --port --map-owners --parallel --no-fsync --no-suid --no-tui --token --pass --cloak --discover --metrics -q -v --log-file --audit --audit-file"},
	{"send", "--via --code --port --dest --compress --zstd-level --parallel --map-owners --no-xattr --no-sparse --devices --one-file-system --resume --no-fsync --no-suid --stop-on-error --probe --token --pass --cloak --limit --retries --dry-run --exclude --include --json --delete --no-tui -q -v --log-file --audit --audit-file"},
	{"pull", "--port --dest --compress --zstd-level --parallel --map-owners --no-xattr --no-sparse --devices --one-file-system --resume --no-fsync --no-suid --stop-on-error --probe --token --pass --cloak --limit --retries --dry-run --exclude --include --json --delete --no-tui -q -v --log-file --audit --audit-file"},
	{"relay", "--bind --port --wait --spool-max --spool-mem --spool-dir --no-spool-disk"},
	{"recv", "--via --code --dest --map-owners --parallel --no-fsync --no-suid --no-tui -q -v --log-file --audit --audit-file"},
	{"swarm seed", "--tracker --code --port --name"},
	{"swarm join", "--tracker --code --spec --dest --parallel --serve --http --verify-key"},
	{"swarm track", "--port"},
	{"swarm verify", ""},
	{"swarm keygen", "--key"},
	{"sync push", "--dir --watch --debounce-ms --sweep-sec"},
	{"sync pull", "--dest"},
	{"peers", "--wait --json"},
	{"serve", "--bind --port --root"},
	{"update", "--check --force --version --repo"},
	{"audit verify", ""},
	{"audit tail", ""},
	{"config path", ""},
	{"config show", ""},
	{"config publish", "--out --key"},
	{"endpoints", ""},
	{"pipe send", "--stdin --name"},
	{"pipe cat", ""},
	{"version", ""},
	{"help", ""},
}

// cmdCompletion implements `botjim completion bash|zsh|fish`.
func cmdCompletion(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, `usage: botjim completion bash|zsh|fish > /etc/profile.d/botjim.sh
(then `+"`source`"+` the file or restart the shell)`)
		return 3
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
		return 0
	case "zsh":
		fmt.Print(zshCompletion)
		return 0
	case "fish":
		fmt.Print(fishCompletion)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown shell %q (bash|zsh|fish)\n", args[0])
		return 3
	}
}

// flatFlags expands the command table into --opt lines for script emitters.
func flatFlags() string {
	var sb strings.Builder
	seen := map[string]bool{}
	for _, c := range completionCommands {
		for _, o := range strings.Fields(c.opts) {
			if !seen[o] {
				seen[o] = true
				sb.WriteString(" --")
				sb.WriteString(strings.TrimLeft(o, "-"))
			}
		}
	}
	return sb.String()
}
