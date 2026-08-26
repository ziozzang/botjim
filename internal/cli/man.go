package cli

import (
	"fmt"
	"os"
	"strings"
)

// cmdMan implements `botjim man` — writes a botjim(1) roff page to
// stdout (feed to `man -l -` or install to man1/).
func cmdMan(args []string) int {
	var sb strings.Builder
	sb.WriteString(".TH BOTJIM 1 \"2026\" \"botjim\" \"User Commands\"\n")
	sb.WriteString(".SH NAME\nbotjim \\- files, ferried intact\n")
	sb.WriteString(".SH SYNOPSIS\n.B botjim\n.I command\n.RI [ flags ]\n.RI [ args ...]\n")
	sb.WriteString(".SH COMMANDS\n")
	for _, c := range completionCommands {
		if c.name == "" || c.name == "help" || c.name == "version" {
			continue
		}
		sb.WriteString(".TP\n.B " + c.name + "\n")
		switch c.name {
		case "server":
			sb.WriteString("Wait for transfers (default port 4761); everything lands under --root (the jail).\n")
		case "send":
			sb.WriteString("Push PATHs to a server, or through a relay with --via.\n")
		case "pull":
			sb.WriteString("Pull RPATHs from a server into --dest.\n")
		case "relay":
			sb.WriteString("Run the pairing broker for relay mode (default port 4762).\n")
		case "recv":
			sb.WriteString("Claim a relay slot and receive into --dest.\n")
		case "swarm seed":
			sb.WriteString("Hash an artifact, serve chunks, announce to a tracker.\n")
		case "swarm join":
			sb.WriteString("Assemble an artifact from the swarm into --dest.\n")
		case "swarm track":
			sb.WriteString("Run the swarm tracker (room membership).\n")
		case "swarm verify":
			sb.WriteString("Re-hash a directory and print its swarm ID.\n")
		case "serve":
			sb.WriteString("Serve a directory over HTTP with Range support.\n")
		case "update":
			sb.WriteString("Self-update from GitHub Releases (SHA256SUMS-verified).\n")
		case "audit verify":
			sb.WriteString("Verify a hash-chained audit journal.\n")
		case "audit tail":
			sb.WriteString("Print the last N audit entries.\n")
		case "config path":
			sb.WriteString("Print the config file location.\n")
		case "config show":
			sb.WriteString("Print the loaded config.\n")
		}
	}
	sb.WriteString(".SH SECURITY\nDirect mode is plaintext unless --pass is set on both sides (X25519 + ChaCha20\\-Poly1305 record layer). --token requires a shared secret. Relay and swarm links are end\\-to\\-end encrypted by construction; the broker and tracker see only ciphertext and metadata.\n")
	sb.WriteString(".SH FILES\n.IR ~/.botjim/config.json \\(en default flag values\n.br\n.IR ~/.cache/botjim/transfers.log \\(en plain transfer log\n.br\n.IR ~/.cache/botjim/audit.log \\(en hash\\-chained audit journal\n")
	sb.WriteString(".SH SEE ALSO\nFull documentation: https://github.com/ziozzang/botjim (README.md, ARCHITECTURE.md)\n")
	fmt.Print(sb.String())
	return 0
}

var _ = os.Stdout
