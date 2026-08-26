package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/relay"
	"github.com/ziozzang/botjim/internal/transport"
	"github.com/ziozzang/botjim/internal/version"
)

// cmdSwarm implements `botjim swarm seed|join|track` — token-joined,
// chunk-level distribution for immutable artifacts (LLM models, datasets).
//
// The swarm token is the single credential: it derives the tracker room
// (the tracker sees only SHA-256(token), never the token) and keys every
// peer↔peer link (the e2ee record layer — a peer without the token
// cannot even complete the handshake).
func cmdSwarm(args []string) int {
	if len(args) == 0 {
		swarmUsage()
		return 3
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "seed":
		return swarmSeed(rest)
	case "join":
		return swarmJoin(rest)
	case "track":
		return swarmTrack(rest)
	case "verify":
		return swarmVerify(rest)
	case "keygen":
		return swarmKeygen(rest)
	case "--help", "-h", "help":
		swarmUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown swarm subcommand %q\n", sub)
		swarmUsage()
		return 3
	}
}

func swarmUsage() {
	fmt.Fprint(os.Stderr, `usage:
  botjim swarm seed  [flags] PATH...          hash, serve and announce an artifact
  botjim swarm join  [flags] --code CODE      assemble from the swarm into --dest
  botjim swarm track [flags]                  run the tracker (room membership)
  botjim swarm verify PATH                    re-hash and print the swarm ID
  botjim swarm keygen [flags]                 create the ed25519 spec-signing key

The token authenticates the tracker room AND encrypts every peer link;
share it out-of-band along with the tracker address. The artifact's
swarm ID (printed by seed, stored in <name>.swarm.json) pins the bytes.
`)
}

// ---- seed ----

func swarmSeed(args []string) int {
	var (
		tracker string
		token   string
		port    int
		name    string
		keyPath string
	)
	fs := newFlagSet("swarm seed", "botjim swarm seed [flags] PATH...",
		"Hash PATH into a swarm spec, serve chunks, announce to the tracker.\nPrints the swarm ID and writes <name>.swarm.json beside the data.")
	fs.StringVar(&tracker, "tracker", "", "tracker address HOST[:4763] (omit to seed without a tracker)")
	fs.StringVar(&token, "code", "", "swarm token (generated when omitted; required for joins)")
	fs.IntVar(&port, "p", 0, "port to serve chunks on (0 = ephemeral; peers need to reach it)")
	fs.StringVar(&name, "name", "", "artifact name for the descriptor (default: first path's base)")
	fs.StringVar(&keyPath, "key", "", "sign the descriptor with this ed25519 key\n(default ~/.botjim/keys/swarm-ed25519 when it exists;\ncreated fresh by 'botjim swarm keygen')")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: swarm seed needs PATH...")
		return 3
	}
	roots := fs.Args()
	if name == "" {
		name = filepath.Base(roots[0])
	}
	if token == "" {
		token = relay.GenerateCode()
	} else if err := relay.ValidateCode(token); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}

	spec, err := relay.BuildSwarmSpec(context.Background(), roots, name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	desc := relay.SwarmManifestFrom(spec, tracker)
	if keyPath == "" {
		keyPath = relay.DefaultSwarmKeyPath() // sign silently only if it exists
	}
	if _, err := os.Stat(keyPath); err == nil {
		priv, kerr := relay.LoadSwarmKey(keyPath)
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", kerr)
			return 2
		}
		desc.Sign(priv)
	} else if flagPresent(args, "key") {
		// --key explicitly pointed somewhere: create it rather than ship unsigned
		priv, kerr := relay.GenerateSwarmKey(keyPath)
		if kerr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", kerr)
			return 2
		}
		desc.Sign(priv)
	}
	descPath, err := relay.WriteSwarmManifest(filepath.Dir(roots[0]), name, desc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "swarm id: %s\n", spec.SpecHash())
	fmt.Fprintf(os.Stderr, "files:   %d (%s)\n", len(spec.Files), humanBytes(uint64(spec.TotalBytes())))
	fmt.Fprintf(os.Stderr, "code:    %s\n", relay.FormatCode(token))
	fmt.Fprintf(os.Stderr, "spec:    %s\n", descPath)
	if desc.Signed() {
		fmt.Fprintf(os.Stderr, "signed:  %s…\n", desc.PubKey[:24])
		fmt.Fprintln(os.Stderr, "         (joiners pin it with --verify-key)")
	}

	// serve chunks (root = the common ancestor of the paths)
	root := filepath.Dir(roots[0])
	bind := fmt.Sprintf(":%d", port)
	ln, err := transport.Listen(bind)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "serving chunks on %s (Ctrl-C to stop)\n", ln.Addr())

	ctx := signalContext()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	if tracker != "" {
		go announceLoop(ctx, tracker, token, spec, ln.Addr().String())
	}
	if err := relay.ServePeer(ctx, ln, spec, root, token); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	return 0
}

func announceLoop(ctx context.Context, tracker, token string, spec *relay.SwarmSpec, self string) {
	roomHave := strings.Repeat("ff", len(spec.Files))
	for {
		if ctx.Err() != nil {
			return
		}
		relay.AnnounceOnce(ctx, tracker, token, spec.SpecHash(), self, roomHave, true)
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

// ---- join ----

func swarmJoin(args []string) int {
	var (
		tracker   string
		token     string
		spec      string
		dest      string
		par       int
		serve     string
		verifyKey string
	)
	fs := newFlagSet("swarm join", "botjim swarm join [flags] --code CODE",
		"Assemble the artifact into --dest: fetch missing chunks from any\npeer (seed or other joiners), verify each file, resume on re-run.")
	fs.StringVar(&tracker, "tracker", "", "tracker address HOST[:4763] (required)")
	fs.StringVar(&token, "code", "", "swarm token from the seed (required)")
	fs.StringVar(&spec, "spec", "", "path to <name>.swarm.json from the seed (required)")
	fs.StringVar(&dest, "dest", ".", "directory to assemble into")
	fs.IntVar(&par, "parallel", 4, "concurrent chunk fetches")
	fs.StringVar(&serve, "serve", ":0", "also serve verified chunks to other joiners\n(the mesh ramp: peers on your LAN fetch from you; \"\" disables)")
	fs.StringVar(&verifyKey, "verify-key", "", "require a valid ed25519 signature by this public key\n(hex, printed by 'swarm seed'/'swarm keygen') on the spec")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if tracker == "" || token == "" || spec == "" {
		fmt.Fprintln(os.Stderr, "error: --tracker, --code and --spec are all required")
		return 3
	}
	if err := relay.ValidateCode(token); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	b, err := os.ReadFile(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 3
	}
	var desc relay.SwarmManifest
	if err := json.Unmarshal(b, &desc); err != nil {
		fmt.Fprintln(os.Stderr, "error: bad spec:", err)
		return 3
	}
	if err := desc.Verify(verifyKey); err != nil {
		fmt.Fprintln(os.Stderr, "error: spec signature:", err)
		return 2
	}
	if desc.Signed() && verifyKey == "" {
		fmt.Fprintf(os.Stderr, "note: spec is signed by %s… (pin it with --verify-key for closed-loop trust)\n", desc.PubKey[:16])
	}
	// the descriptor embeds every file's size and hash — the joiner
	// needs nothing beside it
	full := desc.ToSpec("")
	if full == nil || len(full.Files) == 0 {
		fmt.Fprintln(os.Stderr, "error: descriptor carries no files")
		return 3
	}

	ctx := signalContext()
	j := &relay.Joiner{
		TrackerAddr: tracker,
		Token:       token,
		Spec:        full,
		Dest:        dest,
		Parallel:    par,
		ServeAddr:   serve,
		OnProgress: func(done, total int64) {
			fmt.Fprintf(os.Stderr, "\r%6.1f%% %s/%s",
				float64(done)/float64(total)*100, humanBytes(uint64(done)), humanBytes(uint64(total)))
		},
	}
	if err := j.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "\nswarm join:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "\ndone — verified %d files (%s) under %s\n",
		len(full.Files), humanBytes(uint64(full.TotalBytes())), dest)
	return 0
}

// ---- track ----

func swarmTrack(args []string) int {
	var port int
	fs := newFlagSet("swarm track", "botjim swarm track [flags]",
		"Run the swarm tracker: room membership keyed by SHA-256(token).\nSees only addresses and chunk bitmaps, never tokens or content.")
	fs.IntVar(&port, "p", relay.DefaultSwarmPort, "port to listen on")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	ln, err := transport.Listen(fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "botjim %s swarm tracker on %s\n", version.Version, ln.Addr())
	ctx := signalContext()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	tp := &relay.TrackerProtocol{T: relay.NewTracker()}
	if err := tp.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	return 0
}

// ---- verify ----

func swarmVerify(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: botjim swarm verify PATH...")
		return 3
	}
	spec, err := relay.BuildSwarmSpec(context.Background(), args, "verify")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	for _, f := range spec.Files {
		fmt.Printf("%s  %10s  %s\n", f.SHA[:16], humanBytes(uint64(f.Size)), f.Path)
	}
	fmt.Printf("swarm id: %s\n", spec.SpecHash())
	return 0
}

// ---- keygen ----

// swarmKeygen creates (or reprints) the ed25519 key that signs swarm
// descriptors; the public half is what joiners pass as --verify-key.
func swarmKeygen(args []string) int {
	var keyPath string
	fs := newFlagSet("swarm keygen", "botjim swarm keygen [--key PATH]",
		"Create the ed25519 spec-signing key and print its public half.\n'swarm seed' signs automatically when this key exists.")
	fs.StringVar(&keyPath, "key", relay.DefaultSwarmKeyPath(), "key path")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	if _, err := os.Stat(keyPath); err == nil {
		priv, err := relay.LoadSwarmKey(keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		pub, _ := priv.Public().(ed25519.PublicKey)
		fmt.Printf("key exists: %s\npublic key: %s\n", keyPath, hex.EncodeToString(pub))
		return 0
	}
	priv, err := relay.GenerateSwarmKey(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	fmt.Printf("created:   %s\npublic key: %s\nshare the public key with joiners (--verify-key)\n", keyPath, hex.EncodeToString(pub))
	return 0
}
