package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/fsutil"
	"github.com/ziozzang/botjim/internal/session"
)

// cmdPipe implements the tar|netcat drop-in:
//
//	botjim pipe send --stdin NAME HOST     stdin → remote file NAME
//	botjim pipe cat HOST PATH              remote file → stdout
//
// stdin is spooled to a temp file first so the transfer itself keeps the
// full engine (delta, resume, verification) rather than a lossy stream.
func cmdPipe(args []string) int {
	if len(args) < 1 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		pipeUsage()
		if len(args) >= 1 {
			return 0
		}
		return 3
	}
	switch args[0] {
	case "send":
		return pipeSend(args[1:])
	case "cat":
		return pipeCat(args[1:])
	default:
		pipeUsage()
		return 3
	}
}

func pipeUsage() {
	fmt.Fprint(os.Stderr, `usage:
  tar c dir | botjim pipe send --stdin NAME HOST    stdin → remote NAME (engine-backed)
  botjim pipe cat HOST PATH                          remote file → stdout
`)
}

// pipeSend: stdin → temp spool → send --stdin NAME.
func pipeSend(args []string) int {
	var (
		name  string
		stdin bool
	)
	fs := newFlagSet("pipe send", "… | botjim pipe send --stdin NAME HOST",
		"Read stdin fully, then transfer it as remote file NAME.\nSpooled to a temp file first so resume/verification apply.")
	fs.BoolVar(&stdin, "stdin", true, "read stdin (default; kept for symmetry)")
	fs.StringVar(&name, "name", "", "remote file name (default: stdin-<timestamp>)")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "error: pipe send needs HOST [NAME] (positional)")
		return 3
	}
	host := rest[len(rest)-1] // HOST is the last positional
	if name == "" {
		if len(rest) >= 2 {
			name = rest[0] // `pipe send --stdin NAME HOST` form
		} else {
			name = "stdin-" + tsNow()
		}
	}
	// reject a bad NAME before swallowing all of stdin
	if err := fsutil.RelOK(filepath.ToSlash(name)); err != nil {
		fmt.Fprintf(os.Stderr, "error: bad name %q: %v\n", name, err)
		return 3
	}
	tmp, err := os.CreateTemp("", "botjim-pipe-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, os.Stdin); err != nil {
		tmp.Close()
		fmt.Fprintln(os.Stderr, "error reading stdin:", err)
		return 2
	}
	tmp.Close()
	fi, _ := os.Stat(tmpName)
	fmt.Fprintf(os.Stderr, "spooled %s → sending as %s\n", humanBytes(uint64(fi.Size())), name)

	// stage as <dir>/<name> so the manifest base — and the remote landing
	// path — is exactly NAME
	stage, err := os.MkdirTemp("", "botjim-pipe-stage-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	defer os.RemoveAll(stage)
	dst := filepath.Join(stage, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if err := os.Rename(tmpName, dst); err != nil {
		if err := copyFile(tmpName, dst); err != nil {
			fmt.Fprintln(os.Stderr, "error staging:", err)
			return 2
		}
		os.Remove(tmpName)
	}
	// run from inside the stage and send ".": the manifest's base is the
	// LCA of the args, so a staged file path would strip the NAME's
	// directories (dir/name.bin landed as name.bin). Rooted at ".", the
	// remote path is exactly NAME.
	wd, _ := os.Getwd()
	if err := os.Chdir(stage); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	defer func() { _ = os.Chdir(wd) }()
	tok, pass, cloak := endpointSec(host)
	res := session.RunTransfer(context.Background(), session.ClientConfig{
		Addr:        endpointAddr(host),
		Direction:   0,
		Paths:       []string{"."},
		Compression: 1,
		Parallel:    2,
		Token:       tok,
		Pass:        pass,
		Cloak:       cloak,
	})
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "pipe send:", res.Err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "sent %s as %s\n", humanBytes(res.Report.Bytes), name)
	return 0
}

// pipeCat: pull PATH to a temp dir → stdout.
func pipeCat(args []string) int {
	fs := newFlagSet("pipe cat", "botjim pipe cat HOST PATH",
		"Stream one remote file to stdout (spooled via the engine, verified).")
	if err := fs.Parse(args); err != nil {
		if parseHelp(err) {
			return 0
		}
		return 3
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, "error: pipe cat needs HOST PATH")
		return 3
	}
	host, path := rest[0], rest[1]
	tmpDir, err := os.MkdirTemp("", "botjim-cat-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	defer os.RemoveAll(tmpDir)
	tok, pass, cloak := endpointSec(host)
	res := session.RunTransfer(context.Background(), session.ClientConfig{
		Addr:        endpointAddr(host),
		Direction:   1, // pull
		Paths:       []string{path},
		DestRoot:    tmpDir,
		Compression: 1,
		Parallel:    2,
		Token:       tok,
		Pass:        pass,
		Cloak:       cloak,
	})
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "pipe cat:", res.Err)
		return 2
	}
	// a single-file pull lands as its basename in DestRoot (the manifest
	// base strips the remote directories), so look it up by basename
	local := filepath.Join(tmpDir, filepath.Base(filepath.FromSlash(path)))
	f, err := os.Open(local)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	defer f.Close()
	if _, err := io.Copy(os.Stdout, f); err != nil {
		fmt.Fprintln(os.Stderr, "error writing stdout:", err)
		return 2
	}
	return 0
}

// endpointAddr resolves a named endpoint to its address ("" name passes
// through).
func endpointAddr(host string) string {
	if ep, ok := resolveEndpoint(host); ok {
		return ep.Addr
	}
	return host
}

// endpointSec returns the credentials a named endpoint carries (zero
// SecOpts for a literal host) — pipe talks to authenticated endpoints
// the same way plain send does.
func endpointSec(host string) (token, pass, cloak string) {
	if ep, ok := resolveEndpoint(host); ok {
		return ep.Token, ep.Pass, ep.Cloak
	}
	return "", "", ""
}

func resolveEndpoint(host string) (Endpoint, bool) {
	if cfg := loadConfigQuiet(); cfg != nil {
		return cfg.ResolveEndpoint(host)
	}
	return Endpoint{}, false
}

func tsNow() string {
	return time.Now().Format("20060102-150405")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

var _ = strings.TrimSpace
