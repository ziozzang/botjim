package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	if len(args) < 1 {
		pipeUsage()
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
	fs.Parse(args)
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
	res := session.RunTransfer(context.Background(), session.ClientConfig{
		Addr:        endpointAddr(host),
		Direction:   0,
		Paths:       []string{dst},
		Compression: 1,
		Parallel:    2,
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
	fs.Parse(args)
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
	res := session.RunTransfer(context.Background(), session.ClientConfig{
		Addr:        endpointAddr(host),
		Direction:   1, // pull
		Paths:       []string{path},
		DestRoot:    tmpDir,
		Compression: 1,
		Parallel:    2,
	})
	if res.Err != nil {
		fmt.Fprintln(os.Stderr, "pipe cat:", res.Err)
		return 2
	}
	local := filepath.Join(tmpDir, path)
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

// endpointAddr resolves a named endpoint to its address ("" name passes through).
func endpointAddr(host string) string {
	if cfg := loadConfigQuiet(); cfg != nil {
		if ep, ok := cfg.ResolveEndpoint(host); ok {
			return ep.Addr
		}
	}
	return host
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
