package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// cmdSync implements `botjim sync push|pull` — one-shot mirror runs driven
// by named endpoints and per-target policies from the config:
//
//	"sync push node1"         mirror cwd → node1 (its autosync policy)
//	"sync push --dir D node1" mirror D → node1
//	"sync pull node1"         mirror node1's root → --dest (or policy dest)
//
// The engine (delta, resume, verification, --delete semantics) is the
// plain send/pull path; sync adds policy lookup and reporting.
func cmdSync(args []string) int {
	if len(args) < 1 {
		syncUsage()
		return 3
	}
	switch args[0] {
	case "push":
		return syncPush(args[1:])
	case "pull":
		return syncPull(args[1:])
	default:
		syncUsage()
		return 3
	}
}

func syncUsage() {
	fmt.Fprint(os.Stderr, `usage:
  botjim sync push [--dir DIR] NAME     mirror DIR (default .) → endpoint NAME
  botjim sync pull [--dest DIR] NAME    mirror endpoint NAME's root → DIR

Per-target policy (include/exclude/delete/dest) comes from the
"autosync" section of ~/.botjim/config.json; the endpoint's
addr/token/pass/cloak from "endpoints".
`)
}

// syncPolicy looks up the autosync policy for a target (zero value when
// none — sync then runs with the plain defaults).
func syncPolicy(name string) SyncTarget {
	cfg := loadConfigQuiet()
	if cfg == nil || cfg.Autosync == nil {
		return SyncTarget{}
	}
	return cfg.Autosync[name]
}

func syncPush(args []string) int {
	var (
		dir      string
		watch    bool
		quietMs  int
		sweepSec int
	)
	fs := newFlagSet("sync push", "botjim sync push [--dir DIR] [--watch] NAME",
		"One-shot mirror: push DIR to the endpoint NAME.\nApplies the target's include/exclude/delete policy.\n--watch keeps it running: changes re-mirror after they settle.")
	fs.StringVar(&dir, "dir", ".", "directory to mirror")
	fs.BoolVar(&watch, "watch", false, "keep running: re-push whenever the source settles after changes\n(each re-push is a delta, so it is cheap)")
	fs.IntVar(&quietMs, "debounce-ms", 500, "watch: quiet period before a re-push fires")
	fs.IntVar(&sweepSec, "sweep-sec", 30, "watch: periodic full check for missed events")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: sync push needs an endpoint NAME")
		return 3
	}
	name := fs.Arg(0)
	ep, ok := loadConfigQuiet().ResolveEndpoint(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no endpoint named %q in the config\n", name)
		return 3
	}
	pol := syncPolicy(name)
	f := syncFlags(ep)
	if pol.Include != nil {
		f.include = pol.Include
	}
	if pol.Exclude != nil {
		f.exclude = pol.Exclude
	}
	if pol.Delete {
		// mirror semantics: delete dest entries missing from the source
		f.deleteDst = true
	}
	// mirror the *contents* of dir, so chdir there and send "." —
	// otherwise the last path component would land as a subdirectory
	if err := os.Chdir(dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot enter %s: %v\n", dir, err)
		return 2
	}
	if !watch {
		return runClient(context.Background(), f.withRoot(dir))
	}
	// watch mode: stay in the original cwd only for the watcher's paths —
	// we already chdir'd, and each push re-enters the same dir
	abs, _ := filepath.Abs(dir)
	if abs == "" {
		abs = dir
	}
	fmt.Fprintf(os.Stderr, "watching %s → %s (debounce %dms)\n", abs, ep.Addr, quietMs)
	push := func() error {
		f2 := syncFlags(ep)
		f2.include = f.include
		f2.exclude = f.exclude
		f2.deleteDst = f.deleteDst
		f2.quiet = true
		code := runClient(context.Background(), f2.withRoot(dir))
		if code != 0 {
			return fmt.Errorf("push exited %d", code)
		}
		return nil
	}
	ctx := signalContext()
	if err := watchLoop(ctx, abs, time.Duration(quietMs)*time.Millisecond, time.Duration(sweepSec)*time.Second, push); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	return 0
}

func syncPull(args []string) int {
	var dest string
	fs := newFlagSet("sync pull", "botjim sync pull [--dest DIR] NAME",
		"One-shot mirror: pull the endpoint NAME's root into DIR.\nApplies the target's include/exclude/delete/dest policy.")
	fs.StringVar(&dest, "dest", "", "receive directory (default: the target's autosync dest)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: sync pull needs an endpoint NAME")
		return 3
	}
	name := fs.Arg(0)
	ep, ok := loadConfigQuiet().ResolveEndpoint(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no endpoint named %q in the config\n", name)
		return 3
	}
	pol := syncPolicy(name)
	if dest == "" {
		dest = pol.Dest
	}
	if dest == "" {
		dest = "."
	}
	f := syncFlags(ep)
	f.pull = true
	f.dest = dest
	if pol.Include != nil {
		f.include = pol.Include
	}
	if pol.Exclude != nil {
		f.exclude = pol.Exclude
	}
	if pol.Delete {
		f.deleteDst = true
	}
	// pull: "." mirrors the endpoint's whole jail root into dest
	f.rest = []string{"."}
	return runClient(context.Background(), f)
}

// syncFlags builds the base flags for a sync run by registering the real
// send/pull flag sets on a throwaway parser — defaults can never drift
// from the interactive commands — then applying the endpoint's stored
// credentials on top.
func syncFlags(ep Endpoint) *flags {
	f := &flags{}
	tmp := newFlagSet("sync", "", "")
	addCommonFlags(tmp, f)
	addTransferFlags(tmp, f)
	addFilterFlags(tmp, f)
	f.client = ep.Addr
	f.token = ep.Token
	f.pass = ep.Pass
	f.cloak = ep.Cloak
	return f
}

// withRoot points the push at the (already chdir'd into) source dir —
// "." sends its contents so the mirror lands at the jail root.
func (f *flags) withRoot(dir string) *flags {
	f.rest = []string{"."}
	return f
}
