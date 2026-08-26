package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// watchLoop implements `sync push --watch`: run one push, then re-push
// whenever the source tree settles after changes.
//
// Debounce model: events reset a quiet timer; a push fires only after
// `quiet` with no events (a text editor writing a file in bursts does
// not cause three pushes). Two safety nets cover fsnotify's blind spots:
// a periodic full sweep (events can be lost on buffer overflow or when
// the tree is modified while a push is running) and a change snapshot
// (mtime+size per file) so a sweep only pushes when something actually
// differs.
func watchLoop(ctx context.Context, dir string, quiet, sweep time.Duration, push func() error) error {
	// first push immediately
	if err := push(); err != nil {
		fmt.Fprintf(os.Stderr, "sync: %v (retrying on next change)\n", err)
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := addTree(w, dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	lastSnap := snapshot(dir)

	var (
		quietTimer = time.NewTimer(quiet)
		sweepTimer = time.NewTimer(sweep)
	)
	defer quietTimer.Stop()
	defer sweepTimer.Stop()
	// the quiet timer only runs while armed; drain discipline matters
	quietArmed := true
	if !quietTimer.Stop() {
		<-quietTimer.C
	}
	quietTimer.Reset(quiet)

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-w.Events:
			if !ok {
				return fmt.Errorf("watcher closed")
			}
			// a new directory: watch it too (tree grew)
			if ev.Has(fsnotify.Create) {
				if fi, err := os.Lstat(ev.Name); err == nil && fi.IsDir() {
					_ = addTree(w, ev.Name)
				}
			}
			armQuiet(quietTimer, quiet, &quietArmed)

		case err, ok := <-w.Errors:
			if !ok {
				return fmt.Errorf("watcher closed")
			}
			fmt.Fprintf(os.Stderr, "watch: %v\n", err)

		case <-quietTimer.C:
			quietArmed = false
			snap := snapshot(dir)
			if snap != lastSnap {
				lastSnap = snap
				runWatchedPush(push)
			}
			quietTimer.Reset(quiet)

		case <-sweepTimer.C:
			sweepTimer.Reset(sweep)
			snap := snapshot(dir)
			if snap != lastSnap {
				lastSnap = snap
				runWatchedPush(push)
			}
		}
	}
}

func runWatchedPush(push func() error) {
	start := time.Now()
	if err := push(); err != nil {
		fmt.Fprintf(os.Stderr, "sync: %v (retrying on next change)\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "sync: mirrored in %s — watching for changes\n", time.Since(start).Round(time.Millisecond))
}

func armQuiet(t *time.Timer, d time.Duration, armed *bool) {
	if *armed {
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}
	t.Reset(d)
	*armed = true
}

// addTree recursively adds dir and its subdirectories to the watcher
// (fsnotify is not recursive).
func addTree(w *fsnotify.Watcher, dir string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, the sweep covers it
		}
		if d.IsDir() {
			return w.Add(p)
		}
		return nil
	})
}

// snapshot is a cheap content fingerprint (path‖size‖mtime of regular
// files) used to decide whether a burst of events changed anything.
func snapshot(dir string) string {
	var sb strings.Builder
	type fi struct {
		p     string
		size  int64
		mtime int64
	}
	var files []fi
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, dir)
		files = append(files, fi{rel, info.Size(), info.ModTime().UnixNano()})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].p < files[j].p })
	for _, f := range files {
		fmt.Fprintf(&sb, "%s %d %d\n", f.p, f.size, f.mtime)
	}
	return sb.String()
}
