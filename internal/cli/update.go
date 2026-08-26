package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ziozzang/botjim/internal/selfupdate"
	"github.com/ziozzang/botjim/internal/version"

	"github.com/charmbracelet/x/term"
)

// updateCmd implements `botjim update`.
func updateCmd(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.Bool("check", false, "only report whether a newer version is available")
	force := fs.Bool("force", false, "reinstall even if already on the latest version")
	targetVer := fs.String("version", "", "install a specific release tag (for example v0.1.2)")
	repo := fs.String("repo", version.Repo, "GitHub owner/repo to update from")
	if err := fs.Parse(args); err != nil {
		return 3
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{}
	token := os.Getenv("GITHUB_TOKEN")

	var rel *selfupdate.Release
	var err error
	if *targetVer != "" {
		rel, err = selfupdate.ReleaseByTag(ctx, client, "", *repo, *targetVer, token)
	} else {
		rel, err = selfupdate.LatestRelease(ctx, client, "", *repo, token)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "look up release:", err)
		return 2
	}
	latest := rel.Version()
	cmp := selfupdate.CompareVersions(latest, version.Version)

	fmt.Printf("current: %s\nlatest:  %s\n", version.Version, latest)
	switch {
	case cmp > 0:
		fmt.Printf("a newer version is available: %s -> %s\n", version.Version, latest)
	case cmp == 0:
		fmt.Println("you are on the latest version")
	default:
		fmt.Printf("your version is newer than the published release (%s)\n", latest)
	}
	if *check {
		return 0
	}
	if cmp <= 0 && *targetVer == "" && !*force {
		return 0
	}

	assetName, err := selfupdate.CurrentAssetName(latest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	asset, ok := rel.FindAsset(assetName)
	if !ok {
		fmt.Fprintf(os.Stderr, "release %s has no build for %s/%s (asset %q)\n", rel.TagName, runtime.GOOS, runtime.GOARCH, assetName)
		return 2
	}
	sums, err := selfupdate.Checksums(ctx, client, rel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	want := sums[assetName]
	if want == "" {
		fmt.Fprintf(os.Stderr, "no checksum recorded for %s in SHA256SUMS\n", assetName)
		return 2
	}

	exe, err := selfupdate.ResolveExecutable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	dir := filepath.Dir(exe)
	fmt.Fprintf(os.Stderr, "downloading %s (%s)...\n", assetName, humanBytes(uint64(asset.Size)))
	tmp, err := selfupdate.DownloadVerified(ctx, client, asset, want, dir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(os.Stderr, "cannot write to %s: %v\nre-run with elevated privileges, or download manually from https://github.com/%s/releases\n", dir, err, *repo)
			return 2
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := selfupdate.ReplaceExecutable(exe, tmp); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(os.Stderr, "cannot replace %s: %v\nre-run with elevated privileges, or download manually from https://github.com/%s/releases\n", exe, err, *repo)
			return 2
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("updated %s: %s -> %s\n", exe, version.Version, latest)
	if notes := strings.TrimSpace(rel.Body); notes != "" {
		fmt.Printf("\n--- release notes for %s ---\n%s\n", rel.TagName, notes)
	}
	return 0
}

// ---- background update notice (cached, never blocks, TTY only) ----

const updateCheckInterval = 24 * time.Hour

type updateCache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest_version"`
}

// StartUpdateRefresh kicks a background version check when the cached result
// is stale, then returns immediately. Offline machines never wait.
func StartUpdateRefresh() {
	if os.Getenv("BOTJIM_NO_UPDATE_CHECK") != "" {
		return
	}
	if !stderrIsTerminal() {
		return
	}
	path := updateCachePath()
	c := readUpdateCache(path)
	if c.Latest != "" && time.Since(c.CheckedAt) < updateCheckInterval {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rel, err := selfupdate.LatestRelease(ctx, &http.Client{}, "", version.Repo, os.Getenv("GITHUB_TOKEN"))
		if err != nil {
			return // soft-fail: offline or GitHub down
		}
		writeUpdateCache(path, updateCache{CheckedAt: time.Now(), Latest: rel.Version()})
	}()
}

// MaybeNotifyUpdate prints a one-line upgrade notice from the cached result.
func MaybeNotifyUpdate() {
	if os.Getenv("BOTJIM_NO_UPDATE_CHECK") != "" {
		return
	}
	if !stderrIsTerminal() {
		return
	}
	c := readUpdateCache(updateCachePath())
	if c.Latest == "" {
		return
	}
	if selfupdate.CompareVersions(c.Latest, version.Version) > 0 {
		fmt.Fprintf(os.Stderr, "\nbotjim %s is available (you have %s). Run 'botjim update' to upgrade.\n", c.Latest, version.Version)
	}
}

func updateCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "botjim", "update-check.json")
}

func readUpdateCache(path string) updateCache {
	var c updateCache
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func writeUpdateCache(path string, c updateCache) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-check-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, path)
}

func stderrIsTerminal() bool {
	// ioctl-based check: a Stat() ModeCharDevice test would classify
	// /dev/null as a terminal and launch the TUI on redirected runs
	return term.IsTerminal(os.Stderr.Fd())
}
