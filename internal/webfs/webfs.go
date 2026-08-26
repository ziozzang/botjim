// Package webfs serves a directory over plain HTTP with Range support —
// the bridge that lets browsers, curl and HF-style downloaders consume
// swarm artifacts (or any local tree) without botjim on the other end.
package webfs

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Handler serves files under root. Range requests are honored by
// http.ServeContent (single ranges; the stdlib handles 416/206 itself).
func Handler(root string) http.Handler {
	// resolve once: the jail check below relies on an absolute, symlink-
	// free root, and "." (the CLI default) would otherwise make every
	// request 404 (filepath.Join(".", x) cleans to x, unprefixed by "./")
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if rel == "" {
			writeDir(w, root, root)
			return
		}
		// reject dotfiles and sidecar/part files in any path component:
		// they leak partial artifacts and incidental secrets (.env, .git)
		if hiddenPath(rel) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if !underRoot(root, abs) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// resolve symlinks and re-check: a symlink INSIDE root pointing out
		// (root/link -> /etc) passes the lexical check but must not serve
		// the target. EvalSymlinks also covers a symlinked parent dir.
		real, err := filepath.EvalSymlinks(abs)
		if err != nil || !underRoot(root, real) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fi, err := os.Stat(real)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if fi.IsDir() {
			writeDir(w, root, real)
			return
		}
		if !fi.Mode().IsRegular() {
			http.Error(w, "not found", http.StatusNotFound) // no devices/fifos
			return
		}
		f, err := os.Open(real)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
	})
}

// underRoot reports whether abs is root itself or lies beneath it.
func underRoot(root, abs string) bool {
	return abs == root || strings.HasPrefix(abs, root+string(filepath.Separator))
}

// hiddenPath is true when any component is a dotfile or a botjim sidecar/
// part file — never exposed over HTTP.
func hiddenPath(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, ".") ||
			strings.Contains(part, ".fs-part-") ||
			strings.Contains(part, ".fs-meta-") {
			return true
		}
	}
	return false
}

// Serve runs the HTTP server until the listener closes.
func Serve(ln net.Listener, root string) error {
	return http.Serve(ln, Handler(root))
}

func writeDir(w http.ResponseWriter, root, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title := html.EscapeString(filepath.Base(dir))
	rel, _ := filepath.Rel(root, dir)
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body><h1>%s</h1><ul>",
		title, title)
	if rel != "." {
		fmt.Fprintf(w, `<li><a href="../">../</a></li>`)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") ||
			strings.Contains(name, ".fs-part-") ||
			strings.Contains(name, ".fs-meta-") {
			continue // do not list what we will not serve
		}
		if e.IsDir() {
			name += "/"
		}
		// href: URL-escape each path segment; text: HTML-escape. A crafted
		// filename can neither break out of the attribute nor inject markup.
		href := (&url.URL{Path: name}).EscapedPath()
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, href, html.EscapeString(name))
	}
	fmt.Fprintf(w, "</ul></body></html>")
}
