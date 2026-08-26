// Package webfs serves a directory over plain HTTP with Range support —
// the bridge that lets browsers, curl and HF-style downloaders consume
// swarm artifacts (or any local tree) without botjim on the other end.
package webfs

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Handler serves files under root. Range requests are honored by
// http.ServeContent (single ranges; the stdlib handles 416/206 itself).
func Handler(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if rel == "" {
			writeIndex(w, root)
			return
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		// jail: the joined path must stay under root
		if !strings.HasPrefix(abs, root+string(filepath.Separator)) && abs != root {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fi, err := os.Stat(abs)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if fi.IsDir() {
			writeDir(w, root, abs)
			return
		}
		f, err := os.Open(abs)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
	})
}

// Serve runs the HTTP server until the listener closes.
func Serve(ln net.Listener, root string) error {
	return http.Serve(ln, Handler(root))
}

func writeIndex(w http.ResponseWriter, root string) {
	writeDir(w, root, root)
}

func writeDir(w http.ResponseWriter, root, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	rel, _ := filepath.Rel(root, dir)
	fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body><h1>%s</h1><ul>",
		filepath.Base(dir), filepath.Base(dir))
	if rel != "." {
		fmt.Fprintf(w, `<li><a href="../">../</a></li>`)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`, name, name)
	}
	fmt.Fprintf(w, "</ul></body></html>")
}
