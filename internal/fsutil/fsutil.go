//go:build unix

// Package fsutil holds the small, sharp filesystem helpers the rest of botjim
// leans on: the path jail every remote-controlled operation goes through,
// the literal-first glob expander for command line arguments, and an
// O_NOATIME opener that keeps source atimes intact while reading.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxComponent = 255
	maxPath      = 4096
)

// RelOK validates a manifest-relative path component-wise: '/' separated,
// no leading '/', no '.', '..', empty or NUL-containing component, sane
// length. The lone path "." (the root itself) is legal.
func RelOK(rel string) error {
	if rel == "" {
		return errors.New("empty path")
	}
	if rel == "." {
		return nil
	}
	if len(rel) > maxPath {
		return fmt.Errorf("path too long (%d bytes)", len(rel))
	}
	if strings.ContainsRune(rel, 0) {
		return errors.New("path contains NUL")
	}
	if strings.HasPrefix(rel, "/") {
		return errors.New("absolute path not allowed")
	}
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" {
			return errors.New("empty path component")
		}
		if comp == "." || comp == ".." {
			return fmt.Errorf("%q component not allowed", comp)
		}
		if len(comp) > maxComponent {
			return fmt.Errorf("component too long (%d bytes)", len(comp))
		}
	}
	return nil
}

// SafeJoin returns filepath.Join(root, rel) after validating rel with RelOK
// and re-verifying that the result stays under root. root must already be
// absolute and symlink-resolved (see ResolveRoot). This is the single choke
// point that keeps a remote peer — or a malicious manifest — inside the
// transfer root.
func SafeJoin(root, rel string) (string, error) {
	if err := RelOK(rel); err != nil {
		return "", err
	}
	if rel == "." {
		return root, nil
	}
	joined := filepath.Join(root, rel)
	if root == string(filepath.Separator) {
		return joined, nil // the filesystem root prefixes everything
	}
	if !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes root", rel)
	}
	return joined, nil
}

// CheckNoSymlinkComponents verifies that no component of root/rel —
// including the final one — is a symlink. Lexical SafeJoin alone cannot
// see through intermediate symlinks (Lstat follows them), so every
// remotely-controlled read path goes through this too.
func CheckNoSymlinkComponents(root, rel string) error {
	if rel == "" || rel == "." {
		return nil
	}
	if err := RelOK(rel); err != nil {
		return err
	}
	parts := strings.Split(rel, "/")
	cur := root
	for _, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil // does not exist yet: nothing to follow
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q traverses a symlink", rel)
		}
	}
	return nil
}

// ResolveRoot makes root absolute, symlink-free and existing. A root that
// cannot be resolved is a hard startup error: prefix checks in SafeJoin are
// only meaningful against a canonical root.
func ResolveRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// HasMeta reports whether s contains a glob metacharacter.
func HasMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// ExpandArg expands one command line path argument using the literal-first
// rule: a path that exists as given is taken literally even when it contains
// metacharacters ('./foo*bar' naming a literal file); only when it does not
// exist is it treated as a pattern and globbed. '**' crosses directory
// boundaries. Zero matches after globbing is an error.
func ExpandArg(arg string) ([]string, error) {
	arg = filepath.Clean(arg)
	if !HasMeta(arg) {
		if _, err := os.Lstat(arg); err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		return []string{arg}, nil
	}
	if _, err := os.Lstat(arg); err == nil {
		return []string{arg}, nil // literal wins over the pattern
	}
	matches, err := globPattern(arg)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no matches for pattern %q", arg)
	}
	sort.Strings(matches)
	return matches, nil
}

// ExpandArgs expands a list of arguments, skipping literal existence checks
// after a "--" terminator only in the sense that literals are passed through
// verbatim (they are the caller's business). The literal-first rule applies
// to every argument regardless.
func ExpandArgs(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		ms, err := ExpandArg(a)
		if err != nil {
			return nil, err
		}
		out = append(out, ms...)
	}
	return out, nil
}

// globPattern implements filepath.Match semantics plus '**' spanning any
// number of directories. Patterns that contain no '**' defer to
// filepath.Glob.
func globPattern(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}
	// Split into (dir prefix up to first **, remainder pattern).
	// Walk the prefix dir (or "."), matching the remainder against every
	// descendant path.
	rest := pattern
	prefix := ""
	if i := strings.Index(pattern, "**"); i >= 0 {
		prefix = pattern[:i]
		rest = pattern[i:]
		prefix = strings.TrimSuffix(prefix, "/")
		rest = strings.TrimPrefix(rest, "/**")
	}
	base := "."
	if prefix != "" {
		base = filepath.Clean(prefix)
	}
	var out []string
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if p == base {
				return err // base itself unreadable: nothing to match
			}
			return nil // unreadable subtree: skip, not fatal
		}
		if p == base {
			return nil
		}
		rel := p
		if base != "." {
			rel = strings.TrimPrefix(p, base+"/")
		}
		ok, err2 := matchDoublestar(rest, rel, d.IsDir())
		if err2 != nil || ok {
			if err2 == nil {
				out = append(out, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// matchDoublestar matches pattern (possibly containing '**') against a
// '/'-separated relative path. A '**' segment consumes zero or more path
// segments. isDir lets a pattern ending in '/**' also match the directory
// itself.
func matchDoublestar(pattern, name string, isDir bool) (bool, error) {
	psegs := strings.Split(pattern, "/")
	nsegs := strings.Split(name, "/")
	return matchSegs(psegs, nsegs, isDir)
}

func matchSegs(p, n []string, isDir bool) (bool, error) {
	if len(p) == 0 {
		return len(n) == 0, nil
	}
	if p[0] == "**" {
		// '**' consumes 0..len(n) segments
		for k := 0; k <= len(n); k++ {
			ok, err := matchSegs(p[1:], n[k:], isDir)
			if err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	}
	if len(n) == 0 {
		return false, nil
	}
	ok, err := path.Match(p[0], n[0])
	if err != nil || !ok {
		return false, err
	}
	return matchSegs(p[1:], n[1:], isDir)
}

// FileExists reports a plain existence probe by Lstat.
func FileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
