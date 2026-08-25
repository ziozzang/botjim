//go:build unix

package attrs

import (
	"os/user"
	"sync"
)

var (
	userMu    sync.Mutex
	userCache = map[string]uint32{}
	groupMu   sync.Mutex
	groupCache = map[string]uint32{}
)

func lookupUser(name string) (uint32, error) {
	userMu.Lock()
	defer userMu.Unlock()
	if uid, ok := userCache[name]; ok {
		return uid, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := parseUint32(u.Uid)
	if err != nil {
		return 0, err
	}
	userCache[name] = uid
	return uid, nil
}

func lookupGroup(name string) (uint32, error) {
	groupMu.Lock()
	defer groupMu.Unlock()
	if gid, ok := groupCache[name]; ok {
		return gid, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := parseUint32(g.Gid)
	if err != nil {
		return 0, err
	}
	groupCache[name] = gid
	return gid, nil
}

func parseUint32(s string) (uint32, error) {
	var n uint32
	if s == "" {
		return 0, ErrBadID
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrBadID
		}
		n = n*10 + uint32(c-'0')
		if n > 1<<31 {
			return 0, ErrBadID
		}
	}
	return n, nil
}

// ErrBadID marks an unparseable numeric id.
var ErrBadID = errBadID{}

type errBadID struct{}

func (errBadID) Error() string { return "bad numeric id" }
