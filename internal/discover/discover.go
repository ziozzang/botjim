//go:build unix

// Package discover implements opt-in LAN presence: a server started with
// --discover beacons on a UDP multicast group every few seconds, and
// `botjim peers` collects what it hears. Discovery is a convenience
// layer only — every real transfer still goes through the engine's
// token/encryption, and a spoofed beacon can do no more than cause a
// failed connection.
package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// Group is the administratively-scoped multicast group (LAN-local).
	Group = "239.255.47.61"
	// Port is the conventional botjim discovery port.
	Port = 4762

	maxDatagram = 512
	protoV1     = 1
)

// Beacon is the announcement payload. It carries the *port* only — the
// listener pairs it with the datagram's source IP, so a multi-homed host
// is announced with the address that is actually reachable from wherever
// the beacon landed.
type Beacon struct {
	Proto int    `json:"proto"`
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Root  string `json:"root,omitempty"`
	Ver   string `json:"ver"`
}

// Peer is a discovered server, ready to be used as `botjim send ADDR`.
type Peer struct {
	Beacon
	Addr string    `json:"addr"` // ip:port to connect to
	Last time.Time `json:"last"`
}

// Announce beacons b on the group every `every` until ctx ends. It never
// returns an error for a dead interface — presence is best-effort.
func Announce(ctx context.Context, b Beacon, every time.Duration) {
	b.Proto = protoV1
	payload, err := json.Marshal(b)
	if err != nil {
		return
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(Group, strconv.Itoa(Port)))
	if err != nil {
		return
	}
	defer conn.Close()
	tick := time.NewTicker(every)
	defer tick.Stop()
	// disable loopback suppression? no — keep the default so a stray
	// `peers` on the announcing host still sees it via the kernel's
	// multicast loopback path
	for {
		_, _ = conn.Write(payload)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Listen collects beacons for `window` and returns the deduplicated
// peer list (latest beacon per address, sorted by name).
func Listen(ctx context.Context, window time.Duration) ([]Peer, error) {
	gaddr := &net.UDPAddr{IP: net.ParseIP(Group), Port: Port}
	conn, err := net.ListenMulticastUDP("udp4", nil, gaddr)
	if err != nil {
		return nil, fmt.Errorf("cannot join %s:%d (multicast blocked?): %w", Group, Port, err)
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(64 * 1024); err != nil {
		// non-fatal: small buffer just drops beacons under load
		_ = err
	}

	var (
		mu    sync.Mutex
		seen  = map[string]Peer{}
		buf   = make([]byte, maxDatagram)
		chant = time.Now().Add(window)
	)
	for {
		deadline := time.Now().Add(500 * time.Millisecond)
		if deadline.After(chant) {
			deadline = chant
		}
		_ = conn.SetReadDeadline(deadline)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if !time.Now().Before(chant) || ctx.Err() != nil {
					break // window (or patience) over: return what we heard
				}
				continue
			}
			return nil, err
		}
		var b Beacon
		if json.Unmarshal(buf[:n], &b) != nil || b.Proto != protoV1 || b.Port <= 0 || b.Port > 65535 {
			continue // not ours: ignore quietly
		}
		if src.IP.To4() == nil {
			continue
		}
		// beacon fields are attacker-controlled LAN input printed to a
		// terminal by `botjim peers`: a control/ANSI sequence in Name/Ver/
		// Root could rewrite the screen or spoof rows. Drop such beacons.
		if hasControl(b.Name) || hasControl(b.Ver) || hasControl(b.Root) {
			continue
		}
		p := Peer{Beacon: b, Addr: net.JoinHostPort(src.IP.String(), strconv.Itoa(b.Port)), Last: time.Now()}
		mu.Lock()
		seen[p.Addr] = p
		mu.Unlock()
	}
	out := make([]Peer, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Addr < out[j].Addr
	})
	return out, nil
}

// hasControl reports whether s contains any C0/C1 control byte (including
// ESC, CR, and DEL) — such bytes in a beacon field are terminal-injection
// attempts and disqualify the beacon.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
