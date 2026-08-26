package relay

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultSlotTTL is how long an unmatched offer waits before the broker
// drops it.
const DefaultSlotTTL = 10 * time.Minute

// maxSlots bounds the broker's memory against junk offers.
const maxSlots = 4096

// Broker pairs offer/take peers and pipes their connections. It holds no
// protocol state — after pairing it is a transparent byte pipe, and the
// pairing ID is a hash, so the broker never learns the code itself.
//
// Each direction runs through a bounded spool (SpoolMax bytes total,
// SpoolMem in memory before spilling to SpoolDir): a fast sender can run
// ahead of a slow receiver without stalling, and a sender that finishes
// early can disconnect while its ciphertext drains. The spool holds only
// ciphertext.
type Broker struct {
	TTL      time.Duration
	SpoolMax int64 // total buffered bytes per direction (0 = unlimited)
	SpoolMem int64 // bytes kept in memory before disk spill
	SpoolDir string
	Logger   func(format string, args ...any)

	mu    sync.Mutex
	slots map[string]*slot
}

type slot struct {
	id      string
	offer   net.Conn
	wake    chan net.Conn // taker hands its conn here
	created time.Time
}

// NewBroker builds a broker with the default TTL and a 2GiB disk-spilling
// spool in the system temp directory.
func NewBroker() *Broker {
	return &Broker{
		TTL:      DefaultSlotTTL,
		SpoolMax: 2 << 30,
		SpoolMem: 256 << 20,
		SpoolDir: filepath.Join(os.TempDir(), "botjim-relay-spool"),
		slots:    map[string]*slot{},
	}
}

func (b *Broker) log(format string, args ...any) {
	if b.Logger != nil {
		b.Logger(format, args...)
	}
}

// Serve accepts peers until the listener closes.
func (b *Broker) Serve(ln net.Listener) error {
	go b.janitor()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go b.handle(conn)
	}
}

func (b *Broker) janitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-b.TTL)
		b.mu.Lock()
		var stale []*slot
		for id, s := range b.slots {
			if s.created.Before(cutoff) {
				delete(b.slots, id)
				stale = append(stale, s)
			}
		}
		b.mu.Unlock()
		for _, s := range stale {
			close(s.wake) // tells the parked offer handler to give up
			b.reply(s.offer, "ERR timeout")
			b.log("slot timed out")
		}
	}
}

// handle reads one HELLO line, then offers or takes a slot.
func (b *Broker) handle(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	// byte-by-byte: a buffered reader would swallow the first e2ee bytes
	// that can follow the HELLO line on the same stream
	var line []byte
	one := make([]byte, 1)
	for len(line) < 256 {
		if _, err := conn.Read(one); err != nil {
			_ = conn.Close()
			return
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	_ = conn.SetReadDeadline(time.Time{})
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) != 3 || fields[0] != "BOTRELAY1" {
		b.reply(conn, "ERR protocol")
		_ = conn.Close()
		return
	}
	verb, id := fields[1], fields[2]
	if len(id) != 64 || !isHex(id) {
		b.reply(conn, "ERR badid")
		_ = conn.Close()
		return
	}
	switch verb {
	case "offer":
		b.offer(conn, id, remote)
	case "take":
		b.take(conn, id, remote)
	default:
		b.reply(conn, "ERR verb")
		_ = conn.Close()
	}
}

// offer parks the connection in a slot. The parked goroutine wakes when a
// taker hands over its connection (and becomes one pipe half), when the
// offering peer disconnects, or when the slot times out.
func (b *Broker) offer(conn net.Conn, id, remote string) {
	s := &slot{id: id, offer: conn, wake: make(chan net.Conn, 1), created: time.Now()}
	b.mu.Lock()
	if len(b.slots) >= maxSlots {
		b.mu.Unlock()
		b.reply(conn, "ERR full")
		_ = conn.Close()
		return
	}
	if _, dup := b.slots[id]; dup {
		b.mu.Unlock()
		b.reply(conn, "ERR duplicate")
		_ = conn.Close()
		return
	}
	b.slots[id] = s
	b.mu.Unlock()
	defer b.remove(id, s)
	b.log("%s offers a slot", remote)

	if !b.reply(conn, "OK") {
		return
	}
	// Park until a taker hands over its connection (a dead offering peer
	// is only noticed at pipe time — the taker then sees an immediate
	// close and simply retries). No read watcher here: it would steal the
	// first byte of the paired stream.
	timer := time.NewTimer(b.TTL)
	select {
	case taker, ok := <-s.wake:
		timer.Stop()
		if !ok {
			return // slot expired under us
		}
		b.log("%s paired", remote)
		b.pipe(conn, taker)
	case <-timer.C:
		b.reply(conn, "ERR timeout")
		b.log("%s offer timed out", remote)
	}
}

// take matches a waiting offer, hands the taker connection to the parked
// offer handler, and returns — the offer handler owns the pipe.
func (b *Broker) take(conn net.Conn, id, remote string) {
	b.mu.Lock()
	s, ok := b.slots[id]
	if !ok {
		b.mu.Unlock()
		b.reply(conn, "ERR noslot")
		_ = conn.Close()
		return
	}
	delete(b.slots, id) // one-shot: first taker wins
	b.mu.Unlock()

	// reply BEFORE handing the conn over: once the offer handler starts
	// the pipe, its first ciphertext may race this line on the same socket
	if !b.reply(conn, "OK") {
		b.reply(s.offer, "ERR gone")
		_ = s.offer.Close()
		_ = conn.Close()
		return
	}
	select {
	case s.wake <- conn:
		b.log("%s took the slot", remote)
	default:
		// the offer vanished between the lock and here
		b.reply(conn, "ERR gone")
		_ = conn.Close()
	}
}

// remove deletes the slot unless it was already consumed or replaced.
func (b *Broker) remove(id string, s *slot) {
	b.mu.Lock()
	if cur, ok := b.slots[id]; ok && cur == s {
		delete(b.slots, id)
	}
	b.mu.Unlock()
	_ = s.offer.Close()
}

// pipe joins two connections through bounded spools. No protocol
// interpretation: everything after pairing is end-to-end ciphertext. The
// session tears down only after both directions have fully drained, so a
// sender may finish and disconnect while its receiver keeps draining.
func (b *Broker) pipe(a, c net.Conn) {
	pump := func(src net.Conn, sp *spoolBuf, dst net.Conn, done chan<- struct{}) {
		go func() { // producer: src → spool
			_, err := io.Copy(sp, src)
			if err != nil {
				sp.Fail(err)
			}
			sp.CloseWrite()
		}()
		n, err := io.Copy(dst, sp) // consumer: spool → dst
		if err != nil {
			sp.Fail(err)
		}
		sp.Finish()
		// propagate EOF without killing the reverse direction: half-close
		// the destination's write side so its peer sees EOF while its own
		// sends (acks, control frames) keep flowing back
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		b.log("piped %d bytes (disk=%v) err=%v", n, sp.usedDisk(), err)
		done <- struct{}{}
	}
	done := make(chan struct{}, 2)
	go pump(a, newSpoolBuf(b.SpoolMax, b.SpoolMem, b.SpoolDir), c, done)
	go pump(c, newSpoolBuf(b.SpoolMax, b.SpoolMem, b.SpoolDir), a, done)
	<-done
	<-done
	_ = a.Close()
	_ = c.Close()
}

func (b *Broker) reply(conn net.Conn, msg string) bool {
	if _, err := conn.Write([]byte(msg + "\n")); err != nil {
		_ = conn.Close()
		return false
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
