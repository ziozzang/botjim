// Package transport owns the TCP connection, the handshake exchange and the
// yamux session layered above it. The CipherFunc hook is where a future
// X25519+ChaCha20-Poly1305 record layer drops in: it wraps the raw net.Conn
// before yamux starts, so the entire multiplexed stream (headers included)
// rides inside the cipher with no protocol change.
package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/ziozzang/botjim/internal/protocol"
)

// CipherFunc upgrades a raw connection. V1: identity.
type CipherFunc func(net.Conn) (net.Conn, error)

// IdentityCipher passes the connection through untouched.
func IdentityCipher(c net.Conn) (net.Conn, error) { return c, nil }

// tuneSocket raises TCP buffer ceilings so long-fat links can actually
// fill (Linux autotuning grows into these caps). Best-effort: failures
// (container restrictions, non-Linux) are ignored.
func tuneSocket(network, addr string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		for _, size := range []int{8 << 20, 4 << 20, 1 << 20} {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size); err == nil {
				break
			}
		}
		for _, size := range []int{8 << 20, 4 << 20, 1 << 20} {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size); err == nil {
				break
			}
		}
	})
}

// Listen starts a TCP listener with the same socket tuning as Dial.
func Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: tuneSocket}
	return lc.Listen(context.Background(), "tcp", addr)
}

// Yamux tuning: a large per-stream window matters on long-fat networks
// (yamux's initial window is 256KiB; it grows to this ceiling), and a deep
// accept backlog absorbs N parallel data streams opening at once.
func muxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 << 20
	cfg.AcceptBacklog = 256
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

func deadlineAuth() time.Time { return time.Now().Add(20 * time.Second) }

var noDeadline = time.Time{}

// Session wraps a yamux session.
type Session struct {
	ys *yamux.Session
	HS *protocol.Handshake // peer's handshake (post-intersection features)
}

// SecOpts carries the optional layers applied around the session: a
// shared-secret token (mutual proof-of-knowledge), a passphrase record
// layer, and cloak — carrying the whole session inside a WebSocket
// upgrade so the traffic looks like HTTP. Zero values disable all.
type SecOpts struct {
	Token string
	Pass  string
	Cloak string // cloak path ("" = plain)
}

// CloakServe and CloakSniff are installed by the cloak package for the
// server side: sniff HTTP-looking first bytes and upgrade matching ones.
var (
	CloakSniff func(br *bufio.Reader) bool
	CloakServe func(conn net.Conn, br *bufio.Reader, path string) net.Conn
	// CloakPlain rewraps a sniffed-but-not-HTTP connection so buffered
	// bytes are not lost (nil → use the raw conn).
	CloakPlain func(conn net.Conn, br *bufio.Reader) net.Conn
)

// CloakDialer is installed by the cloak package (transport stays
// dependency-free): upgrade a raw conn to a cloaked conn.
var CloakDialer func(conn net.Conn, path, host string) (net.Conn, error)

func (o SecOpts) flags() uint8 {
	var f uint8
	if o.Token != "" {
		f |= protocol.HSFlagToken
	}
	if o.Pass != "" {
		f |= protocol.HSFlagPass
	}
	return f
}

// Dial connects, handshakes as client and multiplexes.
func Dial(ctx context.Context, addr string, features uint64, cipher CipherFunc) (*Session, error) {
	return DialSec(ctx, addr, features, cipher, SecOpts{})
}

// DialSec is Dial with token auth / passphrase encryption.
func DialSec(ctx context.Context, addr string, features uint64, cipher CipherFunc, sec SecOpts) (*Session, error) {
	if cipher == nil {
		cipher = IdentityCipher
	}
	d := net.Dialer{Timeout: 15 * time.Second, Control: tuneSocket}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if sec.Cloak != "" {
		if CloakDialer == nil {
			_ = raw.Close()
			return nil, errors.New("cloak: unavailable in this build")
		}
		host, _, serr := net.SplitHostPort(addr)
		if serr != nil {
			host = addr
		}
		wrapped, cerr := CloakDialer(raw, sec.Cloak, host)
		if cerr != nil {
			_ = raw.Close()
			return nil, cerr
		}
		raw = wrapped
	}
	return DialConnSec(raw, features, cipher, sec)
}

// DialConn handshakes as the client over an already-established
// connection (relay mode hands in a paired, encrypted conn here — so the
// FSY1 handshake itself travels inside the record layer).
func DialConn(raw net.Conn, features uint64, cipher CipherFunc) (*Session, error) {
	return DialConnSec(raw, features, cipher, SecOpts{})
}

// CipherFactory builds the record layer from a shared secret; the relay
// package installs its implementation, keeping transport dependency-free.
var CipherFactory func(raw net.Conn, secret []byte, initiator bool) (net.Conn, error)

// PassphraseSecret stretches a passphrase into a PSK (both sides derive
// the same bytes; per-session randomness comes from the record-layer
// exchange itself, so a fixed domain salt is correct here — it only sets
// the attacker's per-guess cost).
var PassphraseSecret func(pass string) []byte

// DialConnSec is DialConn with the security options applied inline.
func DialConnSec(raw net.Conn, features uint64, cipher CipherFunc, sec SecOpts) (*Session, error) {
	if cipher == nil {
		cipher = IdentityCipher
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	hs, err := protocol.NewHandshake(features)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	hs.Flags |= sec.flags()
	if err := protocol.WriteHandshake(raw, hs); err != nil {
		_ = raw.Close()
		return nil, err
	}
	peerRaw, err := readHandshakeStrict(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("server handshake: %w", err)
	}
	secured, serr := secureConn(raw, hs, peerRaw, sec, true)
	if serr != nil {
		_ = raw.Close()
		return nil, serr
	}
	raw = secured
	_ = raw.SetDeadline(time.Time{})
	wire, err := cipher(raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	ys, err := yamux.Client(wire, muxConfig())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &Session{ys: ys, HS: negotiate(hs, peerRaw)}, nil
}

// HandshakeResult carries both sides post-negotiation for the listener.
type HandshakeResult struct {
	Peer *protocol.Handshake
}

// Accept handshakes one inbound connection (server side).
func Accept(raw net.Conn, features uint64, cipher CipherFunc) (*Session, error) {
	return AcceptConnSec(raw, features, cipher, SecOpts{})
}

// AcceptConn is Accept for an already-established connection (relay).
func AcceptConn(raw net.Conn, features uint64, cipher CipherFunc) (*Session, error) {
	return AcceptConnSec(raw, features, cipher, SecOpts{})
}

// AcceptSec is Accept with token auth / passphrase encryption. A server
// with a token set refuses clients that did not request auth.
func AcceptSec(raw net.Conn, features uint64, cipher CipherFunc, sec SecOpts) (*Session, error) {
	return AcceptConnSec(raw, features, cipher, sec)
}

// AcceptConnSec is AcceptConn with the security options applied inline.
func AcceptConnSec(raw net.Conn, features uint64, cipher CipherFunc, sec SecOpts) (*Session, error) {
	if cipher == nil {
		cipher = IdentityCipher
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	hs, err := protocol.NewHandshake(features)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	peer, err := readHandshakeStrict(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("client handshake: %w", err)
	}
	// announce the layers we require; refuse mismatched expectations
	hs.Flags |= sec.flags()
	if err := protocol.WriteHandshake(raw, hs); err != nil {
		_ = raw.Close()
		return nil, err
	}
	secured, serr := secureConn(raw, hs, peer, sec, false)
	if serr != nil {
		_ = raw.Close()
		return nil, serr
	}
	raw = secured
	_ = raw.SetDeadline(time.Time{})
	wire, err := cipher(raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	ys, err := yamux.Server(wire, muxConfig())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &Session{ys: ys, HS: negotiate(hs, peer)}, nil
}

// secureConn runs the negotiated post-handshake layers and returns the
// (possibly wrapped) connection: token proof first, then the passphrase
// record layer, which must wrap before yamux so even the multiplexed
// headers are ciphertext.
func secureConn(raw net.Conn, mine, theirs *protocol.Handshake, sec SecOpts, client bool) (net.Conn, error) {
	wantToken := mine.Flags&protocol.HSFlagToken != 0
	gotToken := theirs.Flags&protocol.HSFlagToken != 0
	switch {
	case wantToken && !gotToken:
		if client {
			return nil, fmt.Errorf("server does not use --token auth")
		}
		return nil, fmt.Errorf("token required: client did not authenticate")
	case gotToken && !wantToken:
		if client {
			return nil, fmt.Errorf("server requires --token auth (pass the same token)")
		}
		return nil, fmt.Errorf("client sent --token but this server has none")
	}
	if wantToken {
		if err := TokenAuth(raw, mine, theirs, sec.Token, client); err != nil {
			return nil, err
		}
	}
	// passphrase: both sides must agree
	wantPass := mine.Flags&protocol.HSFlagPass != 0
	gotPass := theirs.Flags&protocol.HSFlagPass != 0
	if wantPass != gotPass {
		if wantPass {
			return nil, fmt.Errorf("encryption required: client connected in plaintext")
		}
		return nil, fmt.Errorf("client wants encryption but this server has no --pass")
	}
	if wantPass {
		if CipherFactory == nil || PassphraseSecret == nil {
			return nil, fmt.Errorf("encryption unavailable (build missing record layer)")
		}
		wrapped, err := CipherFactory(raw, PassphraseSecret(sec.Pass), client)
		if err != nil {
			return nil, fmt.Errorf("encryption: %w", err)
		}
		return wrapped, nil
	}
	return raw, nil
}

// readHandshakeStrict reads the peer's handshake and performs a hard
// version/major check so garbage connections die before yamux starts.
func readHandshakeStrict(raw net.Conn) (*protocol.Handshake, error) {
	peer, err := protocol.ReadHandshake(raw)
	if err != nil {
		return nil, err
	}
	return peer, nil
}

func negotiate(ours, theirs *protocol.Handshake) *protocol.Handshake {
	merged := *theirs
	merged.FeatureBits = ours.FeatureBits & theirs.FeatureBits
	// both sides compute the same intersection from their own handshake
	return &merged
}

// OpenStream opens a new multiplexed stream.
func (s *Session) OpenStream() (net.Conn, error) {
	return s.ys.Open()
}

// AcceptStream blocks for an inbound stream.
func (s *Session) AcceptStream() (net.Conn, error) {
	return s.ys.Accept()
}

// AcceptStreamCtx accepts with context cancellation.
func (s *Session) AcceptStreamCtx(ctx context.Context) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := s.ys.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// RTT measures the round trip with a yamux ping.
func (s *Session) RTT() (time.Duration, error) {
	return s.ys.Ping()
}

// IsClosed reports session health.
func (s *Session) IsClosed() bool { return s.ys.IsClosed() }

// Close tears the session down.
func (s *Session) Close() error {
	if s.ys == nil {
		return errors.New("session not initialized")
	}
	return s.ys.Close()
}
