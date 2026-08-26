// Package transport owns the TCP connection, the handshake exchange and the
// yamux session layered above it. The CipherFunc hook is where a future
// X25519+ChaCha20-Poly1305 record layer drops in: it wraps the raw net.Conn
// before yamux starts, so the entire multiplexed stream (headers included)
// rides inside the cipher with no protocol change.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	if f != 0 {
		f |= protocol.HSFlagSecureV2 // token/pass always use the v2 layer
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

// CipherFactory builds the record layer from a shared secret plus bind
// (canonical handshake bytes, folded into the transcript); the relay
// package installs its implementation, keeping transport dependency-free.
var CipherFactory func(raw net.Conn, secret, bind []byte, initiator bool) (net.Conn, error)

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
// secureConn runs the post-handshake auth/encryption layer. In v2, token
// and/or pass both drive the X25519 record layer (token is no longer a
// bare HMAC — it now encrypts and authenticates the whole stream), and the
// full handshake of both peers is bound into the key schedule so a MITM
// cannot downgrade feature bits or flags undetected.
func secureConn(raw net.Conn, mine, theirs *protocol.Handshake, sec SecOpts, client bool) (net.Conn, error) {
	wantToken := mine.Flags&protocol.HSFlagToken != 0
	gotToken := theirs.Flags&protocol.HSFlagToken != 0
	wantPass := mine.Flags&protocol.HSFlagPass != 0
	gotPass := theirs.Flags&protocol.HSFlagPass != 0

	// each layer must be requested by BOTH sides (mismatch = clear refusal)
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
	if wantPass != gotPass {
		if wantPass {
			return nil, fmt.Errorf("encryption required: peer connected without --pass")
		}
		return nil, fmt.Errorf("peer wants --pass encryption but this side has none")
	}

	if !wantToken && !wantPass {
		return raw, nil // plaintext (trusted network) — unchanged
	}

	// v2 required on both ends. A pre-v0.11 peer never sets SecureV2 (and
	// in fact rejects our SecureV2 flag as unknown before reaching here), so
	// a missing bit means an incompatible/downgraded peer: refuse.
	if mine.Flags&protocol.HSFlagSecureV2 == 0 || theirs.Flags&protocol.HSFlagSecureV2 == 0 {
		return nil, fmt.Errorf("secure auth v2 required — upgrade both ends to v0.11+")
	}
	if CipherFactory == nil {
		return nil, fmt.Errorf("encryption unavailable (build missing record layer)")
	}
	secret, err := authSecret(sec)
	if err != nil {
		return nil, err
	}
	// bind the canonical bytes of BOTH handshakes (order-independent): any
	// alteration to either peer's feature bits/flags/nonce fails the MAC
	mh := protocol.MarshalHandshake(mine)
	th := protocol.MarshalHandshake(theirs)
	bind := handshakeBind(mh[:], th[:])
	wrapped, err := CipherFactory(raw, secret, bind, client)
	if err != nil {
		return nil, fmt.Errorf("secure handshake: %w", err)
	}
	return wrapped, nil
}

// authSecret derives the record-layer PSK from the requested layers. Token
// and pass each contribute keyed material; when both are set the peer must
// know both. Order is fixed so both sides derive identical bytes.
func authSecret(sec SecOpts) ([]byte, error) {
	var out []byte
	if sec.Token != "" {
		h := sha256.Sum256([]byte("botjim-token-psk/v2/" + sec.Token))
		out = append(out, h[:]...)
	}
	if sec.Pass != "" {
		if PassphraseSecret == nil {
			return nil, fmt.Errorf("encryption unavailable (build missing record layer)")
		}
		out = append(out, PassphraseSecret(sec.Pass)...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no auth secret")
	}
	return out, nil
}

// handshakeBind returns the two handshakes concatenated in canonical
// (sorted) order, so both peers compute identical bind bytes regardless of
// role.
func handshakeBind(a, b []byte) []byte {
	if bytes.Compare(b, a) < 0 {
		a, b = b, a
	}
	return append(append([]byte(nil), a...), b...)
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
