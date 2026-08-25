// Package transport owns the TCP connection, the handshake exchange and the
// yamux session layered above it. The CipherFunc hook is where a future
// X25519+ChaCha20-Poly1305 record layer drops in: it wraps the raw net.Conn
// before yamux starts, so the entire multiplexed stream (headers included)
// rides inside the cipher with no protocol change.
package transport

import (
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

// Session wraps a yamux session.
type Session struct {
	ys *yamux.Session
	HS *protocol.Handshake // peer's handshake (post-intersection features)
}

// Dial connects, handshakes as client and multiplexes.
func Dial(ctx context.Context, addr string, features uint64, cipher CipherFunc) (*Session, error) {
	if cipher == nil {
		cipher = IdentityCipher
	}
	d := net.Dialer{Timeout: 15 * time.Second, Control: tuneSocket}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else {
		_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	}
	hs, err := protocol.NewHandshake(features)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := protocol.WriteHandshake(raw, hs); err != nil {
		_ = raw.Close()
		return nil, err
	}
	peerRaw, err := readHandshakeStrict(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("server handshake: %w", err)
	}
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
	if err := protocol.WriteHandshake(raw, hs); err != nil {
		_ = raw.Close()
		return nil, err
	}
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
