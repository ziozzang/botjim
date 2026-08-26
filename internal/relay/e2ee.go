package relay

import (
	"bytes"
	cipher "crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The end-to-end layer for relay transfers. After the broker pairs two
// peers, both sides run handshakeV1: an X25519 exchange whose key schedule
// folds in the pairing code as a PSK, plus mutually verified confirmation
// MACs. Everything afterwards — including botjim's own FSY1 handshake —
// travels inside the recordConn below, so the relay reads only ciphertext.

const (
	e2eeVersion  = "botjim-e2ee/v1"
	maxRecordLen = 2 << 20 // yamux frames are far smaller; junk dies here
)

type e2eeKeys struct {
	send, recv *[32]byte // direction keys
	sendPrefix [4]byte   // nonce domain per direction
	recvPrefix [4]byte
}

// EncryptConn wraps conn in the record layer after a PSK-authenticated
// X25519 exchange. Direct mode (--pass) and swarm links reuse this with
// secret material derived from a passphrase or swarm token.
func EncryptConn(conn net.Conn, secret []byte, initiator bool) (net.Conn, error) {
	return handshakeV1Secret(conn, secret, initiator)
}

// handshakeV1 performs the PSK-authenticated key exchange over the paired
// pipe. initiator is the offering (sending) side. On success the returned
// conn encrypts everything in both directions.
func handshakeV1(conn net.Conn, code string, initiator bool) (net.Conn, error) {
	return handshakeV1Secret(conn, []byte("botjim-relay-psk/v1/"+NormalizeCode(code)), initiator)
}

func handshakeV1Secret(conn net.Conn, psk []byte, initiator bool) (net.Conn, error) {
	// ephemeral X25519
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	myPub := priv.PublicKey().Bytes()

	// exchange pub||nonce in fixed layout. Write concurrently with the
	// read: over an unbuffered pipe (and half-open TCP) a write-then-read
	// sequence deadlocks both sides.
	var hello [16 + 32]byte // 16 nonce + 32 pub
	copy(hello[0:16], nonce[:])
	copy(hello[16:], myPub)
	writeErr := make(chan error, 1)
	go func() { writeErr <- writeFull(conn, hello[:]) }()
	var peerHello [16 + 32]byte
	if err := readFull(conn, peerHello[:]); err != nil {
		return nil, fmt.Errorf("relay handshake: %w", err)
	}
	if err := <-writeErr; err != nil {
		return nil, fmt.Errorf("relay handshake: %w", err)
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerHello[16:])
	if err != nil {
		return nil, fmt.Errorf("relay handshake: bad peer key")
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("relay handshake: %w", err)
	}

	// key schedule: X25519 shared secret + the PSK. Both sides must derive
	// identical output, so anything side-dependent enters only through the
	// (symmetric) confirmation transcript below.
	ikm := append(append([]byte{}, shared...), psk...)
	info := []byte(e2eeVersion)
	var okm [64]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), okm[:]); err != nil {
		return nil, err
	}
	var kI2R, kR2I [32]byte
	copy(kI2R[:], okm[0:32])
	copy(kR2I[:], okm[32:64])

	// confirmation MACs over a canonically ordered transcript (the two
	// hellos sorted, so both sides compute the same bytes).
	h1, h2 := hello, peerHello
	if bytes.Compare(peerHello[:], hello[:]) < 0 {
		h1, h2 = peerHello, hello
	}
	transcript := append(append([]byte(e2eeVersion), h1[:]...), h2[:]...)
	confirmKey := hkdfSum([]byte("confirm"), ikm, transcript)
	mine := hmacSum(confirmKey, []byte(roleTag(initiator)))
	theirs := hmacSum(confirmKey, []byte(roleTag(!initiator)))
	confirmErr := make(chan error, 1)
	go func() { confirmErr <- writeFull(conn, mine[:]) }()
	var peerTag [16]byte
	if err := readFull(conn, peerTag[:]); err != nil {
		return nil, fmt.Errorf("relay confirm: %w", err)
	}
	if err := <-confirmErr; err != nil {
		return nil, fmt.Errorf("relay confirm: %w", err)
	}
	if !hmac.Equal(peerTag[:], theirs[:]) {
		return nil, errors.New("relay code mismatch: the other side used a different code")
	}

	k := &e2eeKeys{}
	if initiator {
		k.send, k.recv = &kI2R, &kR2I
	} else {
		k.send, k.recv = &kR2I, &kI2R
	}
	// per-direction nonce prefixes are derived (not transported): each side
	// derives the same pair from the direction keys
	k.sendPrefix = derivePrefix(k.send)
	k.recvPrefix = derivePrefix(k.recv)
	return &recordConn{Conn: conn, k: k}, nil
}

func roleTag(initiator bool) string {
	if initiator {
		return "initiator"
	}
	return "responder"
}

func derivePrefix(key *[32]byte) [4]byte {
	h := sha256.Sum256(append([]byte("botjim-relay-prefix/"), key[:]...))
	return [4]byte{h[0], h[1], h[2], h[3]}
}

func hkdfSum(domain []byte, ikm, extra []byte) []byte {
	m := append(append([]byte(domain), ikm...), extra...)
	var salt [32]byte
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, m, salt[:], append([]byte("botjim-relay/"), domain...))
	io.ReadFull(r, out)
	return out
}

func hmacSum(key, msg []byte) [16]byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	var out [16]byte
	copy(out[:], h.Sum(nil)[:16])
	return out
}

func writeFull(conn net.Conn, b []byte) error {
	_ = conn.SetWriteDeadline(deadlineSoon())
	_, err := conn.Write(b)
	_ = conn.SetWriteDeadline(timeZero())
	return err
}

func readFull(conn net.Conn, b []byte) error {
	_ = conn.SetReadDeadline(deadlineSoon())
	_, err := io.ReadFull(conn, b)
	_ = conn.SetReadDeadline(timeZero())
	return err
}

// recordConn wraps the paired pipe in AEAD frames:
//
//	[u32 len][12B nonce][ciphertext+tag]
//
// Nonces embed a per-direction prefix and a monotonically increasing
// counter, so records cannot be reordered, replayed or cross-directed.
type recordConn struct {
	net.Conn
	k       *e2eeKeys
	sendMu  sync.Mutex
	recvMu  sync.Mutex
	sendCtr uint64
	recvCtr uint64
	rbuf    []byte // decrypted bytes not yet consumed by the reader
}

func (c *recordConn) aeadFor(key *[32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key[:])
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	aead, err := c.aeadFor(c.k.send)
	if err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxRecordLen {
			n = maxRecordLen
		}
		chunk := p[:n]
		c.sendCtr++
		var nonce [12]byte
		copy(nonce[0:4], c.k.sendPrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], c.sendCtr)

		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(nonce)+len(chunk)+aead.Overhead()))
		sealed := aead.Seal(nil, nonce[:], chunk, hdr[:])
		// frame = hdr | nonce | ciphertext+tag — the nonce must be on the
		// wire (the reader slices it off before opening)
		out := append(hdr[:], nonce[:]...)
		out = append(out, sealed...)
		if _, err := c.Conn.Write(out); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *recordConn) Read(p []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	// serve buffered plaintext first
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	aead, err := c.aeadFor(c.k.recv)
	if err != nil {
		return 0, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if int(length) < 12+aead.Overhead() || int(length) > maxRecordLen+12+aead.Overhead() {
		return 0, errors.New("relay record: implausible length")
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}
	nonce, sealed := frame[:12], frame[12:]
	if string(nonce[0:4]) != string(c.k.recvPrefix[:]) {
		return 0, errors.New("relay record: wrong direction")
	}
	ctr := binary.BigEndian.Uint64(nonce[4:12])
	if ctr == 0 || ctr <= c.recvCtr {
		return 0, errors.New("relay record: replay or reorder")
	}
	c.recvCtr = ctr
	plain, err := aead.Open(nil, nonce, sealed, hdr[:])
	if err != nil {
		return 0, errors.New("relay record: authentication failed")
	}
	n := copy(p, plain)
	if n < len(plain) {
		c.rbuf = append(c.rbuf[:0], plain[n:]...)
	}
	return n, nil
}

func deadlineSoon() time.Time { return time.Now().Add(20 * time.Second) }
func timeZero() time.Time     { return time.Time{} }
