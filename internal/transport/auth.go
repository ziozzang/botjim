package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ziozzang/botjim/internal/protocol"
)

// TokenAuth exchanges proof-of-knowledge HMACs after the handshake when
// both sides set HSFlagToken: each side proves it holds the token without
// transmitting it, bound to both session nonces and its own role (a
// reflection replays the wrong role tag and fails).
func TokenAuth(conn net.Conn, mine, theirs *protocol.Handshake, token string, client bool) error {
	if theirs.Flags&protocol.HSFlagToken == 0 {
		return errors.New("peer did not request token auth")
	}
	key := sha256.Sum256([]byte("botjim-token/v1/" + token))
	role := "S"
	if client {
		role = "C"
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(role))
	mac.Write(mine.Nonce[:])
	mac.Write(theirs.Nonce[:])
	myTag := mac.Sum(nil)

	theirRole := "C"
	if client {
		theirRole = "S"
	}
	mac2 := hmac.New(sha256.New, key[:])
	mac2.Write([]byte(theirRole))
	mac2.Write(theirs.Nonce[:])
	mac2.Write(mine.Nonce[:])
	wantTag := mac2.Sum(nil)

	// concurrent write+read: a write-then-read sequence deadlocks
	// half-duplex transports
	errCh := make(chan error, 1)
	go func() {
		_ = conn.SetWriteDeadline(deadlineAuth())
		_, err := conn.Write(myTag)
		_ = conn.SetWriteDeadline(time.Time{})
		errCh <- err
	}()
	var got [32]byte
	_ = conn.SetReadDeadline(deadlineAuth())
	_, rerr := io.ReadFull(conn, got[:])
	_ = conn.SetReadDeadline(time.Time{})
	if rerr != nil {
		return fmt.Errorf("token auth: %w", rerr)
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("token auth: %w", err)
	}
	if !hmac.Equal(got[:], wantTag) {
		return errors.New("token mismatch")
	}
	return nil
}
