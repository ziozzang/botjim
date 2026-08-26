package relay

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Offer connects to the relay, parks in a slot under the code and waits
// for the receiver. On success the returned conn is the paired pipe with
// the end-to-end record layer active — hand it to transport as the raw
// connection.
func Offer(ctx context.Context, relayAddr, code string) (net.Conn, error) {
	if err := ValidateCode(code); err != nil {
		return nil, err
	}
	conn, err := dialRelay(ctx, relayAddr, "offer", code)
	if err != nil {
		return nil, err
	}
	return handshakeV1(conn, code, true)
}

// Take connects to the relay and claims the slot parked under the code.
func Take(ctx context.Context, relayAddr, code string) (net.Conn, error) {
	if err := ValidateCode(code); err != nil {
		return nil, err
	}
	conn, err := dialRelay(ctx, relayAddr, "take", code)
	if err != nil {
		return nil, err
	}
	return handshakeV1(conn, code, false)
}

func dialRelay(ctx context.Context, relayAddr, verb, code string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(relayAddr)
	if err != nil {
		// no port: use the default relay port
		host = relayAddr
		port = "4762"
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("relay %s: %w", relayAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintf(conn, "BOTRELAY1 %s %s\n", verb, codeID(code))
	// read the reply byte-by-byte: a buffered reader would swallow the
	// first handshake bytes that follow "OK" on the same stream
	var line []byte
	one := make([]byte, 1)
	for len(line) < 128 {
		if _, err := conn.Read(one); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("relay answer: %w", err)
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	_ = conn.SetDeadline(time.Time{})
	resp := string(line)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay answer: %w", err)
	}
	switch trim(resp) {
	case "OK":
		return conn, nil
	case "ERR noslot":
		_ = conn.Close()
		return nil, fmt.Errorf("no pending transfer for this code — is the sender still offering?")
	case "ERR duplicate":
		_ = conn.Close()
		return nil, fmt.Errorf("this code is already offered (codes are one-shot)")
	case "ERR full":
		_ = conn.Close()
		return nil, fmt.Errorf("relay is out of slots, try later")
	case "ERR timeout":
		_ = conn.Close()
		return nil, fmt.Errorf("relay slot timed out")
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("relay refused: %s", trim(resp))
	}
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
