// Package cloak disguises a botjim session as ordinary web traffic,
// V2Ray-style: the TCP stream is an HTTP conversation. Plain GETs get a
// plausible static page (a decoy site); only a request carrying the right
// WebSocket upgrade on the configured path is answered with 101 and
// carries the session as WebSocket frames. A DPI middlebox sees HTTP.
//
//	server: botjim server --cloak /cdn/data
//	client: botjim send --cloak /cdn/data HOST PATH...
//
// The frames are RFC 6455 binary frames (client→server masked, as
// required); the botjim handshake and everything above ride unchanged
// inside them, including the --pass record layer.
package cloak

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// decoyPage is what an observer (or a curious human) gets on any normal
// HTTP request.
const decoyPage = `<!DOCTYPE html>
<html><head><title>Content Delivery Node</title></head>
<body><h1>It works.</h1><p>This node serves cached assets. Nothing to see here.</p></body></html>`

// PlainConn rewires a connection whose first bytes were buffered during
// sniffing: reads replay the buffer before hitting the socket again.
// Without this, a non-HTTP (plain FSY1) client's handshake bytes stay in
// the bufio.Reader and the demux path sees an empty stream.
func PlainConn(conn net.Conn, br *bufio.Reader) net.Conn {
	return &bufConn{Conn: conn, r: br}
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// SniffCloaked reports whether the first bytes of a connection look like
// an HTTP request (server side: route cloaked vs plain FSY1).
func SniffCloaked(br *bufio.Reader) bool {
	b, err := br.Peek(4)
	if err != nil {
		return false
	}
	head := strings.ToUpper(string(b))
	return head == "GET " || head == "POST" || head == "HEAD" || head == "PUT " || head == "OPTI"
}

// ServeHTTP demuxes one inbound connection: normal HTTP → decoy page;
// WebSocket upgrade on path → returns the hijacked conn wrapped in ws
// framing. Returns nil when the request was not an upgrade.
func ServeHTTP(conn net.Conn, br *bufio.Reader, path string) net.Conn {
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return nil
	}
	if req.Method != http.MethodGet ||
		req.Header.Get("Upgrade") != "websocket" ||
		req.Header.Get("Connection") != "Upgrade" ||
		req.Header.Get("Sec-WebSocket-Version") != "13" ||
		req.URL.Path != path {
		writeDecoy(conn, req, path)
		_ = conn.Close()
		return nil
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		_ = conn.Close()
		return nil
	}
	acc := wsAccept(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acc + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return nil
	}
	return &wsConn{Conn: conn, rbuf: br, server: true}
}

func writeDecoy(conn net.Conn, req *http.Request, cloakPath string) {
	body := decoyPage
	status := "200 OK"
	if req.URL.Path == cloakPath && req.Method == http.MethodGet {
		// plausible: the "asset" path exists but requires the upgrade —
		// track the CONFIGURED path so probing different paths sees
		// behavior consistent with the real one
		status = "404 Not Found"
		body = "not found\n"
	}
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, contentTypeFor(req.URL.Path), len(body), body)
}

func contentTypeFor(p string) string {
	if strings.HasSuffix(p, ".html") || p == "/" {
		return "text/html; charset=utf-8"
	}
	return "text/plain; charset=utf-8"
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Dial upgrades an HTTP request on addr to a WebSocket on path and
// returns the framed connection.
func Dial(conn net.Conn, path, hostHeader string) (net.Conn, error) {
	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])
	if hostHeader == "" {
		hostHeader = "localhost"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: Mozilla/5.0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		return nil, fmt.Errorf("cloak: upgrade refused: %s", strings.TrimSpace(line))
	}
	// consume headers, verify accept
	accept := ""
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		if i := strings.Index(h, ":"); i > 0 && strings.EqualFold(h[:i], "Sec-WebSocket-Accept") {
			accept = strings.TrimSpace(h[i+1:])
		}
	}
	if accept != wsAccept(key) {
		return nil, fmt.Errorf("cloak: bad Sec-WebSocket-Accept (not a botjim cloak peer?)")
	}
	return &wsConn{Conn: conn, rbuf: br, server: false}, nil
}

// wsConn frames a net.Conn with RFC 6455 binary frames. Writes become
// frames; reads return frame payloads (oversized payloads spill into a
// pending buffer). Ping/pong are skipped, close yields EOF.
type wsConn struct {
	net.Conn
	rbuf    *bufio.Reader
	server  bool // server: unmasked frames out; client: masked
	wmu     sync.Mutex
	rm      sync.Mutex
	pending []byte
	eof     bool
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 1<<20 {
			n = 1 << 20
		}
		if err := c.writeFrame(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *wsConn) writeFrame(p []byte) error {
	hdr := []byte{0x82} // FIN | binary
	var maskKey [4]byte
	switch {
	case len(p) < 126:
		hdr = append(hdr, byte(len(p)))
	case len(p) <= 0xFFFF:
		hdr = append(hdr, 126, 0, 0)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(p)))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(len(p)))
	}
	if !c.server {
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}
		hdr[1] |= 0x80
		hdr = append(hdr, maskKey[:]...)
	}
	if _, err := c.Conn.Write(hdr); err != nil {
		return err
	}
	out := p
	if !c.server {
		out = make([]byte, len(p))
		copy(out, p)
		for i := range out {
			out[i] ^= maskKey[i%4]
		}
	}
	_, err := c.Conn.Write(out)
	return err
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.rm.Lock()
	defer c.rm.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.eof {
		return 0, io.EOF
	}
	for {
		b0, err := c.rbuf.ReadByte()
		if err != nil {
			return 0, err
		}
		fin := b0&0x80 != 0
		opcode := b0 & 0x0F
		b1, err := c.rbuf.ReadByte()
		if err != nil {
			return 0, err
		}
		masked := b1&0x80 != 0
		// RFC 6455: client→server frames MUST be masked. botjim's own
		// writer never fragments (always FIN|binary), so a data frame that
		// is unmasked (on the server side) or a continuation/un-FIN frame
		// is not a real peer — reject rather than mis-parse.
		if c.server && !masked && opcode < 0x8 {
			return 0, fmt.Errorf("cloak: unmasked client frame")
		}
		if opcode == 0x0 || (!fin && opcode < 0x8) {
			return 0, fmt.Errorf("cloak: unexpected fragmented frame")
		}
		plen := int64(b1 & 0x7F)
		switch plen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.rbuf, ext[:]); err != nil {
				return 0, err
			}
			plen = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.rbuf, ext[:]); err != nil {
				return 0, err
			}
			plen = int64(binary.BigEndian.Uint64(ext[:]))
		}
		if plen < 0 || plen > 17<<20 {
			// a 127-length frame with the top bit set decodes to a
			// negative int64; without this guard make([]byte, plen) panics
			// and one packet crashes the process pre-auth
			return 0, fmt.Errorf("cloak: implausible frame %d", plen)
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.rbuf, mask[:]); err != nil {
				return 0, err
			}
		}
		if opcode == 0x8 { // close
			c.eof = true
			return 0, io.EOF
		}
		if opcode == 0x9 || opcode == 0xA { // ping/pong: drain, continue
			if _, err := io.CopyN(io.Discard, c.rbuf, plen); err != nil {
				return 0, err
			}
			continue
		}
		buf := make([]byte, plen)
		if _, err := io.ReadFull(c.rbuf, buf); err != nil {
			return 0, err
		}
		if masked {
			for i := range buf {
				buf[i] ^= mask[i%4]
			}
		}
		n := copy(p, buf)
		c.pending = buf[n:]
		return n, nil
	}
}
