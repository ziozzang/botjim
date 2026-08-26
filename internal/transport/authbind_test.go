package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/relay"
)

func init() {
	// wire the record layer the same way the app does
	CipherFactory = relay.EncryptConnBound
	PassphraseSecret = relay.PassphraseSecret
}

// runSecure drives secureConn on both ends of a pipe with the given
// handshakes, returning both results.
func runSecure(t *testing.T, cliHS, srvHS *protocol.Handshake, sec SecOpts, tamper func(cliSeen, srvSeen *protocol.Handshake)) (net.Conn, net.Conn, error, error) {
	t.Helper()
	c, s := net.Pipe()
	// what each side BELIEVES the peer sent (tamper simulates a MITM
	// rewriting the plaintext handshake in flight)
	cliSeesSrv := *srvHS
	srvSeesCli := *cliHS
	if tamper != nil {
		tamper(&cliSeesSrv, &srvSeesCli)
	}
	var cc, sc net.Conn
	var ce, se error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); cc, ce = secureConn(c, cliHS, &cliSeesSrv, sec, true) }()
	go func() { defer wg.Done(); sc, se = secureConn(s, srvHS, &srvSeesCli, sec, false) }()
	wg.Wait()
	return cc, sc, ce, se
}

func mkHS(t *testing.T, features uint64, sec SecOpts) *protocol.Handshake {
	h, err := protocol.NewHandshake(features)
	if err != nil {
		t.Fatal(err)
	}
	h.Flags |= sec.flags()
	return h
}

// TestBindDetectsFeatureDowngrade: a MITM that flips the peer's feature
// bits (as each side sees them) must break the secure handshake.
func TestBindDetectsFeatureDowngrade(t *testing.T) {
	sec := SecOpts{Token: "tok"}
	cli := mkHS(t, protocol.FeatAll, sec)
	srv := mkHS(t, protocol.FeatAll, sec)
	// clean run first: both sides agree → success
	cc, sc, ce, se := runSecure(t, cli, srv, sec, nil)
	if ce != nil || se != nil {
		t.Fatalf("clean secure handshake failed: cli=%v srv=%v", ce, se)
	}
	_ = cc
	_ = sc

	// tampered run: the client is told the server's features are downgraded
	// (FeatChunkSum cleared). The server still binds its REAL features, so
	// the two bind values differ and confirmation must fail.
	cli2 := mkHS(t, protocol.FeatAll, sec)
	srv2 := mkHS(t, protocol.FeatAll, sec)
	cc2, sc2, ce2, se2 := runSecure(t, cli2, srv2, sec, func(cliSeen, srvSeen *protocol.Handshake) {
		cliSeen.FeatureBits &^= protocol.FeatChunkSum // MITM strips it from what the client sees
	})
	if ce2 == nil && se2 == nil {
		if cc2 != nil {
			cc2.Close()
		}
		if sc2 != nil {
			sc2.Close()
		}
		t.Fatal("feature-bit downgrade NOT detected — bind failed to protect the handshake")
	}
}

// TestBindCleanRoundtrip: an unmolested token session encrypts and the
// two ends can actually talk (sanity that bind doesn't break the happy path).
func TestBindCleanRoundtrip(t *testing.T) {
	sec := SecOpts{Token: "abc", Pass: "def"}
	cli := mkHS(t, protocol.FeatAll, sec)
	srv := mkHS(t, protocol.FeatAll, sec)
	cc, sc, ce, se := runSecure(t, cli, srv, sec, nil)
	if ce != nil || se != nil {
		t.Fatalf("clean roundtrip failed: cli=%v srv=%v", ce, se)
	}
	msg := []byte("ping-through-the-record-layer")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := cc.Write(msg); err != nil {
			t.Error(err)
		}
	}()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	<-done
	if !bytes.Equal(got, msg) {
		t.Fatal("record layer garbled the payload")
	}
	cc.Close()
	sc.Close()
}
