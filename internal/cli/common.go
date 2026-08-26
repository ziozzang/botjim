package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/relay"
	"github.com/ziozzang/botjim/internal/transport"
)

// preserveBits maps parsed flags onto the wire's preserve mask.
func preserveBits(f *flags) uint16 {
	p := uint16(protocol.PreserveXattr | protocol.PreserveHardlink | protocol.PreserveSparse)
	if f.noXattr {
		p &^= protocol.PreserveXattr
	}
	if f.noSparse {
		p &^= protocol.PreserveSparse
	}
	if f.devices {
		p |= protocol.PreserveDevices
	}
	if f.owners != "none" {
		p |= protocol.PreserveOwners
	}
	if f.owners == "name" {
		p |= protocol.PreserveUname
	}
	return p
}

// probeCmd checks reachability with a handshake + ping and exits.
func probeCmd(ctx context.Context, addr string) int {
	start := time.Now()
	sess, err := transport.Dial(ctx, addr, protocol.FeatAll, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe failed:", err)
		return 2
	}
	defer sess.Close()
	rtt, err := sess.RTT()
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: session ok, ping failed:", err)
		return 0
	}
	fmt.Printf("%s reachable: handshake %.1fms, ping %.1fms, features %#x\n",
		addr, float64(time.Since(start).Microseconds())/1000, float64(rtt.Microseconds())/1000, sess.HS.FeatureBits)
	return 0
}

// relay helpers re-exported for the command files (short names in cli).
func GenerateCode() string        { return relay.GenerateCode() }
func ValidateCode(c string) error { return relay.ValidateCode(c) }
func FormatCode(c string) string  { return relay.FormatCode(c) }
func Offer(ctx context.Context, via, code string) (net.Conn, error) {
	return relay.Offer(ctx, via, code)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
