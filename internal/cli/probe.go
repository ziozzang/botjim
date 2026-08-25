package cli

import (
	"context"

	"github.com/ziozzang/botjim/internal/protocol"
	"github.com/ziozzang/botjim/internal/transport"
)

// transportDialProbe opens a session for --probe.
func transportDialProbe(ctx context.Context, addr string) (*transport.Session, error) {
	return transport.Dial(ctx, addr, protocol.FeatAll, nil)
}
