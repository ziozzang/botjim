package cli

import (
	"github.com/ziozzang/botjim/internal/cloak"
	"github.com/ziozzang/botjim/internal/relay"
	"github.com/ziozzang/botjim/internal/transport"
)

func init() {
	transport.CipherFactory = relay.EncryptConnBound
	transport.PassphraseSecret = relay.PassphraseSecret
	transport.CloakDialer = cloak.Dial
	transport.CloakSniff = cloak.SniffCloaked
	transport.CloakServe = cloak.ServeHTTP
	transport.CloakPlain = cloak.PlainConn
}
