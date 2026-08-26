package relay

import (
	"sync"

	"golang.org/x/crypto/scrypt"
)

var (
	pskMu    sync.Mutex
	pskCache = map[string][]byte{}
)

// PassphraseSecret stretches a passphrase into a 32-byte PSK. The salt is
// a fixed domain constant: per-session randomness comes from the X25519
// exchange inside EncryptConn, so the stretch only sets an attacker's
// per-guess cost (scrypt N=2^15, ~32MiB). Both sides derive identical
// bytes; results are cached per passphrase.
func PassphraseSecret(pass string) []byte {
	pskMu.Lock()
	defer pskMu.Unlock()
	if v, ok := pskCache[pass]; ok {
		return v
	}
	v, err := scrypt.Key([]byte(pass), []byte("botjim-direct-pass/v1"), 1<<15, 8, 1, 32)
	if err != nil {
		return nil
	}
	pskCache[pass] = v
	return v
}
