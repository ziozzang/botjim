//go:build ignore

// sign-sums signs a file with an ed25519 private key (hex-encoded 64-byte
// seed+pub, botjim's key format) and writes the detached hex signature.
//
//	go run scripts/sign-sums.go <keyfile> <infile> <sigfile>
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: sign-sums <keyfile> <infile> <sigfile>")
		os.Exit(2)
	}
	keyHex, err := os.ReadFile(os.Args[1])
	must(err)
	priv, err := hex.DecodeString(string(trim(keyHex)))
	must(err)
	if len(priv) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "bad key length %d (want %d)\n", len(priv), ed25519.PrivateKeySize)
		os.Exit(2)
	}
	body, err := os.ReadFile(os.Args[2])
	must(err)
	sig := ed25519.Sign(ed25519.PrivateKey(priv), body)
	must(os.WriteFile(os.Args[3], []byte(hex.EncodeToString(sig)+"\n"), 0o644))
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
