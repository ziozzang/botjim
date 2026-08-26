package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/botjim/internal/protocol"
)

func startBenchServer(b *testing.B, cfg ServerConfig) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	srv := NewServer(cfg)
	done := make(chan struct{})
	go func() { _ = srv.Serve(ln); close(done) }()
	return ln.Addr().String(), func() { srv.Stop(); <-done }
}

// BenchmarkManySmallFiles pushes N small files, the known weak spot.
func BenchmarkManySmallFiles(b *testing.B) {
	src := b.TempDir()
	const n = 2000
	blob := make([]byte, 64<<10)
	for i := range blob {
		blob[i] = byte(i)
	}
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		p := filepath.Join(src, fmt.Sprintf("f%05d.bin", i))
		os.WriteFile(p, blob, 0o644)
		paths[i] = p
	}
	b.SetBytes(int64(n) * int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := b.TempDir()
		addr, stop := startBenchServer(b, ServerConfig{
			Root: dst, AllowPush: true, Parallel: 8, Fsync: true,
		})
		res := RunTransfer(context.Background(), ClientConfig{
			Addr: addr, Direction: protocol.DirPush, Paths: paths, Parallel: 8,
		})
		if res.Err != nil {
			b.Fatal(res.Err)
		}
		stop()
	}
}

// BenchmarkSingleLargeFile pushes one big file (throughput ceiling).
func BenchmarkSingleLargeFile(b *testing.B) {
	src := b.TempDir()
	blob := make([]byte, 256<<20) // 256MB
	for i := range blob {
		blob[i] = byte(i * 7)
	}
	p := filepath.Join(src, "big.bin")
	os.WriteFile(p, blob, 0o644)
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := b.TempDir()
		addr, stop := startBenchServer(b, ServerConfig{
			Root: dst, AllowPush: true, Parallel: 8, Fsync: true,
		})
		res := RunTransfer(context.Background(), ClientConfig{
			Addr: addr, Direction: protocol.DirPush, Paths: []string{p}, Parallel: 8,
		})
		if res.Err != nil {
			b.Fatal(res.Err)
		}
		stop()
	}
}

// BenchmarkSingleLargeFilePass measures an AEAD-encrypted transfer, where
// the per-chunk crc32c should now be OFF (AEAD already authenticates).
func BenchmarkSingleLargeFilePass(b *testing.B) {
	src := b.TempDir()
	blob := make([]byte, 256<<20)
	for i := range blob {
		blob[i] = byte(i * 7)
	}
	p := filepath.Join(src, "big.bin")
	os.WriteFile(p, blob, 0o644)
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := b.TempDir()
		addr, stop := startBenchServer(b, ServerConfig{
			Root: dst, AllowPush: true, Parallel: 8, Fsync: true, Pass: "benchpass",
		})
		res := RunTransfer(context.Background(), ClientConfig{
			Addr: addr, Direction: protocol.DirPush, Paths: []string{p}, Parallel: 8,
			Pass: "benchpass",
		})
		if res.Err != nil {
			b.Fatal(res.Err)
		}
		stop()
	}
}
