package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/botjim/internal/protocol"
)

// sparsePattern: zero, data, zero — exercises hole skipping and the final
// truncate-length guarantee.
func sparsePattern(n int) []byte {
	b := make([]byte, n)
	copy(b[n/2:], []byte("data in the middle of a hole"))
	return b
}

func bytesRepeat(s string, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i += len(s) {
		copy(out[i:], s)
	}
	return out
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// TestMatrixPushPull verifies every direction × compression × parallelism
// combination moves identical bytes.
func TestMatrixPushPull(t *testing.T) {
	for _, dir := range []uint8{protocol.DirPush, protocol.DirPull} {
		for _, alg := range []uint8{0, 1, 2} {
			for _, par := range []int{1, 4} {
				name := fmt.Sprintf("dir%d/alg%d/par%d", dir, alg, par)
				t.Run(name, func(t *testing.T) {
					src := t.TempDir()
					dst := t.TempDir()
					want := map[string]string{}
					write := func(rel string, b []byte) {
						p := filepath.Join(src, rel)
						os.MkdirAll(filepath.Dir(p), 0o755)
						if err := os.WriteFile(p, b, 0o644); err != nil {
							t.Fatal(err)
						}
						sum := sha256.Sum256(b)
						want[rel] = hex.EncodeToString(sum[:])
					}
					write("a/rand.bin", randBytes(5<<20))
					write("a/b/text.bin", bytesRepeat("botjim ", 9<<20))
					write("a/b/empty", nil)
					write("a/b/c/deep.bin", randBytes(1<<20))
					write("sparse.bin", sparsePattern(9<<20))

					addr, _, stop := startTestServer(t, dst, true, true)
					defer stop()
					paths := []string{filepath.Join(src, "a"), filepath.Join(src, "sparse.bin")}
					if dir == protocol.DirPull {
						// push first so the server has the data, then pull back
						res := RunTransfer(context.Background(), ClientConfig{
							Addr: addr, Direction: protocol.DirPush, Paths: paths,
							Compression: 1, Parallel: 4, Preserve: protocol.PreserveHardlink | protocol.PreserveSparse,
						})
						if res.Err != nil {
							t.Fatalf("seed push: %v", res.Err)
						}
						pullDst := t.TempDir()
						res = RunTransfer(context.Background(), ClientConfig{
							Addr: addr, Direction: protocol.DirPull, Paths: []string{"a", "sparse.bin"},
							DestRoot: pullDst, Compression: alg, Parallel: par,
							Preserve: protocol.PreserveHardlink | protocol.PreserveSparse,
						})
						if res.Err != nil {
							t.Fatalf("pull: %v", res.Err)
						}
						verifyTree(t, pullDst, want)
						return
					}
					res := RunTransfer(context.Background(), ClientConfig{
						Addr: addr, Direction: dir, Paths: paths,
						Compression: alg, Parallel: par,
						Preserve: protocol.PreserveHardlink | protocol.PreserveSparse,
					})
					if res.Err != nil {
						t.Fatalf("push: %v", res.Err)
					}
					if len(res.Report.Errors) > 0 {
						t.Fatalf("errors: %+v", res.Report.Errors)
					}
					verifyTree(t, dst, want)
				})
			}
		}
	}
}

func verifyTree(t *testing.T, root string, want map[string]string) {
	t.Helper()
	for rel, hash := range want {
		p := filepath.Join(root, rel)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		if !fi.Mode().IsRegular() {
			t.Fatalf("%s not regular", rel)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
		if got := hex.EncodeToString(h.Sum(nil)); got != hash {
			t.Fatalf("%s: hash mismatch", rel)
		}
	}
}

// TestResumeAfterCancellation interrupts a transfer partway and resumes it.
func TestResumeAfterCancellation(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	big := randBytes(64 << 20)
	if err := os.WriteFile(filepath.Join(src, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(src, fmt.Sprintf("s%02d.bin", i)), randBytes(64<<10), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	addr, srv, stop := startTestServer(t, dst, true, true)
	defer stop()

	// kill the client mid-transfer
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	_ = RunTransfer(ctx, ClientConfig{
		Addr: addr, Direction: protocol.DirPush,
		Paths:       []string{filepath.Join(src, "big.bin"), src},
		Compression: 1, Parallel: 4, Preserve: protocol.PreserveSparse,
	})

	waitIdle(t, srv)

	// resume to completion
	res2 := RunTransfer(context.Background(), ClientConfig{
		Addr: addr, Direction: protocol.DirPush,
		Paths:       []string{filepath.Join(src, "big.bin"), src},
		Compression: 1, Parallel: 4, Preserve: protocol.PreserveSparse,
	})
	if res2.Err != nil {
		t.Fatalf("resume: %v", res2.Err)
	}
	if len(res2.Report.Errors) > 0 {
		t.Fatalf("resume errors: %+v", res2.Report.Errors)
	}
	sum := sha256.Sum256(big)
	f, err := os.Open(filepath.Join(dst, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(sum[:]) {
		t.Fatal("big.bin content mismatch after resume")
	}
	// no sidecar/part leftovers after full completion
	var leftovers []string
	filepath.Walk(dst, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			base := filepath.Base(p)
			if strings.Contains(base, ".fs-part-") || strings.Contains(base, ".fs-meta-") {
				leftovers = append(leftovers, p)
			}
		}
		return nil
	})
	if len(leftovers) > 0 {
		t.Fatalf("leftover transfer state: %v", leftovers)
	}
}
