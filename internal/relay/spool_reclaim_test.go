package relay

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// TestSpoolReclaimsMidStream: a long stream through a small mem limit must
// not grow the spill file to the whole transfer size — drained bytes are
// reclaimed mid-stream, so the physical file stays bounded.
func TestSpoolReclaimsMidStream(t *testing.T) {
	dir := t.TempDir()
	// limit 4 MiB, spill after 64 KiB in memory
	s := newSpoolBuf(4<<20, 64<<10, dir)
	total := int64(64 << 20) // 64 MiB streamed
	block := make([]byte, 256<<10)
	for i := range block {
		block[i] = byte(i)
	}

	var maxFile int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // reader: drain slowly enough that writer spills
		defer wg.Done()
		buf := make([]byte, 128<<10)
		got := int64(0)
		for {
			n, err := s.Read(buf)
			got += int64(n)
			s.mu.Lock()
			if s.file != nil {
				if sz := s.fileWrOff; sz > maxFile {
					mu.Lock()
					maxFile = sz
					mu.Unlock()
				}
			}
			s.mu.Unlock()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				return
			}
		}
		if got != total {
			t.Errorf("read %d, want %d", got, total)
		}
	}()

	written := int64(0)
	for written < total {
		n := int64(len(block))
		if total-written < n {
			n = total - written
		}
		if _, err := s.Write(block[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	s.CloseWrite()
	wg.Wait()

	// the spill file must never approach the full 64 MiB — with reclamation
	// it should stay within a small multiple of the 4 MiB live limit
	if maxFile > 16<<20 {
		t.Fatalf("spill file grew to %d bytes (no mid-stream reclaim); expected << total", maxFile)
	}
	_ = bytes.MinRead
}
