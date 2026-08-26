package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// spoolBuf is the relay's store-and-forward buffer for one direction of a
// paired session: a fast sender can outrun a slow receiver up to a
// configurable budget while the relay still only ever holds ciphertext.
//
// Policy: bytes stay in memory up to memLimit; beyond that the memory
// contents spill to a file in dir (which is unlinked immediately, so the
// space returns on crash); the total held never exceeds limit — a writer
// beyond the limit blocks (TCP backpressure) until the reader drains. The
// reader drains in FIFO order: spilled file bytes first, then memory.
type spoolBuf struct {
	limit    int64 // total bytes held (memory + file)
	memLimit int64 // stay-in-memory threshold before spilling
	dir      string

	mu        sync.Mutex
	cond      *sync.Cond
	mem       bytes.Buffer
	file      *os.File
	path      string
	fileWrOff int64
	fileRdOff int64
	buffered  int64
	eof       bool
	err       error
}

func newSpoolBuf(limit, memLimit int64, dir string) *spoolBuf {
	s := &spoolBuf{limit: limit, memLimit: memLimit, dir: dir}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *spoolBuf) held() int64 { return s.buffered }

// Write buffers p, blocking while the spool is at its limit.
func (s *spoolBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for s.buffered >= s.limit && s.err == nil {
			s.cond.Wait()
		}
		if s.err != nil {
			return written, s.err
		}
		n := len(p)
		if room := s.limit - s.buffered; room < int64(n) {
			n = int(room)
		}
		if n == 0 {
			continue // limit 0: reject
		}
		chunk := p[:n]
		// spill first if memory is over threshold and disk is available:
		// keeps FIFO simple (file is always older than memory)
		if int64(s.mem.Len()) >= s.memLimit && s.dir != "" {
			if err := s.spillLocked(); err != nil {
				s.failLocked(err)
				return written, err
			}
		}
		if s.file != nil {
			// already spilling: append to the file
			n2, err := s.file.WriteAt(chunk, s.fileWrOff)
			if err != nil {
				s.failLocked(err)
				return written, err
			}
			s.fileWrOff += int64(n2)
			s.buffered += int64(n2)
			written += n2
			p = p[n2:]
		} else {
			n2, _ := s.mem.Write(chunk)
			s.buffered += int64(n2)
			written += n2
			p = p[n2:]
		}
		s.cond.Broadcast()
	}
	return written, nil
}

// spillLocked flushes the memory buffer to the spill file.
func (s *spoolBuf) spillLocked() error {
	if s.mem.Len() == 0 {
		return nil
	}
	if s.file == nil {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return err
		}
		var name [8]byte
		if _, err := rand.Read(name[:]); err != nil {
			return err
		}
		p := filepath.Join(s.dir, "spool-"+hex.EncodeToString(name[:]))
		f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_ = os.Remove(p) // unlink now: space returns when the session ends
		s.file = f
		s.path = p
	}
	if _, err := s.file.WriteAt(s.mem.Bytes(), s.fileWrOff); err != nil {
		return err
	}
	s.fileWrOff += int64(s.mem.Len())
	s.mem.Reset()
	return nil
}

// Read drains the spool in FIFO order (file first, then memory), blocking
// while empty until EOF or failure.
func (s *spoolBuf) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.file != nil && s.fileRdOff < s.fileWrOff {
			n, err := s.file.ReadAt(p, s.fileRdOff)
			if n > 0 {
				s.fileRdOff += int64(n)
				s.buffered -= int64(n)
				if s.fileRdOff == s.fileWrOff && s.mem.Len() == 0 {
					s.maybeTruncateLocked()
				}
				s.cond.Broadcast()
				return n, nil
			}
			if err != nil && err != io.EOF {
				s.failLocked(err)
				return 0, err
			}
			// EOF at write offset: fall through to memory
		}
		if s.mem.Len() > 0 {
			n, _ := s.mem.Read(p)
			s.buffered -= int64(n)
			s.cond.Broadcast()
			return n, nil
		}
		if s.eof {
			return 0, io.EOF
		}
		if s.err != nil {
			return 0, s.err
		}
		s.cond.Wait()
	}
}

// CloseWrite marks the producer done.
func (s *spoolBuf) CloseWrite() {
	s.mu.Lock()
	s.eof = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Fail marks the spool dead and wakes everyone; the spill file is dropped.
func (s *spoolBuf) Fail(err error) {
	s.mu.Lock()
	s.failLocked(err)
	s.mu.Unlock()
}

func (s *spoolBuf) failLocked(err error) {
	if s.err == nil {
		s.err = err
	}
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
	s.cond.Broadcast()
}

// Finish drains-and-cleans: called by the relay when the session ends.
func (s *spoolBuf) Finish() {
	s.mu.Lock()
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
	s.mu.Unlock()
}

// maybeTruncateLocked releases spill-file space once everything is drained.
func (s *spoolBuf) maybeTruncateLocked() {
	if s.file != nil && s.fileRdOff == s.fileWrOff && s.mem.Len() == 0 && s.eof {
		_ = s.file.Truncate(0)
		s.fileRdOff, s.fileWrOff = 0, 0
		if _, err := s.file.Seek(0, io.SeekStart); err == nil {
			// reuse the file for a possible next spill
		}
	}
}

// usedDisk reports whether this spool spilled to disk.
func (s *spoolBuf) usedDisk() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path != ""
}

var errSpoolClosed = errors.New("spool closed")
