// Package audit implements a tamper-evident journal: every entry embeds
// the hash of the previous one, so any edit, deletion or reordering breaks
// the chain at that point. `Verify` walks the chain and reports the first
// intact prefix.
//
// Entry (one JSON object per line):
//
//	{"seq":1,"ts":"...","event":"file-done","detail":{...},
//	 "prev":"<sha256 of the previous line's hash field>","hash":"<sha256>"}
//
// hash = sha256(prev ‖ canonical-json(entry without hash))
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Entry is one journal record.
type Entry struct {
	Seq    int             `json:"seq"`
	TS     string          `json:"ts"`
	Event  string          `json:"event"`
	Detail json.RawMessage `json:"detail,omitempty"`
	Prev   string          `json:"prev"`
	Hash   string          `json:"hash"`
}

// Journal appends hash-chained entries to one file. Safe for concurrent
// use; the sequence and chain head advance under a lock, and each Append
// fsyncs so a crash cannot lose a linked prefix.
type Journal struct {
	mu   sync.Mutex
	path *os.File
	seq  int
	head string // hash of the last entry
}

// Open appends to path (created when missing), resuming the chain from
// the last intact entry found there.
func Open(path string) (*Journal, error) {
	// resume: read the tail entry for seq + head, and repair a torn
	// tail — a crash mid-Append leaves a partial line that would
	// otherwise swallow every future entry (O_APPEND writes onto it and
	// ReadAll stops there forever while Append keeps succeeding)
	entries, validLen, torn, err := readAllValid(path)
	if err != nil {
		return nil, err
	}
	j := &Journal{}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		j.seq = last.Seq
		j.head = last.Hash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err == nil && fi.Size() > int64(validLen) {
		if !torn {
			// complete-but-unparseable lines mid-file are tampering or
			// corruption, never a torn tail: truncating would DESTROY the
			// evidence the journal exists to keep. Fail closed instead.
			f.Close()
			return nil, fmt.Errorf("audit: %s has unreadable entries after byte %d (not a torn tail) — inspect with 'botjim audit verify' before appending", path, validLen)
		}
		if err := f.Truncate(int64(validLen)); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: torn tail repair: %w", err)
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	j.path = f
	return j, nil
}

// Append records one event; detail may be nil.
func (j *Journal) Append(ts, event string, detail any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if string(raw) == "null" {
		raw = nil
	}
	j.seq++
	e := Entry{Seq: j.seq, TS: ts, Event: event, Detail: raw, Prev: j.head}
	e.Hash = hashEntry(&e)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := j.path.Write(line); err != nil {
		return err
	}
	j.head = e.Hash
	return j.path.Sync()
}

// Close releases the file.
func (j *Journal) Close() error {
	if j.path == nil {
		return nil
	}
	return j.path.Close()
}

func hashEntry(e *Entry) string {
	h := sha256.New()
	h.Write([]byte(e.Prev))
	fmt.Fprintf(h, "\x00%d\x00%s\x00%s\x00", e.Seq, e.TS, e.Event)
	h.Write(e.Detail)
	return hex.EncodeToString(h.Sum(nil))
}

// ReadAll streams the journal. It returns entries and stops at the first
// unreadable line (a torn tail from a crash is not an error).
func ReadAll(path string) ([]Entry, error) {
	entries, _, _, err := readAllValid(path)
	return entries, err
}

// readAllValid parses the intact prefix of the journal and reports how
// many bytes it spans. torn means everything past the prefix is a single
// trailing partial line with no newline — the signature of a crash during
// Append, safe to truncate before the next append (otherwise that append
// lands on the partial line and becomes invisible forever). Unparseable
// bytes followed by more lines are corruption/tampering, NOT torn.
func readAllValid(path string) ([]Entry, int, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	var out []Entry
	valid := 0
	for len(b) > 0 {
		idx := bytes.IndexByte(b, '\n')
		if idx < 0 {
			// trailing partial line (no newline): torn tail
			return out, valid, true, nil
		}
		line := b[:idx]
		if len(line) > 0 {
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				// a complete newline-terminated line that does not parse:
				// the intact prefix ends here, and the rest is evidence
				return out, valid, false, nil
			}
			out = append(out, e)
		}
		valid += idx + 1
		b = b[idx+1:]
	}
	return out, valid, false, nil
}

// Verify walks the chain and returns the number of intact entries plus
// the first break ("" when the whole journal verifies).
func Verify(path string) (intact int, breakAt string, err error) {
	entries, err := ReadAll(path)
	if err != nil {
		return 0, "", err
	}
	prev := ""
	for i, e := range entries {
		if e.Prev != prev {
			return i, fmt.Sprintf("entry %d: prev %s does not link to %s", e.Seq, e.Prev, prev), nil
		}
		if e.Hash != hashEntry(&e) {
			return i, fmt.Sprintf("entry %d: hash does not match its contents", e.Seq), nil
		}
		prev = e.Hash
	}
	return len(entries), "", nil
}
