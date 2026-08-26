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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// resume: read the tail entry for seq + head
	entries, err := ReadAll(path)
	j := &Journal{}
	if err == nil && len(entries) > 0 {
		last := entries[len(entries)-1]
		j.seq = last.Seq
		j.head = last.Hash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
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
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			break // torn tail
		}
		out = append(out, e)
	}
	return out, nil
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

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
