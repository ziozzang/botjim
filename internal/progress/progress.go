// Package progress holds the live counters both engines and the TUI share.
//
// Design: chunk-level events fire thousands of times a second on fast links,
// which would flood any channel. Instead the engines bump atomics and the
// renderers poll Snapshot() at 4–10Hz. Discrete events (file done, errors,
// log lines) go through a small buffered channel — those must never be lost
// to a full progress queue.
package progress

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// FileState is the per-file view the TUI renders.
type FileState struct {
	ID    uint32
	Path  string
	Size  int64
	Done  int64 // verified bytes at destination (or sent bytes for sender view)
	State string
	Err   string
}

// Snapshot is a consistent-ish view for one transfer.
type Snapshot struct {
	Scanning     bool
	TotalFiles   uint64 // manifest files seen so far (grows during scan)
	TotalBytes   uint64
	DoneFiles    uint64
	ErrFiles     uint64
	SkipFiles    uint64
	SentBytes    uint64 // bytes moved this session
	SkippedBytes uint64 // bytes not sent (already at destination)
	Files        []FileState
	RateBps      float64
	ETA          time.Duration
	Elapsed      time.Duration
}

// Event is a discrete occurrence worth showing or logging.
type Event struct {
	Kind string // "file-done", "file-error", "warn", "info", "cancel"
	Path string
	Msg  string
	At   time.Time
}

// Registry is the per-transfer counter set.
type Registry struct {
	scanning     atomic.Bool
	totalFiles   atomic.Uint64
	totalBytes   atomic.Uint64
	doneFiles    atomic.Uint64
	errFiles     atomic.Uint64
	skipFiles    atomic.Uint64
	sentBytes    atomic.Uint64
	skippedBytes atomic.Uint64

	start time.Time

	mu    sync.RWMutex
	files map[uint32]*fileRow
	order []uint32

	// rate tracking
	rateMu   sync.Mutex
	rateHist []ratePoint

	Events chan Event

	logMu  sync.Mutex
	logW   io.Writer // optional persistent transfer log
	sinkMu sync.Mutex
	sink   func(Event) // optional structured sink (audit journal)
}

// SetEventSink installs a structured event sink (the audit journal).
func (r *Registry) SetEventSink(f func(Event)) {
	r.sinkMu.Lock()
	r.sink = f
	r.sinkMu.Unlock()
}

// SetLogWriter installs a plain-text sink: every event is appended there
// in addition to the in-memory channel (the TUI consumes the channel).
func (r *Registry) SetLogWriter(w io.Writer) {
	r.logMu.Lock()
	r.logW = w
	r.logMu.Unlock()
}

type fileRow struct {
	path  string
	size  int64
	done  int64
	state string
	err   string
}

type ratePoint struct {
	at   time.Time
	sent uint64
}

// New creates a registry and starts its clock.
func New() *Registry {
	return &Registry{start: time.Now(), files: map[uint32]*fileRow{}, Events: make(chan Event, 256)}
}

// Start/StopScanning mark the manifest-scan phase.
func (r *Registry) SetScanning(b bool) { r.scanning.Store(b) }

// AddFile registers a file (during manifest streaming).
func (r *Registry) AddFile(id uint32, path string, size int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totalBytes.Add(uint64(size))
	r.totalFiles.Add(1)
	if _, ok := r.files[id]; !ok {
		r.files[id] = &fileRow{path: path, size: size, state: "wait"}
		r.order = append(r.order, id)
	}
}

// FileDoneBytes records progress within a file (bytes verified/sent).
func (r *Registry) FileDoneBytes(id uint32, n int64) {
	r.mu.Lock()
	if f, ok := r.files[id]; ok {
		f.done += n
	}
	r.mu.Unlock()
}

// FileStateUpdate sets a file's state string ("wait", "active", "done",
// "error", "skipped"). Same-state updates are no-ops so hot paths can set
// "active" on every chunk.
func (r *Registry) FileStateUpdate(id uint32, state, errMsg string) {
	r.mu.Lock()
	if f, ok := r.files[id]; ok {
		if f.state == state && state == "active" {
			r.mu.Unlock()
			return
		}
		f.state = state
		f.err = errMsg
		if state == "done" {
			f.done = f.size
		}
	}
	r.mu.Unlock()
	switch state {
	case "done":
		r.doneFiles.Add(1)
	case "error":
		r.errFiles.Add(1)
	case "skipped":
		r.skipFiles.Add(1)
	}
}

// AddSent accumulates moved bytes.
func (r *Registry) AddSent(n int64) { r.sentBytes.Add(uint64(n)) }

// SentBytes returns bytes moved so far.
func (r *Registry) SentBytes() uint64 { return r.sentBytes.Load() }

// AddSkipped accumulates bytes not moved (already present).
func (r *Registry) AddSkipped(n int64) { r.skippedBytes.Add(uint64(n)) }

// Emit queues a discrete event; drops (never blocks) when the queue is
// full, and appends a timestamped line to the persistent log sink.
func (r *Registry) Emit(kind, path, msg string) {
	now := time.Now()
	r.sinkMu.Lock()
	sink := r.sink
	r.sinkMu.Unlock()
	if sink != nil {
		sink(Event{Kind: kind, Path: path, Msg: msg, At: now})
	}
	r.logMu.Lock()
	if r.logW != nil {
		fmt.Fprintf(r.logW, "%s %-10s %s %s\n", now.Format(time.RFC3339), kind, path, msg)
	}
	r.logMu.Unlock()
	select {
	case r.Events <- Event{Kind: kind, Path: path, Msg: msg, At: now}:
	default:
	}
}

// Snapshot captures the current state and computes rate/ETA from the recent
// sent-bytes history.
func (r *Registry) Snapshot() Snapshot {
	now := time.Now()
	s := Snapshot{
		Scanning:     r.scanning.Load(),
		TotalFiles:   r.totalFiles.Load(),
		TotalBytes:   r.totalBytes.Load(),
		DoneFiles:    r.doneFiles.Load(),
		ErrFiles:     r.errFiles.Load(),
		SkipFiles:    r.skipFiles.Load(),
		SentBytes:    r.sentBytes.Load(),
		SkippedBytes: r.skippedBytes.Load(),
		Elapsed:      now.Sub(r.start),
	}

	r.mu.RLock()
	// TUI file table: in-flight files first (the ones actually moving),
	// then queued ones newest-first, then errors — capped so million-file
	// trees stay cheap.
	s.Files = make([]FileState, 0, 24)
	for pass := 0; pass < 3; pass++ {
		want := "active"
		cap24 := 12
		if pass == 1 {
			want, cap24 = "wait", 24
		} else if pass == 2 {
			want, cap24 = "error", 48
		}
		for i := len(r.order) - 1; i >= 0 && len(s.Files) < cap24; i-- {
			id := r.order[i]
			if f, ok := r.files[id]; ok && f.state == want {
				s.Files = append(s.Files, FileState{ID: id, Path: f.path, Size: f.size, Done: f.done, State: f.state, Err: f.err})
			}
		}
	}
	r.mu.RUnlock()

	// rate: EWMA over samples recorded by the rate ticker
	r.rateMu.Lock()
	sent := s.SentBytes
	r.rateHist = append(r.rateHist, ratePoint{at: now, sent: sent})
	cutoff := now.Add(-4 * time.Second) // short window: the number should feel live
	drop := 0
	for drop < len(r.rateHist) && r.rateHist[drop].at.Before(cutoff) {
		drop++
	}
	if drop > 0 {
		r.rateHist = r.rateHist[drop:]
	}
	if len(r.rateHist) >= 2 {
		a, b := r.rateHist[0], r.rateHist[len(r.rateHist)-1]
		if dt := b.at.Sub(a.at).Seconds(); dt > 0.1 {
			s.RateBps = float64(b.sent-a.sent) / dt
		}
	}
	r.rateMu.Unlock()

	total := s.TotalBytes - s.SkippedBytes
	if s.RateBps > 0 && s.SentBytes < total {
		s.ETA = time.Duration(float64(total-s.SentBytes)/s.RateBps) * time.Second
	}
	return s
}

// Elapsed returns wall time since the registry started.
func (r *Registry) Elapsed() time.Duration { return time.Since(r.start) }
