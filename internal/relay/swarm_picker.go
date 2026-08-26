package relay

import (
	"sync"
)

// picker is the swarm joiner's live piece-selection state. It replaces the
// old "sort once, feed a channel" model with a rarest-first picker that
// re-prioritizes as peers announce, plus an endgame mode that duplicates
// the last few outstanding pieces across peers so one slow peer cannot
// stall completion at 99%, plus per-chunk retry with a failure ceiling.
type picker struct {
	mu       sync.Mutex
	pending  map[chunkTask]struct{} // not yet handed to a worker
	inflight map[chunkTask]int      // task → workers currently fetching it
	done     map[chunkTask]struct{} // completed (written + verified)
	fails    map[chunkTask]int      // consecutive full-fetch failures
	total    int
	maxFails int
}

func newPicker(tasks []chunkTask) *picker {
	p := &picker{
		pending:  make(map[chunkTask]struct{}, len(tasks)),
		inflight: map[chunkTask]int{},
		done:     map[chunkTask]struct{}{},
		fails:    map[chunkTask]int{},
		total:    len(tasks),
		maxFails: 6, // a chunk unavailable from every source this many rounds → fatal
	}
	for _, t := range tasks {
		p.pending[t] = struct{}{}
	}
	return p
}

// pick returns the next chunk to fetch. It prefers the rarest pending
// chunk (using the current peer availability); when nothing is pending but
// pieces are still in flight it returns one of those to DUPLICATE across
// another peer (endgame). ok=false means every chunk is done.
func (p *picker) pick(rarity map[rarityKey]int) (chunkTask, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.done) >= p.total {
		return chunkTask{}, false, false
	}
	if len(p.pending) > 0 {
		// rarest pending chunk (fewest peers hold it)
		best, bestR, has := chunkTask{}, int(^uint(0)>>1), false
		for t := range p.pending {
			r := rarity[rarityKey{t.file, t.chunk}]
			if !has || r < bestR {
				best, bestR, has = t, r, true
			}
		}
		delete(p.pending, best)
		p.inflight[best]++
		return best, true, false
	}
	// endgame: nothing pending, but some pieces are still being fetched by
	// (possibly slow) workers — hand one to a free worker to race it
	for t := range p.inflight {
		p.inflight[t]++
		return t, true, true // endgame=true
	}
	return chunkTask{}, false, false
}

// complete marks a piece written+verified. Returns true if this is the
// first completion (the caller should write it; a duplicate that arrives
// second gets false and discards its bytes).
func (p *picker) complete(t chunkTask) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[t] > 0 {
		p.inflight[t]--
		if p.inflight[t] <= 0 {
			delete(p.inflight, t)
		}
	}
	if _, already := p.done[t]; already {
		return false
	}
	p.done[t] = struct{}{}
	delete(p.pending, t)
	delete(p.fails, t)
	return true
}

// fail records a failed fetch of t. Returns fatal=true when the chunk has
// failed from every source too many rounds (nothing can complete it).
func (p *picker) fail(t chunkTask) (fatal bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[t] > 0 {
		p.inflight[t]--
		if p.inflight[t] <= 0 {
			delete(p.inflight, t)
		}
	}
	if _, already := p.done[t]; already {
		return false // a duplicate lost the race; harmless
	}
	p.fails[t]++
	if p.fails[t] >= p.maxFails {
		return true
	}
	p.pending[t] = struct{}{} // retry it (a peer may appear via re-announce)
	return false
}

func (p *picker) allDone() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.done) >= p.total
}

// remaining reports pending+inflight count (for the endgame trigger).
func (p *picker) remaining() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total - len(p.done)
}
