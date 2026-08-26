package engine

import (
	"context"
	"sync"
	"time"
)

// limiter is a token bucket shared by the sender's workers: a bounded
// burst starts fast, then chunks wait for tokens at --limit bytes/s.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	tokens float64
	burst  float64
	last   time.Time
}

func newLimiter(bytesPerSec int64) *limiter {
	burst := float64(bytesPerSec) // one second of burst
	if burst > 64<<20 {
		burst = 64 << 20
	}
	return &limiter{rate: float64(bytesPerSec), tokens: burst, burst: burst, last: time.Now()}
}

// acquire waits for n bytes of budget; ctx cancels the wait.
func (l *limiter) acquire(ctx context.Context, n int64) error {
	if l == nil || l.rate <= 0 {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		deficit := float64(n) - l.tokens
		l.mu.Unlock()
		wait := time.Duration(deficit / l.rate * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
