package ratelimit

import (
	"sync"
	"time"
)

// Limiter is an in-memory sliding-window rate limiter keyed by a string
type Limiter struct {
	mu       sync.Mutex
	window   time.Duration
	maxReqs  int
	now      func() time.Time
	requests map[string][]time.Time
	calls    int
}

// sweepInterval is how many Allow calls run between full sweeps of idle keys
const sweepInterval = 1024

// New creates a Limiter allowing up to maxReqs requests per sliding window
func New(maxReqs int, window time.Duration) *Limiter {
	return &Limiter{
		window:   window,
		maxReqs:  maxReqs,
		now:      time.Now,
		requests: make(map[string][]time.Time),
	}
}

// Allow reports whether a request for key is inside the configured limit.
// Allowed requests are recorded; denied requests are not.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.calls%sweepInterval == 0 {
		l.sweep()
	}
	l.calls++

	now := l.now()
	cutoff := now.Add(-l.window)

	timestamps := l.requests[key]
	firstValid := 0
	for firstValid < len(timestamps) && timestamps[firstValid].Before(cutoff) {
		firstValid++
	}
	if firstValid > 0 {
		timestamps = timestamps[firstValid:]
		l.requests[key] = timestamps
	}

	if len(timestamps) >= l.maxReqs {
		return false
	}

	l.requests[key] = append(timestamps, now)
	return true
}

// sweep drops keys whose most recent request has left the window, so tenants or
// clients that stopped sending requests do not retain state indefinitely.
// ponytail: full O(n) scan under l.mu every sweepInterval calls. Key set is
// bounded (active tenants + per-signin-client IPs within one window), so this
// is a sub-millisecond amortized cost; an LRU/heap structure to make eviction
// O(k) would add real complexity for no measured benefit. Revisit if profiling
// shows contention.
func (l *Limiter) sweep() {
	now := l.now()
	cutoff := now.Add(-l.window)
	for key, timestamps := range l.requests {
		if len(timestamps) == 0 || timestamps[len(timestamps)-1].Before(cutoff) {
			delete(l.requests, key)
		}
	}
}