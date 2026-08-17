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
}

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