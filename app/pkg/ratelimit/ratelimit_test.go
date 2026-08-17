package ratelimit

import (
	"testing"
	"time"

	. "github.com/getfider/fider/app/pkg/assert"
)

func TestLimiter_AllowsUpToLimit(t *testing.T) {
	RegisterT(t)

	limiter := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		Expect(limiter.Allow("key-1")).IsTrue()
	}
	Expect(limiter.Allow("key-1")).IsFalse()
}

func TestLimiter_KeysAreIndependent(t *testing.T) {
	RegisterT(t)

	limiter := New(1, time.Minute)
	Expect(limiter.Allow("key-1")).IsTrue()
	Expect(limiter.Allow("key-1")).IsFalse()
	Expect(limiter.Allow("key-2")).IsTrue()
}

func TestLimiter_SlidingWindow(t *testing.T) {
	RegisterT(t)

	limiter := New(2, 10*time.Second)
	current := time.Unix(0, 0)
	limiter.now = func() time.Time { return current }

	Expect(limiter.Allow("key")).IsTrue()
	current = current.Add(9 * time.Second)
	Expect(limiter.Allow("key")).IsTrue()
	current = current.Add(1 * time.Second)
	Expect(limiter.Allow("key")).IsFalse()

	// once the oldest request leaves the window, room opens up again
	current = current.Add(1 * time.Second)
	Expect(limiter.Allow("key")).IsTrue()
}

func TestLimiter_EmptyKey(t *testing.T) {
	RegisterT(t)

	limiter := New(0, time.Minute)
	Expect(limiter.Allow("key")).IsFalse()
}