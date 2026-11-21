package spamfilter

import (
	"sync"
	"time"
)

// Limiter caps the bytes per second read over all connections that share
// it: a token bucket holding at most one second's worth.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	tokens float64
	last   time.Time
}

// NewLimiter returns a limiter for mbit megabits per second, or nil (no
// limit) when mbit <= 0.
func NewLimiter(mbit float64) *Limiter {
	if mbit <= 0 {
		return nil
	}
	r := mbit * 1e6 / 8
	return &Limiter{rate: r, tokens: r, last: time.Now()}
}

// wait takes n bytes from the bucket, sleeping while it is in debt.
func (l *Limiter) wait(n int) {
	l.mu.Lock()
	now := time.Now()
	l.tokens = min(l.rate, l.tokens+now.Sub(l.last).Seconds()*l.rate) - float64(n)
	l.last = now
	debt := -l.tokens
	l.mu.Unlock()
	if debt > 0 {
		time.Sleep(time.Duration(debt / l.rate * float64(time.Second)))
	}
}
