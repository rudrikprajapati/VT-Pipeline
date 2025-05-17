package services

import (
	"sync"
	"time"
)

var (
	globalLimiter *RateLimiter
	once          sync.Once
)

type RateLimiter struct {
	delay       time.Duration
	lastRequest time.Time
	mutex       sync.Mutex
}

// GetGlobalRateLimiter returns the singleton instance of RateLimiter
func GetGlobalRateLimiter() *RateLimiter {
	once.Do(func() {
		globalLimiter = newRateLimiter()
	})
	return globalLimiter
}

// newRateLimiter creates a new rate limiter with 15 second delay
func newRateLimiter() *RateLimiter {
	return &RateLimiter{
		delay:       15 * time.Second,
		lastRequest: time.Now().Add(-15 * time.Second),
	}
}

// Wait ensures at least 15 seconds have passed since the last request
func (r *RateLimiter) Wait() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRequest)
	if elapsed < r.delay {
		time.Sleep(r.delay - elapsed)
	}
	r.lastRequest = time.Now()
}
