package services

import (
	"sync"
	"time"
)

var (
	globalLimiter *RateLimiter
	once          sync.Once
)

// RateLimiter represents a simple rate limiter for API requests
type RateLimiter struct {
	tokens   chan struct{}
	interval time.Duration
}

// GetGlobalRateLimiter returns the singleton instance of RateLimiter
func GetGlobalRateLimiter() *RateLimiter {
	once.Do(func() {
		globalLimiter = newRateLimiter(4) // 4 requests per minute as per VirusTotal limit
	})
	return globalLimiter
}

// newRateLimiter creates a new rate limiter with specified requests per minute
func newRateLimiter(requestsPerMinute int) *RateLimiter {
	tokens := make(chan struct{}, requestsPerMinute)
	// Initially fill the tokens
	for i := 0; i < requestsPerMinute; i++ {
		tokens <- struct{}{}
	}

	limiter := &RateLimiter{
		tokens:   tokens,
		interval: time.Minute / time.Duration(requestsPerMinute),
	}

	// Start token replenishment
	go limiter.replenish()
	return limiter
}

func (r *RateLimiter) replenish() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case r.tokens <- struct{}{}:
		default:
			// Channel is full, skip
		}
	}
}

func (r *RateLimiter) Wait() {
	<-r.tokens
}
