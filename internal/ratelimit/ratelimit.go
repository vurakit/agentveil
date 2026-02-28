package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Config holds rate limiter settings
type Config struct {
	RequestsPerMinute int           // max requests per window per key
	WindowSize        time.Duration // sliding window size
	CleanupInterval   time.Duration // how often to purge expired entries
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		RequestsPerMinute: 60,
		WindowSize:        1 * time.Minute,
		CleanupInterval:   5 * time.Minute,
	}
}

type window struct {
	count   int
	resetAt time.Time
}

// Limiter implements a sliding window rate limiter
type Limiter struct {
	cfg     Config
	mu      sync.Mutex
	windows map[string]*window
	stop    chan struct{}
}

// New creates a rate Limiter and starts background cleanup
func New(cfg Config) *Limiter {
	l := &Limiter{
		cfg:     cfg,
		windows: make(map[string]*window),
		stop:    make(chan struct{}),
	}
	go l.cleanup()
	return l
}

// Allow checks if a request from the given key is allowed
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	w, ok := l.windows[key]

	if !ok || now.After(w.resetAt) {
		l.windows[key] = &window{
			count:   1,
			resetAt: now.Add(l.cfg.WindowSize),
		}
		return true
	}

	if w.count >= l.cfg.RequestsPerMinute {
		return false
	}

	w.count++
	return true
}

// RetryAfter returns seconds until the window resets for a key
func (l *Limiter) RetryAfter(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.windows[key]
	if !ok {
		return 0
	}

	remaining := time.Until(w.resetAt)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds()) + 1
}

// Middleware returns an HTTP middleware that rate-limits by client IP
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractIP(r)

		if !l.Allow(key) {
			retryAfter := l.RetryAfter(key)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w,
				`{"error":"rate_limited","message":"too many requests"}`,
				http.StatusTooManyRequests,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Close stops the background cleanup goroutine
func (l *Limiter) Close() {
	close(l.stop)
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for key, w := range l.windows {
				if now.After(w.resetAt) {
					delete(l.windows, key)
				}
			}
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (behind load balancer)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
