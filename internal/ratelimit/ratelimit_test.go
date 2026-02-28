package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	l := New(Config{
		RequestsPerMinute: 3,
		WindowSize:        1 * time.Second,
		CleanupInterval:   10 * time.Second,
	})
	defer l.Close()

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !l.Allow("test-ip") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th should be rejected
	if l.Allow("test-ip") {
		t.Error("4th request should be rejected")
	}
}

func TestAllow_DifferentKeys(t *testing.T) {
	l := New(Config{
		RequestsPerMinute: 1,
		WindowSize:        1 * time.Second,
		CleanupInterval:   10 * time.Second,
	})
	defer l.Close()

	if !l.Allow("ip-a") {
		t.Error("ip-a first request should be allowed")
	}
	if !l.Allow("ip-b") {
		t.Error("ip-b first request should be allowed (separate bucket)")
	}
	if l.Allow("ip-a") {
		t.Error("ip-a second request should be rejected")
	}
}

func TestAllow_WindowReset(t *testing.T) {
	l := New(Config{
		RequestsPerMinute: 1,
		WindowSize:        50 * time.Millisecond,
		CleanupInterval:   10 * time.Second,
	})
	defer l.Close()

	l.Allow("key")
	if l.Allow("key") {
		t.Error("should be rejected within window")
	}

	time.Sleep(60 * time.Millisecond)

	if !l.Allow("key") {
		t.Error("should be allowed after window reset")
	}
}

func TestRetryAfter(t *testing.T) {
	l := New(Config{
		RequestsPerMinute: 1,
		WindowSize:        5 * time.Second,
		CleanupInterval:   10 * time.Second,
	})
	defer l.Close()

	l.Allow("key")
	l.Allow("key") // rejected

	ra := l.RetryAfter("key")
	if ra <= 0 || ra > 6 {
		t.Errorf("expected RetryAfter 1-6, got %d", ra)
	}
}

func TestMiddleware_RateLimited(t *testing.T) {
	l := New(Config{
		RequestsPerMinute: 1,
		WindowSize:        1 * time.Second,
		CleanupInterval:   10 * time.Second,
	})
	defer l.Close()

	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request: OK
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec.Code)
	}

	// Second request: rate limited
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}
