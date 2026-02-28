package privacyguard

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// Config holds PrivacyGuard proxy configuration
type Config struct {
	// ProxyURL is the PrivacyGuard proxy address (e.g. "http://localhost:8080")
	ProxyURL string

	// APIKey is the customer's original LLM API key (forwarded as-is)
	APIKey string

	// Role determines data masking level: "admin" (full), "viewer" (masked 70%)
	Role string

	// SessionID groups PII mappings together. Auto-generated if empty.
	SessionID string
}

// Transport is an http.RoundTripper that injects PrivacyGuard headers
// into every request and rewrites the target URL to the proxy.
type Transport struct {
	cfg  Config
	base http.RoundTripper
}

// NewTransport creates a Transport wrapping the given base (or http.DefaultTransport)
func NewTransport(cfg Config, base http.RoundTripper) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	if cfg.SessionID == "" {
		cfg.SessionID = uuid.NewString()
	}
	if cfg.Role == "" {
		cfg.Role = "admin"
	}
	return &Transport{cfg: cfg, base: base}
}

// RoundTrip rewrites the request to go through PrivacyGuard proxy
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid mutating the original
	r := req.Clone(req.Context())

	// Inject PrivacyGuard headers
	r.Header.Set("X-Session-ID", t.cfg.SessionID)
	r.Header.Set("X-User-Role", t.cfg.Role)

	// Forward the original API key
	if t.cfg.APIKey != "" && r.Header.Get("Authorization") == "" {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.cfg.APIKey))
	}

	return t.base.RoundTrip(r)
}

// NewHTTPClient returns an *http.Client pre-configured to route through PrivacyGuard
func NewHTTPClient(cfg Config) *http.Client {
	return &http.Client{
		Transport: NewTransport(cfg, nil),
	}
}
