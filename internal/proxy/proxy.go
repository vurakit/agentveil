package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/vura/privacyguard/internal/auth"
	"github.com/vura/privacyguard/internal/detector"
	"github.com/vura/privacyguard/internal/promptguard"
	"github.com/vura/privacyguard/internal/vault"
)

// Config holds proxy configuration
type Config struct {
	TargetURL string // upstream LLM API base URL
}

// Option configures the Server
type Option func(*Server)

// WithAuth adds API key authentication
func WithAuth(am *auth.Manager) Option {
	return func(s *Server) { s.auth = am }
}

// WithPromptGuard adds prompt injection protection
func WithPromptGuard(pg *promptguard.Guard) Option {
	return func(s *Server) { s.promptGuard = pg }
}

// Server is the PrivacyGuard reverse proxy
type Server struct {
	proxy       *httputil.ReverseProxy
	target      *url.URL
	detector    *detector.Detector
	vault       *vault.Vault
	auth        *auth.Manager
	promptGuard *promptguard.Guard
}

// New creates a new proxy Server
func New(cfg Config, det *detector.Detector, v *vault.Vault, opts ...Option) (*Server, error) {
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, err
	}

	s := &Server{
		target:   target,
		detector: det,
		vault:    v,
	}

	for _, opt := range opts {
		opt(s)
	}

	s.proxy = &httputil.ReverseProxy{
		Director:       s.director,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
	}

	return s, nil
}

// MaxBodySize is the maximum allowed request body size (10MB)
const MaxBodySize = 10 * 1024 * 1024

// Handler returns the HTTP handler with middleware chain
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Chain: [auth →] [promptGuard →] securityEnforcer → roleMiddleware → proxy
	var handler http.Handler = s.securityEnforcer(s.roleMiddleware(s.proxy))
	if s.promptGuard != nil {
		handler = promptguard.Middleware(s.promptGuard)(handler)
	}
	if s.auth != nil {
		handler = s.auth.Middleware(handler)
	}
	mux.Handle("/v1/", handler)
	mux.Handle("/audit", http.HandlerFunc(s.handleAudit))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}

// director rewrites the request to the upstream target and anonymizes PII
func (s *Server) director(req *http.Request) {
	// Rewrite host/scheme to target
	req.URL.Scheme = s.target.Scheme
	req.URL.Host = s.target.Host
	req.Host = s.target.Host

	// Skip body processing for non-POST/PUT
	if req.Body == nil || (req.Method != http.MethodPost && req.Method != http.MethodPut) {
		return
	}

	// Limit request body size to prevent abuse
	limited := io.LimitReader(req.Body, MaxBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		log.Printf("[proxy] error reading request body: %v", err)
		return
	}
	req.Body.Close()

	if int64(len(body)) > MaxBodySize {
		log.Printf("[proxy] request body too large: %d bytes", len(body))
		return
	}

	sessionID := extractSessionID(req)
	anonymized, mapping := s.detector.Anonymize(string(body))

	if len(mapping) > 0 {
		log.Printf("[proxy] anonymized %d PII entities for session %s", len(mapping), sessionID)

		if err := s.vault.Store(context.Background(), sessionID, mapping); err != nil {
			log.Printf("[proxy] vault store error: %v", err)
		}
	}

	req.Body = io.NopCloser(bytes.NewBufferString(anonymized))
	req.ContentLength = int64(len(anonymized))
}

// modifyResponse handles outbound rehydration for non-streaming responses
func (s *Server) modifyResponse(resp *http.Response) error {
	contentType := resp.Header.Get("Content-Type")

	// For SSE streams, we handle rehydration in the streaming transport
	if strings.Contains(contentType, "text/event-stream") {
		sessionID := extractSessionIDFromResponse(resp)
		resp.Body = newSSERehydrator(resp.Body, s.vault, sessionID)
		return nil
	}

	// Standard JSON response - read, rehydrate, replace
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	sessionID := extractSessionIDFromResponse(resp)
	role := resp.Request.Header.Get("X-User-Role")

	rehydrated := s.rehydrateText(string(body), sessionID, role)

	resp.Body = io.NopCloser(bytes.NewBufferString(rehydrated))
	resp.ContentLength = int64(len(rehydrated))

	return nil
}

// rehydrateText replaces pseudonym tokens with real values, applying role masking
func (s *Server) rehydrateText(text, sessionID, role string) string {
	mappings, err := s.vault.LookupAll(context.Background(), sessionID)
	if err != nil || len(mappings) == 0 {
		return text
	}

	result := text
	for token, original := range mappings {
		replacement := original
		if strings.EqualFold(role, "viewer") {
			replacement = maskValue(original)
		}
		result = strings.ReplaceAll(result, token, replacement)
	}

	return result
}

// maskValue hides ~70% of a value for viewer role
func maskValue(val string) string {
	runes := []rune(val)
	n := len(runes)
	if n <= 3 {
		return val
	}

	visible := n * 30 / 100 // show ~30%
	if visible < 2 {
		visible = 2
	}
	front := visible / 2
	back := visible - front

	masked := make([]rune, n)
	for i := range masked {
		if i < front || i >= n-back {
			masked[i] = runes[i]
		} else {
			masked[i] = 'x'
		}
	}
	return string(masked)
}

// errorHandler handles proxy errors
func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[proxy] upstream error: %v", err)
	http.Error(w, `{"error":"upstream_error","message":"failed to reach LLM provider"}`, http.StatusBadGateway)
}

// extractSessionID gets session ID from request header or generates one
func extractSessionID(req *http.Request) string {
	sid := req.Header.Get("X-Session-ID")
	if sid == "" {
		sid = req.Header.Get("X-Request-ID")
	}
	if sid == "" {
		sid = "default"
	}
	return sid
}

func extractSessionIDFromResponse(resp *http.Response) string {
	if resp.Request != nil {
		return extractSessionID(resp.Request)
	}
	return "default"
}
