package router

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Provider wraps config with runtime state
type Provider struct {
	Config  ProviderConfig
	Target  *url.URL
	Proxy   *httputil.ReverseProxy
	healthy atomic.Bool
}

// Router routes requests to multiple LLM providers
type Router struct {
	providers    map[string]*Provider
	routes       map[string]string // path prefix → provider name
	defaultRoute string
	strategy     LoadBalanceStrategy
	fallback     FallbackConfig

	// Round-robin state
	mu       sync.Mutex
	rrIndex  int
	rrList   []string // provider names for round-robin

	// Weighted state
	weightedList []string // expanded list based on weights

	// Request modifier — applied before forwarding (e.g. PII anonymization)
	requestModifier func(*http.Request)
	// Response modifier — applied after receiving response (e.g. PII rehydration)
	responseModifier func(*http.Response) error
}

// New creates a Router from config
func New(cfg *RouterConfig) (*Router, error) {
	r := &Router{
		providers:    make(map[string]*Provider),
		routes:       make(map[string]string),
		defaultRoute: cfg.DefaultRoute,
		strategy:     cfg.LoadBalance,
		fallback:     cfg.Fallback,
	}

	for _, pc := range cfg.Providers {
		if !pc.Enabled {
			continue
		}
		target, err := url.Parse(pc.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("provider %s: invalid URL %s: %w", pc.Name, pc.BaseURL, err)
		}

		p := &Provider{
			Config: pc,
			Target: target,
		}
		p.healthy.Store(true)

		// Create reverse proxy for this provider
		p.Proxy = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.Host = target.Host

				// Prepend target base path if present
				// e.g. base_url=https://api.example.com/api → /chat becomes /api/chat
				if target.Path != "" && target.Path != "/" {
					req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
				}

				// Set provider API key if configured
				if pc.APIKey != "" {
					switch pc.AuthMethod {
					case "query":
						q := req.URL.Query()
						q.Set(pc.AuthParam, pc.APIKey)
						req.URL.RawQuery = q.Encode()
					case "x-api-key":
						req.Header.Set("x-api-key", pc.APIKey)
					default: // "header" — Bearer token
						req.Header.Set("Authorization", "Bearer "+pc.APIKey)
					}
				}

				// Apply custom request modifier (PII anonymization)
				if r.requestModifier != nil {
					slog.Debug("applying request modifier", "provider", pc.Name, "path", req.URL.Path)
					r.requestModifier(req)
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				if r.responseModifier != nil {
					return r.responseModifier(resp)
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				slog.Warn("provider error", "provider", pc.Name, "error", err)
				p.healthy.Store(false)
				// Schedule health recovery
				go func() {
					time.Sleep(30 * time.Second)
					p.healthy.Store(true)
					slog.Info("provider health restored", "provider", pc.Name)
				}()
				http.Error(w, fmt.Sprintf(`{"error":"provider_error","provider":"%s"}`, pc.Name), http.StatusBadGateway)
			},
			Transport: &http.Transport{
				ResponseHeaderTimeout: time.Duration(pc.TimeoutSec) * time.Second,
			},
		}

		r.providers[pc.Name] = p
	}

	if len(r.providers) == 0 {
		return nil, fmt.Errorf("no enabled providers")
	}

	// Build routes
	for _, rc := range cfg.Routes {
		r.routes[rc.PathPrefix] = rc.Provider
	}

	// Set default if not configured
	if r.defaultRoute == "" {
		for name := range r.providers {
			r.defaultRoute = name
			break
		}
	}

	// Build round-robin and weighted lists
	r.buildLoadBalanceLists()

	return r, nil
}

// SetRequestModifier sets a function that modifies requests before forwarding
func (r *Router) SetRequestModifier(fn func(*http.Request)) {
	r.requestModifier = fn
}

// SetResponseModifier sets a function that modifies responses before returning to client
func (r *Router) SetResponseModifier(fn func(*http.Response) error) {
	r.responseModifier = fn
}

func (r *Router) buildLoadBalanceLists() {
	// Priority-sorted list
	var names []string
	for name := range r.providers {
		names = append(names, name)
	}

	// Sort by priority (lower = higher priority)
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if r.providers[names[j]].Config.Priority < r.providers[names[i]].Config.Priority {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	r.rrList = names

	// Weighted list
	r.weightedList = nil
	for _, name := range names {
		p := r.providers[name]
		for range p.Config.Weight {
			r.weightedList = append(r.weightedList, name)
		}
	}
}

// ServeHTTP routes the request to the appropriate provider
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	providerName := r.resolveProvider(req)

	if r.fallback.Enabled {
		r.serveWithFallback(w, req, providerName)
		return
	}

	p, ok := r.providers[providerName]
	if !ok || !p.healthy.Load() {
		http.Error(w, `{"error":"no_healthy_provider"}`, http.StatusServiceUnavailable)
		return
	}

	// Strip the route prefix from the path
	req.URL.Path = r.stripRoutePrefix(req.URL.Path)

	slog.Debug("routing request", "provider", providerName, "path", req.URL.Path)
	p.Proxy.ServeHTTP(w, req)
}

func (r *Router) serveWithFallback(w http.ResponseWriter, req *http.Request, primaryName string) {
	// Build fallback order: primary first, then others by priority
	order := []string{primaryName}
	for _, name := range r.rrList {
		if name != primaryName {
			order = append(order, name)
		}
	}

	attempts := r.fallback.MaxAttempts
	if attempts > len(order) {
		attempts = len(order)
	}

	for i := 0; i < attempts; i++ {
		name := order[i]
		p, ok := r.providers[name]
		if !ok || !p.healthy.Load() {
			slog.Warn("provider unhealthy, trying next", "provider", name, "attempt", i+1)
			continue
		}

		// Use a response recorder to detect errors
		rec := &fallbackRecorder{
			ResponseWriter: w,
			statusCode:     0,
			headerWritten:  false,
		}

		originalPath := req.URL.Path
		req.URL.Path = r.stripRoutePrefix(originalPath)

		slog.Debug("routing request (fallback)", "provider", name, "attempt", i+1, "path", req.URL.Path)
		p.Proxy.ServeHTTP(rec, req)

		// If successful or client error, return (don't retry on 4xx)
		if rec.statusCode > 0 && rec.statusCode < 500 {
			return
		}

		// Server error — try next provider
		slog.Warn("provider returned error, falling back",
			"provider", name, "status", rec.statusCode, "attempt", i+1)
		req.URL.Path = originalPath

		if i < attempts-1 && r.fallback.RetryDelaySec > 0 {
			time.Sleep(time.Duration(r.fallback.RetryDelaySec) * time.Second)
		}
	}

	http.Error(w, `{"error":"all_providers_failed"}`, http.StatusBadGateway)
}

// resolveProvider determines which provider to use for a request
func (r *Router) resolveProvider(req *http.Request) string {
	// 1. Check explicit provider header
	if provider := req.Header.Get("X-Veil-Provider"); provider != "" {
		if _, ok := r.providers[provider]; ok {
			return provider
		}
	}

	// 2. Check path-based routes
	for prefix, provider := range r.routes {
		if strings.HasPrefix(req.URL.Path, prefix) {
			return provider
		}
	}

	// 3. Load balancing across providers
	switch r.strategy {
	case StrategyRoundRobin:
		return r.nextRoundRobin()
	case StrategyWeighted:
		return r.nextWeighted()
	default: // StrategyPriority
		return r.nextPriority()
	}
}

func (r *Router) nextRoundRobin() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.rrList) == 0 {
		return r.defaultRoute
	}

	// Find next healthy provider
	for range r.rrList {
		name := r.rrList[r.rrIndex%len(r.rrList)]
		r.rrIndex++
		if p := r.providers[name]; p != nil && p.healthy.Load() {
			return name
		}
	}
	return r.defaultRoute
}

func (r *Router) nextWeighted() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.weightedList) == 0 {
		return r.defaultRoute
	}

	for range r.weightedList {
		name := r.weightedList[r.rrIndex%len(r.weightedList)]
		r.rrIndex++
		if p := r.providers[name]; p != nil && p.healthy.Load() {
			return name
		}
	}
	return r.defaultRoute
}

func (r *Router) nextPriority() string {
	for _, name := range r.rrList {
		if p := r.providers[name]; p != nil && p.healthy.Load() {
			return name
		}
	}
	return r.defaultRoute
}

// singleJoiningSlash joins two URL path segments with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// stripRoutePrefix removes the route prefix from the path
func (r *Router) stripRoutePrefix(path string) string {
	for prefix := range r.routes {
		if strings.HasPrefix(path, prefix) {
			stripped := strings.TrimPrefix(path, prefix)
			if stripped == "" {
				return "/"
			}
			if !strings.HasPrefix(stripped, "/") {
				stripped = "/" + stripped
			}
			return stripped
		}
	}
	return path
}

// GetProviders returns the list of provider names
func (r *Router) GetProviders() []string {
	var names []string
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// IsHealthy returns the health status of a provider
func (r *Router) IsHealthy(name string) bool {
	if p, ok := r.providers[name]; ok {
		return p.healthy.Load()
	}
	return false
}

// SetHealthy manually sets provider health (for testing)
func (r *Router) SetHealthy(name string, healthy bool) {
	if p, ok := r.providers[name]; ok {
		p.healthy.Store(healthy)
	}
}

// fallbackRecorder captures the response to detect server errors
type fallbackRecorder struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
}

func (fr *fallbackRecorder) WriteHeader(code int) {
	fr.statusCode = code
	fr.headerWritten = true
	fr.ResponseWriter.WriteHeader(code)
}

func (fr *fallbackRecorder) Write(b []byte) (int, error) {
	if !fr.headerWritten {
		fr.statusCode = http.StatusOK
		fr.headerWritten = true
	}
	return fr.ResponseWriter.Write(b)
}
