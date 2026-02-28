package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// === Config Tests ===

func TestParseConfig_Valid(t *testing.T) {
	yaml := `
providers:
  - name: openai
    base_url: https://api.openai.com
    api_key: sk-test123
    model: gpt-4
    priority: 1
    weight: 3
    enabled: true
  - name: anthropic
    base_url: https://api.anthropic.com
    api_key: sk-ant-test
    model: claude-sonnet-4-20250514
    priority: 2
    weight: 1
    enabled: true

routes:
  - path_prefix: /v1/openai
    provider: openai
  - path_prefix: /v1/anthropic
    provider: anthropic

fallback:
  enabled: true
  max_attempts: 3

load_balance: weighted
default_route: openai
`
	cfg, err := ParseConfig(yaml)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if len(cfg.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(cfg.Providers))
	}
	if cfg.Providers[0].Name != "openai" {
		t.Errorf("expected openai, got %s", cfg.Providers[0].Name)
	}
	if cfg.LoadBalance != StrategyWeighted {
		t.Errorf("expected weighted, got %s", cfg.LoadBalance)
	}
	if cfg.DefaultRoute != "openai" {
		t.Errorf("expected openai default, got %s", cfg.DefaultRoute)
	}
	if len(cfg.Routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(cfg.Routes))
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	yaml := `
providers:
  - name: openai
    base_url: https://api.openai.com
    enabled: true
`
	cfg, err := ParseConfig(yaml)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if cfg.LoadBalance != StrategyPriority {
		t.Errorf("expected priority default, got %s", cfg.LoadBalance)
	}
	if cfg.Fallback.MaxAttempts != 3 {
		t.Errorf("expected 3 max attempts default, got %d", cfg.Fallback.MaxAttempts)
	}
	if cfg.Providers[0].Weight != 1 {
		t.Errorf("expected weight 1 default, got %d", cfg.Providers[0].Weight)
	}
	if cfg.Providers[0].TimeoutSec != 30 {
		t.Errorf("expected 30s timeout default, got %d", cfg.Providers[0].TimeoutSec)
	}
}

func TestParseConfig_MissingName(t *testing.T) {
	yaml := `
providers:
  - base_url: https://api.openai.com
    enabled: true
`
	_, err := ParseConfig(yaml)
	if err == nil {
		t.Error("expected error for missing provider name")
	}
}

func TestParseConfig_MissingURL(t *testing.T) {
	yaml := `
providers:
  - name: openai
    enabled: true
`
	_, err := ParseConfig(yaml)
	if err == nil {
		t.Error("expected error for missing base_url")
	}
}

func TestParseConfig_InvalidRoute(t *testing.T) {
	yaml := `
providers:
  - name: openai
    base_url: https://api.openai.com
    enabled: true
routes:
  - path_prefix: /v1/unknown
    provider: nonexistent
`
	_, err := ParseConfig(yaml)
	if err == nil {
		t.Error("expected error for unknown provider in route")
	}
}

func TestParseConfig_InvalidDefaultRoute(t *testing.T) {
	yaml := `
providers:
  - name: openai
    base_url: https://api.openai.com
    enabled: true
default_route: nonexistent
`
	_, err := ParseConfig(yaml)
	if err == nil {
		t.Error("expected error for invalid default_route")
	}
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	_, err := ParseConfig("not: valid: yaml: [")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// === Router Tests ===

func newTestConfig() *RouterConfig {
	return &RouterConfig{
		Providers: []ProviderConfig{
			{Name: "primary", BaseURL: "http://primary.test", Priority: 1, Weight: 2, Enabled: true, TimeoutSec: 5},
			{Name: "secondary", BaseURL: "http://secondary.test", Priority: 2, Weight: 1, Enabled: true, TimeoutSec: 5},
		},
		Routes: []RouteConfig{
			{PathPrefix: "/v1/primary", Provider: "primary"},
			{PathPrefix: "/v1/secondary", Provider: "secondary"},
		},
		Fallback:     FallbackConfig{Enabled: false},
		LoadBalance:  StrategyPriority,
		DefaultRoute: "primary",
	}
}

func TestNewRouter(t *testing.T) {
	cfg := newTestConfig()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	providers := r.GetProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}

	if !r.IsHealthy("primary") {
		t.Error("primary should be healthy")
	}
	if !r.IsHealthy("secondary") {
		t.Error("secondary should be healthy")
	}
}

func TestNewRouter_NoProviders(t *testing.T) {
	cfg := &RouterConfig{
		Providers: []ProviderConfig{
			{Name: "disabled", BaseURL: "http://test", Enabled: false},
		},
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for no enabled providers")
	}
}

func TestRouteByPath(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/primary/chat/completions", nil)
	name := r.resolveProvider(req)
	if name != "primary" {
		t.Errorf("expected primary for /v1/primary path, got %s", name)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/secondary/chat/completions", nil)
	name = r.resolveProvider(req)
	if name != "secondary" {
		t.Errorf("expected secondary for /v1/secondary path, got %s", name)
	}
}

func TestRouteByHeader(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Veil-Provider", "secondary")
	name := r.resolveProvider(req)
	if name != "secondary" {
		t.Errorf("expected secondary from header, got %s", name)
	}
}

func TestRouteByHeader_Unknown(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Veil-Provider", "nonexistent")
	name := r.resolveProvider(req)
	// Should fallback to load balance / default
	if name == "nonexistent" {
		t.Error("should not use unknown provider")
	}
}

func TestPriorityStrategy(t *testing.T) {
	cfg := newTestConfig()
	cfg.LoadBalance = StrategyPriority
	r, _ := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	name := r.resolveProvider(req)
	if name != "primary" {
		t.Errorf("expected primary (priority 1), got %s", name)
	}

	// Mark primary unhealthy
	r.SetHealthy("primary", false)
	name = r.resolveProvider(req)
	if name != "secondary" {
		t.Errorf("expected secondary after primary unhealthy, got %s", name)
	}
}

func TestRoundRobinStrategy(t *testing.T) {
	cfg := newTestConfig()
	cfg.LoadBalance = StrategyRoundRobin
	r, _ := New(cfg)

	// Should alternate between providers
	seen := make(map[string]int)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		name := r.resolveProvider(req)
		seen[name]++
	}

	if len(seen) < 2 {
		t.Error("round-robin should use multiple providers")
	}
}

func TestWeightedStrategy(t *testing.T) {
	cfg := newTestConfig()
	cfg.LoadBalance = StrategyWeighted
	// primary weight=2, secondary weight=1
	r, _ := New(cfg)

	counts := make(map[string]int)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		name := r.resolveProvider(req)
		counts[name]++
	}

	// Primary should get roughly 2x traffic
	if counts["primary"] <= counts["secondary"] {
		t.Errorf("primary (weight=2) should get more traffic: primary=%d, secondary=%d",
			counts["primary"], counts["secondary"])
	}
}

func TestHealthManagement(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	if !r.IsHealthy("primary") {
		t.Error("should be healthy initially")
	}

	r.SetHealthy("primary", false)
	if r.IsHealthy("primary") {
		t.Error("should be unhealthy after SetHealthy(false)")
	}

	r.SetHealthy("primary", true)
	if !r.IsHealthy("primary") {
		t.Error("should be healthy after SetHealthy(true)")
	}
}

func TestIsHealthy_Unknown(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	if r.IsHealthy("nonexistent") {
		t.Error("unknown provider should not be healthy")
	}
}

func TestStripRoutePrefix(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)

	tests := []struct {
		input    string
		expected string
	}{
		{"/v1/primary/chat/completions", "/chat/completions"},
		{"/v1/secondary/models", "/models"},
		{"/v1/primary", "/"},
		{"/v1/other/path", "/v1/other/path"}, // no matching route
	}

	for _, tt := range tests {
		got := r.stripRoutePrefix(tt.input)
		if got != tt.expected {
			t.Errorf("stripRoutePrefix(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}

// === Router HTTP Tests ===

func TestServeHTTP_RouteToProvider(t *testing.T) {
	// Create test upstream servers
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"provider": "primary", "path": r.URL.Path})
	}))
	defer primary.Close()

	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"provider": "secondary", "path": r.URL.Path})
	}))
	defer secondary.Close()

	cfg := &RouterConfig{
		Providers: []ProviderConfig{
			{Name: "primary", BaseURL: primary.URL, Priority: 1, Enabled: true, TimeoutSec: 5},
			{Name: "secondary", BaseURL: secondary.URL, Priority: 2, Enabled: true, TimeoutSec: 5},
		},
		Routes: []RouteConfig{
			{PathPrefix: "/v1/primary", Provider: "primary"},
			{PathPrefix: "/v1/secondary", Provider: "secondary"},
		},
		LoadBalance:  StrategyPriority,
		DefaultRoute: "primary",
	}

	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Route to primary
	req := httptest.NewRequest(http.MethodGet, "/v1/primary/chat/completions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["provider"] != "primary" {
		t.Errorf("expected primary provider, got %s", resp["provider"])
	}
	if resp["path"] != "/chat/completions" {
		t.Errorf("expected /chat/completions, got %s", resp["path"])
	}
}

func TestServeHTTP_HeaderRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfg := &RouterConfig{
		Providers: []ProviderConfig{
			{Name: "target", BaseURL: server.URL, Priority: 1, Enabled: true, TimeoutSec: 5},
		},
		LoadBalance:  StrategyPriority,
		DefaultRoute: "target",
	}

	r, _ := New(cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Veil-Provider", "target")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_UnhealthyProvider(t *testing.T) {
	cfg := newTestConfig()
	r, _ := New(cfg)
	r.SetHealthy("primary", false)
	r.SetHealthy("secondary", false)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// === Adapter Tests ===

func TestAdaptToOpenAI(t *testing.T) {
	req := UnifiedRequest{
		Model: "gpt-4",
		Messages: []UnifiedMessage{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens:   100,
		Temperature: 0.7,
	}

	data, err := AdaptToProvider("openai", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	if result["model"] != "gpt-4" {
		t.Error("expected model gpt-4")
	}
	if result["max_tokens"] != float64(100) {
		t.Error("expected max_tokens 100")
	}
}

func TestAdaptToAnthropic(t *testing.T) {
	req := UnifiedRequest{
		Model: "claude-sonnet-4-20250514",
		Messages: []UnifiedMessage{
			{Role: "system", Content: "You are helpful"},
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 200,
	}

	data, err := AdaptToProvider("anthropic", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	if result["system"] != "You are helpful" {
		t.Error("expected system prompt extracted")
	}
	// Messages should not contain system role
	msgs := result["messages"].([]any)
	for _, m := range msgs {
		msg := m.(map[string]any)
		if msg["role"] == "system" {
			t.Error("system message should be extracted, not in messages")
		}
	}
}

func TestAdaptToAnthropic_DefaultMaxTokens(t *testing.T) {
	req := UnifiedRequest{
		Model: "claude-sonnet-4-20250514",
		Messages: []UnifiedMessage{
			{Role: "user", Content: "Hello"},
		},
	}

	data, err := AdaptToProvider("anthropic", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	if result["max_tokens"] != float64(4096) {
		t.Errorf("expected default max_tokens 4096, got %v", result["max_tokens"])
	}
}

func TestAdaptToGemini(t *testing.T) {
	req := UnifiedRequest{
		Model: "gemini-pro",
		Messages: []UnifiedMessage{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens: 150,
	}

	data, err := AdaptToProvider("gemini", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	if result["contents"] == nil {
		t.Error("expected contents field")
	}
	if result["generationConfig"] == nil {
		t.Error("expected generationConfig")
	}
}

func TestAdaptToOllama(t *testing.T) {
	req := UnifiedRequest{
		Model: "llama3",
		Messages: []UnifiedMessage{
			{Role: "user", Content: "Hello"},
		},
		MaxTokens:   100,
		Temperature: 0.8,
	}

	data, err := AdaptToProvider("ollama", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}

	var result map[string]any
	json.Unmarshal(data, &result)
	if result["model"] != "llama3" {
		t.Error("expected model llama3")
	}
	opts := result["options"].(map[string]any)
	if opts["num_predict"] != float64(100) {
		t.Error("expected num_predict 100")
	}
	if opts["temperature"] != 0.8 {
		t.Error("expected temperature 0.8")
	}
}

func TestAdaptToUnknown(t *testing.T) {
	req := UnifiedRequest{
		Model:    "custom-model",
		Messages: []UnifiedMessage{{Role: "user", Content: "Hi"}},
	}
	// Unknown provider should default to OpenAI format
	data, err := AdaptToProvider("custom", req)
	if err != nil {
		t.Fatalf("AdaptToProvider: %v", err)
	}
	if !strings.Contains(string(data), "messages") {
		t.Error("unknown should use OpenAI format")
	}
}

func TestAdaptFromOpenAI(t *testing.T) {
	resp := `{"id":"chatcmpl-123","model":"gpt-4","choices":[{"message":{"content":"Hello!"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`
	result, err := AdaptFromProvider("openai", []byte(resp))
	if err != nil {
		t.Fatalf("AdaptFromProvider: %v", err)
	}
	if result.Content != "Hello!" {
		t.Errorf("expected 'Hello!', got '%s'", result.Content)
	}
	if result.Usage.InputTokens != 10 {
		t.Error("expected 10 input tokens")
	}
}

func TestAdaptFromAnthropic(t *testing.T) {
	resp := `{"id":"msg_123","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Bonjour!"}],"usage":{"input_tokens":8,"output_tokens":3}}`
	result, err := AdaptFromProvider("anthropic", []byte(resp))
	if err != nil {
		t.Fatalf("AdaptFromProvider: %v", err)
	}
	if result.Content != "Bonjour!" {
		t.Errorf("expected 'Bonjour!', got '%s'", result.Content)
	}
}

func TestAdaptFromGemini(t *testing.T) {
	resp := `{"candidates":[{"content":{"parts":[{"text":"Hola!"}]}}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2}}`
	result, err := AdaptFromProvider("gemini", []byte(resp))
	if err != nil {
		t.Fatalf("AdaptFromProvider: %v", err)
	}
	if result.Content != "Hola!" {
		t.Errorf("expected 'Hola!', got '%s'", result.Content)
	}
}

func TestAdaptFromOllama(t *testing.T) {
	resp := `{"model":"llama3","message":{"role":"assistant","content":"Xin chào!"},"prompt_eval_count":12,"eval_count":6}`
	result, err := AdaptFromProvider("ollama", []byte(resp))
	if err != nil {
		t.Fatalf("AdaptFromProvider: %v", err)
	}
	if result.Content != "Xin chào!" {
		t.Errorf("expected 'Xin chào!', got '%s'", result.Content)
	}
	if result.Usage.InputTokens != 12 {
		t.Error("expected 12 input tokens")
	}
}

func TestAdaptFrom_InvalidJSON(t *testing.T) {
	providers := []string{"openai", "anthropic", "gemini", "ollama"}
	for _, p := range providers {
		_, err := AdaptFromProvider(p, []byte("not json"))
		if err == nil {
			t.Errorf("%s: expected error for invalid JSON", p)
		}
	}
}

func TestAdaptFromOpenAI_EmptyChoices(t *testing.T) {
	resp := `{"id":"123","model":"gpt-4","choices":[],"usage":{}}`
	result, err := AdaptFromProvider("openai", []byte(resp))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Content != "" {
		t.Errorf("expected empty content, got '%s'", result.Content)
	}
}
