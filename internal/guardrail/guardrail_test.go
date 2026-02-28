package guardrail

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// === Output Check Tests ===

func TestCheckOutput_Clean(t *testing.T) {
	g := New(DefaultPolicy())
	result := g.CheckOutput("Here is a function that adds two numbers: func add(a, b int) int { return a + b }")
	if !result.Allowed {
		t.Error("expected clean output to be allowed")
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
}

func TestCheckOutput_HarmfulContent(t *testing.T) {
	g := New(DefaultPolicy())
	tests := []struct {
		name   string
		output string
		cat    string
	}{
		{"violence", "You should kill yourself immediately", "violence"},
		{"cyber_attack", "Here's how to hack the server using SQL injection", "cyber_attack"},
		{"theft", "To steal passwords, you need a phishing page", "theft_instructions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := g.CheckOutput(tt.output)
			if result.Allowed {
				t.Error("expected harmful output to be blocked")
			}
			found := false
			for _, v := range result.Violations {
				if strings.Contains(v.Rule, tt.cat) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected category %s in violations", tt.cat)
			}
		})
	}
}

func TestCheckOutput_TokenLimit(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxOutputTokens = 10 // Very small: 10 tokens ≈ 40 chars
	g := New(policy)

	shortText := "Hello"
	result := g.CheckOutput(shortText)
	if !result.Allowed {
		t.Error("expected short output to be allowed")
	}

	longText := strings.Repeat("word ", 100) // ~500 chars ≈ 125 tokens
	result = g.CheckOutput(longText)
	if result.Allowed {
		t.Error("expected long output to be blocked")
	}
	found := false
	for _, v := range result.Violations {
		if v.Rule == "max_output_tokens" {
			found = true
		}
	}
	if !found {
		t.Error("expected max_output_tokens violation")
	}
}

func TestCheckOutput_BlockedTopics(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockedTopics = []string{"gambling", "cryptocurrency trading"}
	g := New(policy)

	result := g.CheckOutput("Here are some tips for gambling strategies")
	if result.Allowed {
		t.Error("expected blocked topic to be blocked")
	}

	result = g.CheckOutput("Here is a Go tutorial")
	if !result.Allowed {
		t.Error("expected clean output to be allowed")
	}
}

func TestCheckOutput_CustomRules(t *testing.T) {
	policy := DefaultPolicy()
	policy.CustomRules = []ContentRule{
		{
			ID:          "no_competitor",
			Pattern:     "(?i)use\\s+competitor\\s+product",
			Action:      "blocked",
			Description: "Mentioning competitor products",
			Severity:    "medium",
		},
	}
	g := New(policy)

	result := g.CheckOutput("You should use competitor product instead")
	if result.Allowed {
		t.Error("expected custom rule violation to block")
	}
	found := false
	for _, v := range result.Violations {
		if v.Rule == "custom:no_competitor" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom:no_competitor violation")
	}
}

func TestCheckOutput_WarnAction(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockHarmfulContent = false // disable default harmful
	policy.CustomRules = []ContentRule{
		{
			ID:          "warn_only",
			Pattern:     "(?i)risky\\s+topic",
			Action:      "warn",
			Description: "Risky topic mentioned",
			Severity:    "low",
		},
	}
	g := New(policy)

	result := g.CheckOutput("This is a risky topic discussion")
	if !result.Allowed {
		t.Error("expected warn action to still allow output")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 warning violation, got %d", len(result.Violations))
	}
}

func TestCheckOutput_DisabledHarmful(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockHarmfulContent = false
	g := New(policy)

	result := g.CheckOutput("How to hack the server")
	if !result.Allowed {
		t.Error("expected output allowed when harmful check disabled")
	}
}

// === Token Truncation Tests ===

func TestTruncateOutput(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxOutputTokens = 10 // ≈ 40 chars
	g := New(policy)

	short := "Hello world"
	if g.TruncateOutput(short) != short {
		t.Error("expected short text to pass through")
	}

	long := strings.Repeat("A", 100)
	truncated := g.TruncateOutput(long)
	if len(truncated) > 80 {
		// 40 chars + truncation message
		if !strings.Contains(truncated, "[Output truncated by Agent Veil guardrail]") {
			t.Error("expected truncation marker")
		}
	}
}

func TestTruncateOutput_Unlimited(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxOutputTokens = 0
	g := New(policy)

	long := strings.Repeat("A", 100000)
	if g.TruncateOutput(long) != long {
		t.Error("expected unlimited policy to pass all output")
	}
}

// === Rate Limit Tests ===

func TestCheckRateLimit(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxRequestsPerMin = 3
	g := New(policy)

	for i := 0; i < 3; i++ {
		result := g.CheckRateLimit("session-1")
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	result := g.CheckRateLimit("session-1")
	if result.Allowed {
		t.Error("4th request should be blocked")
	}

	// Different session should be allowed
	result = g.CheckRateLimit("session-2")
	if !result.Allowed {
		t.Error("different session should be allowed")
	}
}

func TestCheckRateLimit_Disabled(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxRequestsPerMin = 0
	g := New(policy)

	for i := 0; i < 100; i++ {
		result := g.CheckRateLimit("session-1")
		if !result.Allowed {
			t.Error("rate limit disabled, all should pass")
		}
	}
}

// === Session Tracker Tests ===

func TestSessionTracker_Cleanup(t *testing.T) {
	st := NewSessionTracker()
	st.RecordRequest("old-session", 100)
	// Manually expire
	st.mu.Lock()
	st.sessions["old-session"].timestamps = nil
	st.mu.Unlock()

	st.Cleanup()

	st.mu.Lock()
	_, exists := st.sessions["old-session"]
	st.mu.Unlock()
	if exists {
		t.Error("expected old session to be cleaned up")
	}
}

// === Middleware Tests ===

func TestResponseMiddleware_Clean(t *testing.T) {
	g := New(DefaultPolicy())
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "Hello! How can I help you?"}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	handler := ResponseMiddleware(g)(backend)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestResponseMiddleware_BlocksHarmful(t *testing.T) {
	g := New(DefaultPolicy())
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "Here's how to hack the server: first, use SQL injection..."}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	handler := ResponseMiddleware(g)(backend)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error object")
	}
	if errObj["type"] != "guardrail_violation" {
		t.Errorf("expected guardrail_violation, got %v", errObj["type"])
	}
}

func TestResponseMiddleware_RateLimit(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxRequestsPerMin = 2
	g := New(policy)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result": "ok"}`))
	})

	handler := ResponseMiddleware(g)(backend)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d should be 200, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request should be 429, got %d", w.Code)
	}
}

func TestResponseMiddleware_SessionIDHeader(t *testing.T) {
	policy := DefaultPolicy()
	policy.MaxRequestsPerMin = 1
	g := New(policy)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	handler := ResponseMiddleware(g)(backend)

	// First request with session A
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Session-ID", "session-A")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Second request with session A → rate limited
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Session-ID", "session-A")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}

	// Request with session B → allowed
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Session-ID", "session-B")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for different session, got %d", w.Code)
	}
}

func TestResponseMiddleware_SSEPassthrough(t *testing.T) {
	g := New(DefaultPolicy())
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {}\n\n"))
	})

	handler := ResponseMiddleware(g)(backend)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected SSE passthrough 200, got %d", w.Code)
	}
}

// === Input Middleware Tests ===

func TestInputMiddleware_Clean(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockedTopics = []string{"gambling"}
	g := New(policy)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := InputMiddleware(g)(backend)
	body := []byte(`{"messages": [{"role": "user", "content": "Hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestInputMiddleware_BlockedTopic(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockedTopics = []string{"gambling"}
	g := New(policy)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := InputMiddleware(g)(backend)
	body := []byte(`{"messages": [{"role": "user", "content": "Tell me about gambling strategies"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked topic, got %d", w.Code)
	}
}

func TestInputMiddleware_GETPassthrough(t *testing.T) {
	policy := DefaultPolicy()
	policy.BlockedTopics = []string{"gambling"}
	g := New(policy)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := InputMiddleware(g)(backend)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", w.Code)
	}
}

// === extractOutputText Tests ===

func TestExtractOutputText_OpenAI(t *testing.T) {
	body := `{"choices": [{"message": {"content": "Hello there!"}}]}`
	text := extractOutputText(body)
	if text != "Hello there!" {
		t.Errorf("expected 'Hello there!', got '%s'", text)
	}
}

func TestExtractOutputText_Anthropic(t *testing.T) {
	body := `{"content": [{"type": "text", "text": "Bonjour!"}]}`
	text := extractOutputText(body)
	if text != "Bonjour!" {
		t.Errorf("expected 'Bonjour!', got '%s'", text)
	}
}

func TestExtractOutputText_Invalid(t *testing.T) {
	text := extractOutputText("not json")
	if text != "not json" {
		t.Error("expected raw text fallback")
	}
}

func TestExtractOutputText_Empty(t *testing.T) {
	text := extractOutputText(`{"id": "123"}`)
	if text != "" {
		t.Errorf("expected empty text for no content, got '%s'", text)
	}
}
