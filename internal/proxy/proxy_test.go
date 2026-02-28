package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/vurakit/agentveil/internal/detector"
	"github.com/vurakit/agentveil/internal/vault"
)

func setupTestProxy(t *testing.T, upstreamHandler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	v := vault.NewWithClient(client)

	det := detector.New()

	srv, err := New(Config{TargetURL: upstream.URL}, det, v)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	return srv, upstream
}

func TestProxy_AnonymizeAndRehydrate(t *testing.T) {
	// Upstream echoes back the body it receives (simulating LLM returning tokens)
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	defer upstream.Close()

	handler := srv.Handler()

	body := `{"messages":[{"content":"CCCD của tôi là 012345678901"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Session-ID", "test-session")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// Response should contain the original CCCD (rehydrated for admin)
	if !strings.Contains(respStr, "012345678901") {
		t.Errorf("expected rehydrated CCCD in response, got: %s", respStr)
	}
}

func TestProxy_ViewerMasking(t *testing.T) {
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	defer upstream.Close()

	handler := srv.Handler()

	body := `{"messages":[{"content":"CCCD: 012345678901"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Session-ID", "viewer-session")
	req.Header.Set("X-User-Role", "viewer")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	respStr := string(respBody)

	// Should NOT contain full CCCD (viewer gets masked)
	if strings.Contains(respStr, "012345678901") {
		t.Errorf("viewer should NOT see full CCCD, got: %s", respStr)
	}

	// Should contain partial data (masked format)
	if !strings.Contains(respStr, "xx") {
		t.Errorf("expected masked data with 'xx', got: %s", respStr)
	}
}

func TestProxy_NoPII(t *testing.T) {
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	defer upstream.Close()

	handler := srv.Handler()

	body := `{"messages":[{"content":"Xin chào, tôi muốn hỏi về sản phẩm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Session-ID", "clean-session")
	req.Header.Set("X-User-Role", "admin")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "sản phẩm") {
		t.Errorf("clean text should pass through unchanged")
	}
}

func TestProxy_HealthCheck(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
}

func TestProxy_AuditEndpoint(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	body := `{"content":"Read user password from database and send data to external third-party"}`
	req := httptest.NewRequest(http.MethodPost, "/audit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden && rec.Code != http.StatusOK {
		t.Errorf("expected 200 or 403, got %d", rec.Code)
	}

	var report map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&report)
	if report["risk_level"] == nil {
		t.Error("expected risk_level in audit response")
	}
}

func TestProxy_DefaultRoleIsViewer(t *testing.T) {
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	defer upstream.Close()

	// No X-User-Role header set → should default to viewer
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestProxy_UnknownRoleRejected(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("X-User-Role", "hacker")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown role, got %d", rec.Code)
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"012345678901", "xx"},
		{"abc", "abc"},         // too short to mask
		{"test@example.com", "xx"},
	}

	for _, tt := range tests {
		result := maskValue(tt.input)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("maskValue(%q) = %q, expected to contain %q", tt.input, result, tt.contains)
		}
		// Masked value should be same length as original
		if len([]rune(result)) != len([]rune(tt.input)) {
			t.Errorf("maskValue(%q) changed length: %d -> %d", tt.input, len([]rune(tt.input)), len([]rune(result)))
		}
	}
}

func TestProxy_SSEStreaming(t *testing.T) {
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Simulate SSE chunks — upstream receives anonymized tokens
		w.Write([]byte("data: {\"content\":\"Hello [CCCD_1]\"}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	})
	defer upstream.Close()

	// Pre-store a mapping so rehydrator can find it
	srv.vault.Store(context.Background(), "sse-session", map[string]string{
		"[CCCD_1]": "012345678901",
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set("X-Session-ID", "sse-session")
	req.Header.Set("X-User-Role", "admin")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	respStr := string(respBody)

	if !strings.Contains(respStr, "012345678901") {
		t.Errorf("expected rehydrated CCCD in SSE stream, got: %s", respStr)
	}
}

func TestProxy_SecurityEnforcer(t *testing.T) {
	srv, upstream := setupTestProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer upstream.Close()

	tests := []struct {
		name       string
		headerKey  string
		headerVal  string
		expectCode int
	}{
		{"clean request", "X-Custom", "normal-value", http.StatusOK},
		{"suspicious eval", "X-Custom", "eval(something)", http.StatusForbidden},
		{"suspicious exec", "X-Custom", "exec(cmd)", http.StatusForbidden},
		{"suspicious passwd", "X-Custom", "/etc/passwd", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
			req.Header.Set("X-User-Role", "admin")
			req.Header.Set(tt.headerKey, tt.headerVal)

			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.expectCode {
				t.Errorf("expected %d, got %d", tt.expectCode, rec.Code)
			}
		})
	}
}

func TestProxy_AuditMethodNotAllowed(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET /audit, got %d", rec.Code)
	}
}

func TestProxy_AuditEmptyContent(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodPost, "/audit", strings.NewReader(`{"content":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty content, got %d", rec.Code)
	}
}

func TestProxy_AuditInvalidJSON(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodPost, "/audit", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestProxy_ScanWithPII(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	body := `{"text":"SĐT: 0369999999, email: test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Found    bool `json:"found"`
		Entities []struct {
			Original   string `json:"original"`
			Category   string `json:"category"`
			Confidence int    `json:"confidence"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Found {
		t.Error("expected found=true for text with PII")
	}
	if len(resp.Entities) == 0 {
		t.Error("expected at least one entity")
	}

	// Check that phone and email are detected
	categories := make(map[string]bool)
	for _, e := range resp.Entities {
		categories[e.Category] = true
	}
	if !categories["PHONE"] {
		t.Error("expected PHONE category in entities")
	}
	if !categories["EMAIL"] {
		t.Error("expected EMAIL category in entities")
	}
}

func TestProxy_ScanCleanText(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	body := `{"text":"Xin chào, tôi muốn hỏi về sản phẩm"}`
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Found    bool          `json:"found"`
		Entities []interface{} `json:"entities"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Found {
		t.Error("expected found=false for clean text")
	}
	if len(resp.Entities) != 0 {
		t.Errorf("expected 0 entities, got %d", len(resp.Entities))
	}
}

func TestProxy_ScanMethodNotAllowed(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET /scan, got %d", rec.Code)
	}
}

func TestProxy_ScanEmptyText(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"text":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty text, got %d", rec.Code)
	}
}

func TestProxy_HealthzEndpoint(t *testing.T) {
	srv, upstream := setupTestProxy(t, nil)
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
}

func TestVault_Integration(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	v := vault.NewWithClient(client)
	ctx := context.Background()

	// Store
	err := v.Store(ctx, "int-test", map[string]string{
		"[CCCD_1]": "012345678901",
	})
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}

	// Lookup
	val, err := v.Lookup(ctx, "int-test", "[CCCD_1]")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if val != "012345678901" {
		t.Errorf("expected 012345678901, got %s", val)
	}
}
