package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListTools(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mcp/tools/list", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp ListToolsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if len(resp.Tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(resp.Tools))
	}

	expectedTools := map[string]bool{
		ToolScanPII:         false,
		ToolAuditSkill:      false,
		ToolCheckCompliance: false,
		ToolHealthCheck:     false,
	}
	for _, tool := range resp.Tools {
		expectedTools[tool.Name] = true
	}
	for name, found := range expectedTools {
		if !found {
			t.Errorf("missing tool: %s", name)
		}
	}
}

func TestToolsHaveSchema(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mcp/tools/list", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp ListToolsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	for _, tool := range resp.Tools {
		if tool.Description == "" {
			t.Errorf("tool %s missing description", tool.Name)
		}
		if len(tool.InputSchema) == 0 {
			t.Errorf("tool %s missing inputSchema", tool.Name)
		}
		// Validate schema is valid JSON
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %s has invalid schema: %v", tool.Name, err)
		}
	}
}

func TestCallTool_Unknown(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	body, _ := json.Marshal(map[string]any{
		"name":      "unknown_tool",
		"arguments": json.RawMessage(`{}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCallTool_InvalidBody(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCallTool_MethodNotAllowed(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mcp/tools/call", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestCallTool_ScanPII_InvalidParams(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	body, _ := json.Marshal(map[string]any{
		"name":      ToolScanPII,
		"arguments": json.RawMessage(`"invalid"`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var result ToolResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.IsError {
		t.Error("expected error for invalid params")
	}
}

func TestCallTool_ScanPII_WithBackend(t *testing.T) {
	// Mock Agent Veil backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"found":    true,
			"entities": []map[string]any{{"type": "PHONE", "value": "0912345678"}},
		})
	}))
	defer backend.Close()

	s := NewServer(Config{ProxyURL: backend.URL})
	handler := s.Handler()

	body, _ := json.Marshal(map[string]any{
		"name":      ToolScanPII,
		"arguments": json.RawMessage(`{"text":"Call me at 0912345678"}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result ToolResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.IsError {
		t.Error("expected success")
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
	if !strings.Contains(result.Content[0].Text, "PHONE") {
		t.Error("expected PII result to contain PHONE")
	}
}

func TestCallTool_AuditSkill_WithBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"risk_level":       1,
			"compliance_score": 100,
			"findings":         []any{},
		})
	}))
	defer backend.Close()

	s := NewServer(Config{ProxyURL: backend.URL})
	handler := s.Handler()

	body, _ := json.Marshal(map[string]any{
		"name":      ToolAuditSkill,
		"arguments": json.RawMessage(`{"content":"# Safe Agent\n- Greet user"}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var result ToolResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.IsError {
		t.Error("expected success for audit")
	}
	if !strings.Contains(result.Content[0].Text, "compliance_score") {
		t.Error("expected compliance_score in result")
	}
}

func TestCallTool_HealthCheck_WithBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	s := NewServer(Config{ProxyURL: backend.URL})
	handler := s.Handler()

	body, _ := json.Marshal(map[string]any{
		"name":      ToolHealthCheck,
		"arguments": json.RawMessage(`{}`),
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var result ToolResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.IsError {
		t.Error("expected success for health check")
	}
	if !strings.Contains(result.Content[0].Text, "ok") {
		t.Error("expected ok in health result")
	}
}

func TestMCPHealth(t *testing.T) {
	s := NewServer(Config{ProxyURL: "http://localhost:8080"})
	handler := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/mcp/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "mcp") {
		t.Error("expected mcp in health response")
	}
}

func TestErrorResult(t *testing.T) {
	result := errorResult("test error")
	if !result.IsError {
		t.Error("expected IsError true")
	}
	if result.Content[0].Text != "test error" {
		t.Errorf("expected 'test error', got '%s'", result.Content[0].Text)
	}
}
