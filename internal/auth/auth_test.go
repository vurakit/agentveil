package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestAuth(t *testing.T) *Manager {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewManager(client)
}

func TestGenerateAndValidate(t *testing.T) {
	mgr := setupTestAuth(t)
	ctx := context.Background()

	plaintext, key, err := mgr.GenerateKey(ctx, RoleAdmin, "test key")
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if !strings.HasPrefix(plaintext, "veil_sk_") {
		t.Errorf("expected veil_sk_ prefix, got %s", plaintext)
	}
	if key.Role != RoleAdmin {
		t.Errorf("expected admin role, got %s", key.Role)
	}
	if key.ID == "" {
		t.Error("expected non-empty ID")
	}

	// Validate
	validated, err := mgr.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if validated.Role != RoleAdmin {
		t.Errorf("expected admin, got %s", validated.Role)
	}
}

func TestValidate_InvalidKey(t *testing.T) {
	mgr := setupTestAuth(t)
	_, err := mgr.Validate(context.Background(), "veil_sk_invalid")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestRevoke(t *testing.T) {
	mgr := setupTestAuth(t)
	ctx := context.Background()

	plaintext, _, _ := mgr.GenerateKey(ctx, RoleViewer, "to revoke")

	if err := mgr.Revoke(ctx, plaintext); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	_, err := mgr.Validate(ctx, plaintext)
	if err == nil {
		t.Error("expected error after revocation")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected 'revoked' in error, got: %v", err)
	}
}

func TestRevokeByID(t *testing.T) {
	mgr := setupTestAuth(t)
	ctx := context.Background()

	plaintext, key, _ := mgr.GenerateKey(ctx, RoleOperator, "by-id")

	if err := mgr.RevokeByID(ctx, key.ID); err != nil {
		t.Fatalf("revokeByID failed: %v", err)
	}

	_, err := mgr.Validate(ctx, plaintext)
	if err == nil {
		t.Error("expected error after revocation by ID")
	}
}

func TestMiddleware_ValidKey(t *testing.T) {
	mgr := setupTestAuth(t)
	ctx := context.Background()

	plaintext, _, _ := mgr.GenerateKey(ctx, RoleViewer, "mw test")

	var capturedRole string
	handler := mgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = r.Header.Get("X-User-Role")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedRole != "viewer" {
		t.Errorf("expected role viewer from key binding, got %s", capturedRole)
	}
}

func TestMiddleware_NoAuth(t *testing.T) {
	mgr := setupTestAuth(t)

	handler := mgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestMiddleware_NonVeilKeyPassthrough(t *testing.T) {
	mgr := setupTestAuth(t)

	handler := mgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// OpenAI key (sk-xxx) should pass through without Agent Veil validation
	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer sk-proj-abc123")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected passthrough for non-veil key, got %d", rec.Code)
	}
}

func TestMiddleware_RoleOverride(t *testing.T) {
	mgr := setupTestAuth(t)
	ctx := context.Background()

	// Key bound to viewer role
	plaintext, _, _ := mgr.GenerateKey(ctx, RoleViewer, "role override")

	var capturedRole string
	handler := mgr.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = r.Header.Get("X-User-Role")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("X-User-Role", "admin") // client tries to escalate

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should be forced to viewer (key binding), not admin
	if capturedRole != "viewer" {
		t.Errorf("expected forced viewer role, got %s", capturedRole)
	}
}
