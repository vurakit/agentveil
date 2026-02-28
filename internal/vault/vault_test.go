package vault

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestVault(t *testing.T) (*Vault, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	v := NewWithClient(client)
	return v, mr
}

func TestPing(t *testing.T) {
	v, _ := setupTestVault(t)
	if err := v.Ping(context.Background()); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestStoreAndLookup(t *testing.T) {
	v, _ := setupTestVault(t)
	ctx := context.Background()

	mapping := map[string]string{
		"[CCCD_1]":  "012345678901",
		"[PHONE_1]": "0901234567",
		"[EMAIL_1]": "test@example.com",
	}

	if err := v.Store(ctx, "session-1", mapping); err != nil {
		t.Fatalf("store failed: %v", err)
	}

	// LookupAll
	got, err := v.LookupAll(ctx, "session-1")
	if err != nil {
		t.Fatalf("lookupAll failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(got))
	}
	for token, expected := range mapping {
		if got[token] != expected {
			t.Errorf("token %s: expected %s, got %s", token, expected, got[token])
		}
	}

	// Single Lookup
	val, err := v.Lookup(ctx, "session-1", "[CCCD_1]")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if val != "012345678901" {
		t.Errorf("expected 012345678901, got %s", val)
	}
}

func TestStoreEmpty(t *testing.T) {
	v, _ := setupTestVault(t)
	// Should not error on empty mapping
	if err := v.Store(context.Background(), "session-x", nil); err != nil {
		t.Fatalf("store empty failed: %v", err)
	}
}

func TestLookupNonexistent(t *testing.T) {
	v, _ := setupTestVault(t)
	got, err := v.LookupAll(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestDelete(t *testing.T) {
	v, _ := setupTestVault(t)
	ctx := context.Background()

	v.Store(ctx, "session-del", map[string]string{"[X]": "data"})

	if err := v.Delete(ctx, "session-del"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	got, _ := v.LookupAll(ctx, "session-del")
	if len(got) != 0 {
		t.Errorf("expected empty after delete, got %v", got)
	}
}

func TestTTLExpiry(t *testing.T) {
	v, mr := setupTestVault(t)
	ctx := context.Background()

	v.SetTTL(1 * time.Second)
	v.Store(ctx, "session-ttl", map[string]string{"[A]": "value"})

	// Fast-forward time in miniredis
	mr.FastForward(2 * time.Second)

	got, _ := v.LookupAll(ctx, "session-ttl")
	if len(got) != 0 {
		t.Errorf("expected expired data, got %v", got)
	}
}

func TestSessionIsolation(t *testing.T) {
	v, _ := setupTestVault(t)
	ctx := context.Background()

	v.Store(ctx, "session-A", map[string]string{"[TOKEN]": "secret-A"})
	v.Store(ctx, "session-B", map[string]string{"[TOKEN]": "secret-B"})

	gotA, _ := v.LookupAll(ctx, "session-A")
	gotB, _ := v.LookupAll(ctx, "session-B")

	if gotA["[TOKEN]"] != "secret-A" {
		t.Errorf("session A leaked: got %s", gotA["[TOKEN]"])
	}
	if gotB["[TOKEN]"] != "secret-B" {
		t.Errorf("session B leaked: got %s", gotB["[TOKEN]"])
	}
}
