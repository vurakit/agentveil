package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcher_EmitAndDeliver(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)

		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected application/json content type")
		}
		if r.Header.Get("X-Veil-Event") == "" {
			t.Error("expected X-Veil-Event header")
		}
		if r.Header.Get("X-Veil-Delivery") == "" {
			t.Error("expected X-Veil-Delivery header")
		}

		var event Event
		json.NewDecoder(r.Body).Decode(&event)
		if event.Type != EventPIIDetected {
			t.Errorf("expected pii.detected, got %s", event.Type)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{Name: "test", URL: server.URL, Enabled: true},
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{
		Type:      EventPIIDetected,
		SessionID: "session-1",
		Data:      map[string]int{"count": 3},
	})

	// Wait for delivery
	time.Sleep(200 * time.Millisecond)
	d.Close()

	if received.Load() != 1 {
		t.Errorf("expected 1 delivery, got %d", received.Load())
	}
}

func TestDispatcher_EventFilter(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{
			Name:    "filtered",
			URL:     server.URL,
			Events:  []EventType{EventAuditHighRisk},
			Enabled: true,
		},
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)

	// This event should NOT be delivered
	d.Emit(Event{Type: EventPIIDetected, Data: "ignored"})
	// This event SHOULD be delivered
	d.Emit(Event{Type: EventAuditHighRisk, Data: "important"})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if received.Load() != 1 {
		t.Errorf("expected 1 delivery (filtered), got %d", received.Load())
	}
}

func TestDispatcher_DisabledDestination(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{Name: "disabled", URL: server.URL, Enabled: false},
	}

	d := NewDispatcher(cfg)
	d.Emit(Event{Type: EventPIIDetected, Data: "test"})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if received.Load() != 0 {
		t.Error("disabled destination should not receive events")
	}
}

func TestDispatcher_HMACSignature(t *testing.T) {
	var receivedSig string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Veil-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{Name: "signed", URL: server.URL, Secret: "my-secret", Enabled: true},
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{Type: EventPIIDetected, Data: "test"})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if receivedSig == "" {
		t.Error("expected HMAC signature header")
	}
	if receivedSig[:7] != "sha256=" {
		t.Errorf("expected sha256= prefix, got %s", receivedSig[:7])
	}
}

func TestDispatcher_CustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{
			Name:    "custom",
			URL:     server.URL,
			Enabled: true,
			Headers: map[string]string{
				"Authorization": "Bearer custom-token",
			},
		},
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{Type: EventPIIDetected, Data: "test"})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if receivedAuth != "Bearer custom-token" {
		t.Errorf("expected custom auth header, got: %s", receivedAuth)
	}
}

func TestDispatcher_SlackWebhook(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Slack = &SlackConfig{
		WebhookURL: server.URL,
		Channel:    "#alerts",
		Username:   "Agent Veil Bot",
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{
		Type:      EventPIIHighRisk,
		SessionID: "session-1",
		Data:      map[string]string{"risk": "high"},
	})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if receivedBody["text"] == "" {
		t.Error("expected Slack message text")
	}
	if receivedBody["channel"] != "#alerts" {
		t.Errorf("expected channel #alerts, got %s", receivedBody["channel"])
	}
}

func TestDispatcher_DiscordWebhook(t *testing.T) {
	var receivedPayload discordPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Discord = &DiscordConfig{
		WebhookURL: server.URL,
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{
		Type:      EventPIIDetected,
		SessionID: "session-discord",
		Data:      map[string]int{"count": 5},
	})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if len(receivedPayload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(receivedPayload.Embeds))
	}
	embed := receivedPayload.Embeds[0]
	if embed.Title == "" {
		t.Error("expected non-empty embed title")
	}
	if embed.Color != 15844367 { // yellow for PII detected
		t.Errorf("expected yellow color 15844367, got %d", embed.Color)
	}
	if len(embed.Fields) < 3 {
		t.Errorf("expected at least 3 fields, got %d", len(embed.Fields))
	}
}

func TestFormatDiscordMessage(t *testing.T) {
	event := Event{
		Type:      EventPIIHighRisk,
		SessionID: "session-456",
		Timestamp: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Data:      map[string]int{"count": 3},
	}

	payload := formatDiscordMessage(event)
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
	}

	embed := payload.Embeds[0]
	if embed.Color != 15158332 { // red for high risk
		t.Errorf("expected red color 15158332, got %d", embed.Color)
	}
	if !containsAll(embed.Title, "Agent Veil", "pii.high_risk") {
		t.Error("title should contain event type")
	}
	if embed.Footer == nil || embed.Footer.Text == "" {
		t.Error("expected non-empty footer")
	}
}

func TestDispatcher_EventAutoID(t *testing.T) {
	var receivedEvent Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedEvent)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Destinations = []Destination{
		{Name: "test", URL: server.URL, Enabled: true},
	}
	cfg.RetryCount = 0

	d := NewDispatcher(cfg)
	d.Emit(Event{Type: EventPIIDetected, Data: "auto-id"})

	time.Sleep(200 * time.Millisecond)
	d.Close()

	if receivedEvent.ID == "" {
		t.Error("expected auto-generated event ID")
	}
	if receivedEvent.Timestamp.IsZero() {
		t.Error("expected auto-set timestamp")
	}
}

func TestMatchesEvent(t *testing.T) {
	tests := []struct {
		filter   []EventType
		event    EventType
		expected bool
	}{
		{nil, EventPIIDetected, true},                       // no filter = all
		{[]EventType{}, EventPIIDetected, true},             // empty filter = all
		{[]EventType{EventPIIDetected}, EventPIIDetected, true},
		{[]EventType{EventAuditHighRisk}, EventPIIDetected, false},
		{[]EventType{EventPIIDetected, EventAuditHighRisk}, EventAuditHighRisk, true},
	}

	for _, tt := range tests {
		got := matchesEvent(tt.filter, tt.event)
		if got != tt.expected {
			t.Errorf("matchesEvent(%v, %s) = %v, want %v", tt.filter, tt.event, got, tt.expected)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"type":"pii.detected"}`)
	secret := "test-secret"

	sig := "sha256=" + signPayload(payload, secret)

	if !VerifySignature(payload, sig, secret) {
		t.Error("valid signature should verify")
	}

	if VerifySignature(payload, "sha256=invalid", secret) {
		t.Error("invalid signature should not verify")
	}

	if VerifySignature(payload, sig, "wrong-secret") {
		t.Error("wrong secret should not verify")
	}
}

func TestFormatSlackMessage(t *testing.T) {
	event := Event{
		Type:      EventPIIHighRisk,
		SessionID: "session-123",
		Timestamp: time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Data:      map[string]int{"count": 5},
	}

	msg := formatSlackMessage(event)
	if msg == "" {
		t.Error("expected non-empty message")
	}
	if !containsAll(msg, "Agent Veil", "pii.high_risk", "session-123") {
		t.Error("message should contain event details")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RetryCount != 3 {
		t.Errorf("expected 3 retries, got %d", cfg.RetryCount)
	}
	if cfg.TimeoutSec != 10 {
		t.Errorf("expected 10s timeout, got %d", cfg.TimeoutSec)
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
