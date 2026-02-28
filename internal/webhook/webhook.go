package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// EventType represents the type of webhook event
type EventType string

const (
	EventPIIDetected       EventType = "pii.detected"
	EventPIIHighRisk       EventType = "pii.high_risk"
	EventPromptInjection   EventType = "prompt_injection.detected"
	EventGuardrailViolation EventType = "guardrail.violation"
	EventAuditComplete     EventType = "audit.complete"
	EventAuditHighRisk     EventType = "audit.high_risk"
	EventRateLimitHit      EventType = "rate_limit.hit"
	EventProviderFailover  EventType = "provider.failover"
)

// Event is a webhook event payload
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id,omitempty"`
	Data      any       `json:"data"`
}

// Destination defines where to send webhook events
type Destination struct {
	Name    string      `json:"name"`
	URL     string      `json:"url"`
	Secret  string      `json:"secret,omitempty"` // HMAC signing secret
	Events  []EventType `json:"events"`           // empty = all events
	Enabled bool        `json:"enabled"`
	Headers map[string]string `json:"headers,omitempty"`
}

// SlackConfig configures Slack webhook integration
type SlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel,omitempty"`
	Username   string `json:"username,omitempty"`
}

// Config holds webhook dispatcher configuration
type Config struct {
	Destinations []Destination `json:"destinations"`
	Slack        *SlackConfig  `json:"slack,omitempty"`
	RetryCount   int           `json:"retry_count"`
	TimeoutSec   int           `json:"timeout_sec"`
	BufferSize   int           `json:"buffer_size"`
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		RetryCount: 3,
		TimeoutSec: 10,
		BufferSize: 1000,
	}
}

// Dispatcher sends webhook events to configured destinations
type Dispatcher struct {
	config       Config
	destinations []Destination
	client       *http.Client
	eventChan    chan Event
	wg           sync.WaitGroup
	closed       chan struct{}
}

// NewDispatcher creates a webhook dispatcher
func NewDispatcher(cfg Config) *Dispatcher {
	d := &Dispatcher{
		config:       cfg,
		destinations: cfg.Destinations,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		},
		eventChan: make(chan Event, cfg.BufferSize),
		closed:    make(chan struct{}),
	}

	// Add Slack as a destination if configured
	if cfg.Slack != nil && cfg.Slack.WebhookURL != "" {
		d.destinations = append(d.destinations, Destination{
			Name:    "slack",
			URL:     cfg.Slack.WebhookURL,
			Events:  nil, // all events
			Enabled: true,
		})
	}

	// Start worker
	d.wg.Add(1)
	go d.worker()

	return d
}

// Emit sends an event to all matching destinations
func (d *Dispatcher) Emit(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("evt_%d", time.Now().UnixNano())
	}

	select {
	case d.eventChan <- event:
	default:
		slog.Warn("webhook: event buffer full, dropping event", "type", event.Type)
	}
}

// Close stops the dispatcher and waits for pending events
func (d *Dispatcher) Close() {
	close(d.closed)
	d.wg.Wait()
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case event := <-d.eventChan:
			d.dispatch(event)
		case <-d.closed:
			// Drain remaining events
			for {
				select {
				case event := <-d.eventChan:
					d.dispatch(event)
				default:
					return
				}
			}
		}
	}
}

func (d *Dispatcher) dispatch(event Event) {
	for _, dest := range d.destinations {
		if !dest.Enabled {
			continue
		}
		if !matchesEvent(dest.Events, event.Type) {
			continue
		}

		if dest.Name == "slack" {
			d.sendSlack(dest, event)
		} else {
			d.sendWebhook(dest, event)
		}
	}
}

func matchesEvent(filter []EventType, eventType EventType) bool {
	if len(filter) == 0 {
		return true // no filter = all events
	}
	for _, f := range filter {
		if f == eventType {
			return true
		}
	}
	return false
}

func (d *Dispatcher) sendWebhook(dest Destination, event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		slog.Error("webhook: marshal error", "error", err)
		return
	}

	for attempt := 0; attempt <= d.config.RetryCount; attempt++ {
		req, err := http.NewRequest(http.MethodPost, dest.URL, bytes.NewReader(payload))
		if err != nil {
			slog.Error("webhook: request error", "dest", dest.Name, "error", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AgentVeil-Webhook/1.0")
		req.Header.Set("X-Veil-Event", string(event.Type))
		req.Header.Set("X-Veil-Delivery", event.ID)

		// HMAC signature
		if dest.Secret != "" {
			sig := signPayload(payload, dest.Secret)
			req.Header.Set("X-Veil-Signature", "sha256="+sig)
		}

		// Custom headers
		for k, v := range dest.Headers {
			req.Header.Set(k, v)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			slog.Warn("webhook: delivery failed", "dest", dest.Name, "attempt", attempt+1, "error", err)
			if attempt < d.config.RetryCount {
				time.Sleep(time.Duration(attempt+1) * time.Second)
			}
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			slog.Debug("webhook: delivered", "dest", dest.Name, "event", event.Type)
			return
		}

		slog.Warn("webhook: non-2xx response", "dest", dest.Name, "status", resp.StatusCode, "attempt", attempt+1)
		if attempt < d.config.RetryCount {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
}

func (d *Dispatcher) sendSlack(dest Destination, event Event) {
	text := formatSlackMessage(event)
	payload, _ := json.Marshal(map[string]string{
		"text": text,
	})

	if d.config.Slack != nil && d.config.Slack.Channel != "" {
		var m map[string]string
		json.Unmarshal(payload, &m)
		m["channel"] = d.config.Slack.Channel
		if d.config.Slack.Username != "" {
			m["username"] = d.config.Slack.Username
		}
		payload, _ = json.Marshal(m)
	}

	resp, err := d.client.Post(dest.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		slog.Warn("webhook: slack delivery failed", "error", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("webhook: slack non-200", "status", resp.StatusCode)
	}
}

func formatSlackMessage(event Event) string {
	emoji := "🔔"
	switch event.Type {
	case EventPIIHighRisk:
		emoji = "🚨"
	case EventPromptInjection:
		emoji = "⚠️"
	case EventGuardrailViolation:
		emoji = "🛡️"
	case EventAuditHighRisk:
		emoji = "❌"
	case EventProviderFailover:
		emoji = "🔄"
	}

	data, _ := json.MarshalIndent(event.Data, "", "  ")
	return fmt.Sprintf("%s *[Agent Veil]* `%s`\nSession: `%s`\nTime: %s\n```%s```",
		emoji, event.Type, event.SessionID, event.Timestamp.Format("15:04:05"), string(data))
}

// signPayload creates an HMAC-SHA256 signature
func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies a webhook signature (for receivers)
func VerifySignature(payload []byte, signature, secret string) bool {
	expected := signPayload(payload, secret)
	return hmac.Equal([]byte("sha256="+expected), []byte(signature))
}
