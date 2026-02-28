package guardrail

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// ResponseMiddleware wraps an http.Handler and checks LLM output against guardrails
func ResponseMiddleware(g *Guardrail) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Session rate limiting (use X-Session-ID or fallback to IP)
			sessionID := r.Header.Get("X-Session-ID")
			if sessionID == "" {
				sessionID = r.RemoteAddr
			}

			rateResult := g.CheckRateLimit(sessionID)
			if !rateResult.Allowed {
				slog.Warn("guardrail: session rate limited",
					"session_id", sessionID,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"message": "Session rate limit exceeded",
						"type":    "rate_limit",
					},
				})
				return
			}

			// For SSE streaming, we can't buffer - pass through
			if isSSE(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Capture response for non-streaming requests
			rec := &responseRecorder{
				ResponseWriter: w,
				body:           &bytes.Buffer{},
				statusCode:     http.StatusOK,
			}
			next.ServeHTTP(rec, r)

			// Check output content
			body := rec.body.String()
			outputText := extractOutputText(body)

			if outputText != "" {
				result := g.CheckOutput(outputText)
				if !result.Allowed {
					slog.Warn("guardrail: output blocked",
						"violations", len(result.Violations),
						"session_id", sessionID,
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{
							"message": "Response blocked by guardrail",
							"type":    "guardrail_violation",
							"details": result.Violations,
						},
					})
					return
				}
			}

			// Write original response
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.statusCode)
			w.Write(rec.body.Bytes())
		})
	}
}

func isSSE(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}

// responseRecorder captures the response for inspection
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// extractOutputText extracts assistant message text from LLM response
func extractOutputText(body string) string {
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return body
	}

	var texts []string

	// OpenAI format: {"choices": [{"message": {"content": "..."}}]}
	if choices, ok := data["choices"].([]any); ok {
		for _, choice := range choices {
			c, ok := choice.(map[string]any)
			if !ok {
				continue
			}
			if msg, ok := c["message"].(map[string]any); ok {
				if content, ok := msg["content"].(string); ok {
					texts = append(texts, content)
				}
			}
			// Also check delta for streaming chunks
			if delta, ok := c["delta"].(map[string]any); ok {
				if content, ok := delta["content"].(string); ok {
					texts = append(texts, content)
				}
			}
		}
	}

	// Anthropic format: {"content": [{"text": "..."}]}
	if content, ok := data["content"].([]any); ok {
		for _, c := range content {
			block, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if block["type"] == "text" {
				if text, ok := block["text"].(string); ok {
					texts = append(texts, text)
				}
			}
		}
	}

	if len(texts) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, t := range texts {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(t)
	}
	return sb.String()
}

// InputMiddleware checks request body content against guardrail blocked topics
func InputMiddleware(g *Guardrail) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
			r.Body.Close()
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Check allowed/blocked topics in input
			if len(g.policy.AllowedTopics) > 0 || len(g.policy.BlockedTopics) > 0 {
				text := strings.ToLower(string(body))
				for _, topic := range g.policy.BlockedTopics {
					if strings.Contains(text, strings.ToLower(topic)) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]any{
							"error": map[string]any{
								"message": "Request contains blocked topic",
								"type":    "guardrail_topic_block",
								"topic":   topic,
							},
						})
						return
					}
				}
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}
