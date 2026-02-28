package promptguard

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// Middleware intercepts HTTP requests/responses and scans for prompt injection
func Middleware(guard *Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB
			r.Body.Close()
			if err != nil {
				slog.Warn("promptguard: read body failed", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			// Extract text content from OpenAI/Anthropic request body
			text := extractTextFromBody(body)
			if text == "" {
				r.Body = io.NopCloser(bytes.NewReader(body))
				next.ServeHTTP(w, r)
				return
			}

			result := guard.ScanInput(text)

			if guard.ShouldBlock(result) {
				slog.Warn("promptguard: blocked request",
					"threat_level", result.ThreatLevel.String(),
					"score", result.Score,
					"detections", len(result.Detections),
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				resp := map[string]any{
					"error": map[string]any{
						"message": "Request blocked: prompt injection detected",
						"type":    "prompt_injection",
						"threat":  result.ThreatLevel.String(),
						"score":   result.Score,
					},
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			if len(result.Detections) > 0 {
				slog.Info("promptguard: suspicious input (allowed)",
					"threat_level", result.ThreatLevel.String(),
					"score", result.Score,
					"detections", len(result.Detections),
				)
			}

			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

// extractTextFromBody extracts user message text from OpenAI/Anthropic request formats
func extractTextFromBody(body []byte) string {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return string(body)
	}

	var texts []string

	// OpenAI format: {"messages": [{"role": "user", "content": "..."}]}
	if messages, ok := data["messages"].([]any); ok {
		for _, msg := range messages {
			m, ok := msg.(map[string]any)
			if !ok {
				continue
			}
			// Only scan user messages (not system/assistant)
			role, _ := m["role"].(string)
			if role != "user" {
				continue
			}

			switch content := m["content"].(type) {
			case string:
				texts = append(texts, content)
			case []any:
				// Multi-part content (text + images)
				for _, part := range content {
					p, ok := part.(map[string]any)
					if !ok {
						continue
					}
					if p["type"] == "text" {
						if t, ok := p["text"].(string); ok {
							texts = append(texts, t)
						}
					}
				}
			}
		}
	}

	// Anthropic format: {"messages": [{"role": "user", "content": [...]}]}
	// Same structure, already handled above

	// Fallback: raw prompt field
	if prompt, ok := data["prompt"].(string); ok {
		texts = append(texts, prompt)
	}
	if input, ok := data["input"].(string); ok {
		texts = append(texts, input)
	}

	return joinTexts(texts)
}

func joinTexts(texts []string) string {
	if len(texts) == 0 {
		return ""
	}
	var sb bytes.Buffer
	for i, t := range texts {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(t)
	}
	return sb.String()
}
