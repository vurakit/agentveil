package auth

import (
	"log"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that validates API keys.
// If the key is valid, it sets X-User-Role from the key's bound role
// (overriding any client-provided value) and passes to the next handler.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Support both "Authorization: Bearer <key>" (OpenAI) and "x-api-key: <key>" (Anthropic)
		var token string
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"unauthorized","message":"invalid Authorization format"}`, http.StatusUnauthorized)
				return
			}
			token = parts[1]
		} else if apiKey := r.Header.Get("x-api-key"); apiKey != "" {
			token = apiKey
		} else {
			http.Error(w, `{"error":"unauthorized","message":"missing Authorization or x-api-key header"}`, http.StatusUnauthorized)
			return
		}

		// If it's a Agent Veil API key, validate and bind role
		if strings.HasPrefix(token, "veil_sk_") {
			apiKey, err := m.Validate(r.Context(), token)
			if err != nil {
				log.Printf("[auth] rejected key: %v", err)
				http.Error(w, `{"error":"unauthorized","message":"invalid or revoked API key"}`, http.StatusUnauthorized)
				return
			}

			// Override role from key binding — client cannot escalate
			r.Header.Set("X-User-Role", string(apiKey.Role))
			r.Header.Set("X-Veil-Key-ID", apiKey.ID)

			log.Printf("[auth] authenticated key=%s role=%s", apiKey.ID, apiKey.Role)
		}

		// Non-veil keys (e.g. sk-xxx for OpenAI) pass through
		next.ServeHTTP(w, r)
	})
}
