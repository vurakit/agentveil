package proxy

import (
	"log"
	"net/http"
	"strings"
)

// roleMiddleware checks X-User-Role header and enforces access control
func (s *Server) roleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-User-Role")
		if role == "" {
			role = s.config.DefaultRole
			r.Header.Set("X-User-Role", role)
		}

		role = strings.ToLower(role)

		// Validate role
		switch role {
		case "admin", "viewer", "operator":
			// allowed roles
		default:
			log.Printf("[middleware] rejected unknown role: %s", role)
			http.Error(w, `{"error":"forbidden","message":"unknown role"}`, http.StatusForbidden)
			return
		}

		log.Printf("[middleware] %s %s role=%s session=%s",
			r.Method, r.URL.Path, role, extractSessionID(r))

		next.ServeHTTP(w, r)
	})
}

// securityEnforcer checks for blatant data exfiltration attempts
func (s *Server) securityEnforcer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for suspicious patterns in headers
		for key, values := range r.Header {
			for _, v := range values {
				if containsSuspiciousPayload(key) || containsSuspiciousPayload(v) {
					log.Printf("[security] blocked suspicious header: %s", key)
					http.Error(w, `{"error":"forbidden","message":"security violation detected"}`, http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

var suspiciousPatterns = []string{
	"curl ",
	"wget ",
	"nc ",
	"/etc/passwd",
	"/etc/shadow",
	"base64 -d",
	"eval(",
	"exec(",
}

func containsSuspiciousPayload(s string) bool {
	lower := strings.ToLower(s)
	for _, pat := range suspiciousPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}
