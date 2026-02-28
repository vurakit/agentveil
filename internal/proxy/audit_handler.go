package proxy

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/vura/privacyguard/internal/auditor"
)

// AuditRequest is the JSON body for skill.md audit requests
type AuditRequest struct {
	Content string `json:"content"`
}

// handleAudit handles POST /audit to analyze skill.md content
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"bad_request","message":"cannot read body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req AuditRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"bad_request","message":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, `{"error":"bad_request","message":"content is required"}`, http.StatusBadRequest)
		return
	}

	a := auditor.New()
	report := a.Analyze(req.Content)

	w.Header().Set("Content-Type", "application/json")

	if report.RiskLevel >= auditor.RiskHigh {
		w.WriteHeader(http.StatusForbidden)
	}

	json.NewEncoder(w).Encode(report)
}
