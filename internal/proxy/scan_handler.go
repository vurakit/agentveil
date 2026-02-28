package proxy

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/vurakit/agentveil/internal/detector"
)

// ScanRequest is the JSON body for PII scan requests
type ScanRequest struct {
	Text string `json:"text"`
}

// ScanEntity represents a detected PII entity in the scan response
type ScanEntity struct {
	Original   string `json:"original"`
	Category   string `json:"category"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Confidence int    `json:"confidence"`
}

// ScanResponse is the JSON response for /scan
type ScanResponse struct {
	Found    bool         `json:"found"`
	Entities []ScanEntity `json:"entities"`
}

// HandleScan returns an http.HandlerFunc for POST /scan (standalone, no Server needed).
// Used in router mode where /scan is registered outside the Server handler chain.
func HandleScan(det *detector.Detector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srv := &Server{detector: det}
		srv.handleScan(w, r)
	}
}

// handleScan handles POST /scan to detect PII in text
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
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

	var req ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"bad_request","message":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Text == "" {
		http.Error(w, `{"error":"bad_request","message":"text is required"}`, http.StatusBadRequest)
		return
	}

	matches := s.detector.Scan(req.Text)

	entities := make([]ScanEntity, 0, len(matches))
	for _, m := range matches {
		entities = append(entities, ScanEntity{
			Original:   m.Original,
			Category:   string(m.Category),
			Start:      m.Start,
			End:        m.End,
			Confidence: m.Confidence,
		})
	}

	resp := ScanResponse{
		Found:    len(entities) > 0,
		Entities: entities,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
