package media

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vura/privacyguard/internal/detector"
)

// ScanMiddleware intercepts multipart/form-data and JSON requests containing
// file attachments, extracts text via OCR/PDF, scans for PII, and blocks
// requests that contain sensitive data in attachments.
type ScanMiddleware struct {
	extractor *Extractor
	detector  *detector.Detector
	logger    *slog.Logger
	blockMode bool // true = block request if PII found, false = log only
}

// NewScanMiddleware creates attachment scanning middleware
func NewScanMiddleware(ext *Extractor, det *detector.Detector, logger *slog.Logger, block bool) *ScanMiddleware {
	return &ScanMiddleware{
		extractor: ext,
		detector:  det,
		logger:    logger,
		blockMode: block,
	}
}

// Middleware returns the HTTP middleware handler
func (sm *ScanMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}

		contentType := r.Header.Get("Content-Type")

		// Only scan JSON bodies (OpenAI format with base64 images)
		if !strings.Contains(contentType, "application/json") {
			next.ServeHTTP(w, r)
			return
		}

		// Read body for media scanning
		body, err := io.ReadAll(r.Body)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		r.Body.Close()

		// Restore body for downstream handlers
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Extract text from any embedded media
		results := sm.extractor.ScanOpenAIMessages(body)
		if len(results) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Scan extracted text for PII
		totalPII := 0
		for _, result := range results {
			if result.Error != "" || result.Text == "" {
				continue
			}

			matches := sm.detector.Scan(result.Text)
			if len(matches) > 0 {
				totalPII += len(matches)
				sm.logger.Warn("PII detected in attachment",
					"file_type", result.FileType,
					"pii_count", len(matches),
					"pages", result.Pages,
				)
			}
		}

		if totalPII > 0 && sm.blockMode {
			sm.logger.Error("blocked request: PII in media attachment",
				"pii_count", totalPII,
			)
			http.Error(w,
				`{"error":"forbidden","message":"PII detected in file attachment. Remove sensitive data before sending to AI."}`,
				http.StatusForbidden,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
