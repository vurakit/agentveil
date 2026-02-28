package media

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// FileType identifies the media type
type FileType string

const (
	TypeImage FileType = "image"
	TypePDF   FileType = "pdf"
)

// ExtractionResult holds text extracted from media
type ExtractionResult struct {
	Text     string   `json:"text"`
	FileType FileType `json:"file_type"`
	Pages    int      `json:"pages,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Extractor pulls text from images and PDFs for PII scanning
type Extractor struct {
	tesseractPath string
	pdfToTextPath string
}

// New creates an Extractor. Checks for system dependencies.
func New() *Extractor {
	tess, _ := exec.LookPath("tesseract")
	pdf, _ := exec.LookPath("pdftotext")
	return &Extractor{
		tesseractPath: tess,
		pdfToTextPath: pdf,
	}
}

// Available reports which extraction capabilities are present
func (e *Extractor) Available() map[FileType]bool {
	return map[FileType]bool{
		TypeImage: e.tesseractPath != "",
		TypePDF:   e.pdfToTextPath != "",
	}
}

// ExtractFromBase64 decodes a base64 data blob and extracts text.
// fileType should be "image" or "pdf".
func (e *Extractor) ExtractFromBase64(data string, ft FileType) (*ExtractionResult, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return e.ExtractFromBytes(raw, ft)
}

// ExtractFromBytes extracts text from raw file bytes
func (e *Extractor) ExtractFromBytes(data []byte, ft FileType) (*ExtractionResult, error) {
	switch ft {
	case TypeImage:
		return e.ocrImage(data)
	case TypePDF:
		return e.extractPDF(data)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ft)
	}
}

// ocrImage runs Tesseract OCR on image bytes
func (e *Extractor) ocrImage(data []byte) (*ExtractionResult, error) {
	if e.tesseractPath == "" {
		return &ExtractionResult{
			FileType: TypeImage,
			Error:    "tesseract not installed",
		}, nil
	}

	// tesseract stdin stdout -l vie+eng
	cmd := exec.Command(e.tesseractPath, "stdin", "stdout", "-l", "vie+eng")
	cmd.Stdin = bytes.NewReader(data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &ExtractionResult{
			FileType: TypeImage,
			Error:    fmt.Sprintf("tesseract: %v: %s", err, stderr.String()),
		}, nil
	}

	return &ExtractionResult{
		Text:     strings.TrimSpace(stdout.String()),
		FileType: TypeImage,
	}, nil
}

// extractPDF runs pdftotext on PDF bytes
func (e *Extractor) extractPDF(data []byte) (*ExtractionResult, error) {
	if e.pdfToTextPath == "" {
		return &ExtractionResult{
			FileType: TypePDF,
			Error:    "pdftotext not installed",
		}, nil
	}

	// pdftotext - - (stdin to stdout)
	cmd := exec.Command(e.pdfToTextPath, "-", "-")
	cmd.Stdin = bytes.NewReader(data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &ExtractionResult{
			FileType: TypePDF,
			Error:    fmt.Sprintf("pdftotext: %v: %s", err, stderr.String()),
		}, nil
	}

	text := strings.TrimSpace(stdout.String())
	pages := strings.Count(text, "\f") + 1

	return &ExtractionResult{
		Text:     text,
		FileType: TypePDF,
		Pages:    pages,
	}, nil
}

// OpenAIImageContent represents an image_url content block from OpenAI API
type OpenAIImageContent struct {
	Type     string `json:"type"`
	ImageURL *struct {
		URL string `json:"url"`
	} `json:"image_url,omitempty"`
}

// ExtractBase64FromDataURI parses "data:image/png;base64,..." URIs
func ExtractBase64FromDataURI(uri string) (data string, mimeType string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", "", false
	}
	parts := strings.SplitN(uri[5:], ",", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	meta := parts[0] // "image/png;base64"
	mimeType = strings.SplitN(meta, ";", 2)[0]
	return parts[1], mimeType, true
}

// DetectFileType guesses file type from MIME type string
func DetectFileType(mimeType string) FileType {
	switch {
	case strings.HasPrefix(mimeType, "image/"):
		return TypeImage
	case mimeType == "application/pdf":
		return TypePDF
	default:
		return ""
	}
}

// ScanOpenAIMessages scans OpenAI-format messages for base64 media content.
// Returns extracted texts for PII scanning.
func (e *Extractor) ScanOpenAIMessages(body []byte) []ExtractionResult {
	var payload struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}

	var results []ExtractionResult

	for _, msg := range payload.Messages {
		// Content can be string or array of content blocks
		var blocks []OpenAIImageContent
		if err := json.Unmarshal(msg.Content, &blocks); err != nil {
			continue // string content, skip
		}

		for _, block := range blocks {
			if block.Type != "image_url" || block.ImageURL == nil {
				continue
			}

			data, mimeType, ok := ExtractBase64FromDataURI(block.ImageURL.URL)
			if !ok {
				continue
			}

			ft := DetectFileType(mimeType)
			if ft == "" {
				continue
			}

			result, err := e.ExtractFromBase64(data, ft)
			if err != nil {
				results = append(results, ExtractionResult{
					FileType: ft,
					Error:    err.Error(),
				})
				continue
			}
			results = append(results, *result)
		}
	}

	return results
}
