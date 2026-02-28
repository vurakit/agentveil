package media

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractBase64FromDataURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantOK   bool
		wantMime string
	}{
		{"valid image", "data:image/png;base64,iVBOR...", true, "image/png"},
		{"valid pdf", "data:application/pdf;base64,JVBER...", true, "application/pdf"},
		{"no data prefix", "http://example.com/img.png", false, ""},
		{"no comma", "data:image/png;base64", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mime, ok := ExtractBase64FromDataURI(tt.uri)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && mime != tt.wantMime {
				t.Errorf("mime = %s, want %s", mime, tt.wantMime)
			}
		})
	}
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		mime string
		want FileType
	}{
		{"image/png", TypeImage},
		{"image/jpeg", TypeImage},
		{"application/pdf", TypePDF},
		{"text/plain", ""},
	}

	for _, tt := range tests {
		got := DetectFileType(tt.mime)
		if got != tt.want {
			t.Errorf("DetectFileType(%s) = %s, want %s", tt.mime, got, tt.want)
		}
	}
}

func TestAvailable(t *testing.T) {
	e := New()
	avail := e.Available()

	// Should return both keys even if tools not installed
	if _, ok := avail[TypeImage]; !ok {
		t.Error("missing TypeImage key in Available()")
	}
	if _, ok := avail[TypePDF]; !ok {
		t.Error("missing TypePDF key in Available()")
	}
}

func TestExtractFromBytes_UnsupportedType(t *testing.T) {
	e := New()
	_, err := e.ExtractFromBytes([]byte("data"), "video")
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestExtractFromBytes_ImageNoTesseract(t *testing.T) {
	// Force no tesseract
	e := &Extractor{tesseractPath: "", pdfToTextPath: ""}

	result, err := e.ExtractFromBytes([]byte("fake-image"), TypeImage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error message about tesseract not installed")
	}
}

func TestExtractFromBytes_PDFNoPdftotext(t *testing.T) {
	e := &Extractor{tesseractPath: "", pdfToTextPath: ""}

	result, err := e.ExtractFromBytes([]byte("fake-pdf"), TypePDF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error message about pdftotext not installed")
	}
}

func TestExtractFromBase64_InvalidBase64(t *testing.T) {
	e := New()
	_, err := e.ExtractFromBase64("not-valid-base64!!!", TypeImage)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestScanOpenAIMessages_NoMedia(t *testing.T) {
	e := New()

	body := `{"messages":[{"role":"user","content":"Hello"}]}`
	results := e.ScanOpenAIMessages([]byte(body))
	if len(results) != 0 {
		t.Errorf("expected 0 results for text-only message, got %d", len(results))
	}
}

func TestScanOpenAIMessages_WithImage(t *testing.T) {
	e := New()

	// Build a fake base64 image data URI
	fakeImg := base64.StdEncoding.EncodeToString([]byte("fake-png-data"))
	dataURI := "data:image/png;base64," + fakeImg

	msg := map[string]interface{}{
		"messages": []map[string]interface{}{
			{
				"role": "user",
				"content": []map[string]interface{}{
					{
						"type": "image_url",
						"image_url": map[string]string{
							"url": dataURI,
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(msg)
	results := e.ScanOpenAIMessages(body)

	// Should attempt extraction (may fail due to no tesseract, but should not panic)
	if len(results) != 1 {
		t.Errorf("expected 1 extraction result, got %d", len(results))
	}
}

func TestScanOpenAIMessages_InvalidJSON(t *testing.T) {
	e := New()
	results := e.ScanOpenAIMessages([]byte("not json"))
	if len(results) != 0 {
		t.Errorf("expected 0 results for invalid JSON, got %d", len(results))
	}
}
