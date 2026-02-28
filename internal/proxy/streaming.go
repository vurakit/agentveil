package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"strings"

	"github.com/vura/privacyguard/internal/vault"
)

// sseRehydrator wraps an SSE response body and rehydrates PII tokens line-by-line
type sseRehydrator struct {
	reader    *bufio.Scanner
	vault     *vault.Vault
	sessionID string
	mappings  map[string]string
	loaded    bool
	buf       *bytes.Buffer
	done      bool
}

func newSSERehydrator(body io.ReadCloser, v *vault.Vault, sessionID string) io.ReadCloser {
	return &sseRehydrator{
		reader:    bufio.NewScanner(body),
		vault:     v,
		sessionID: sessionID,
		buf:       &bytes.Buffer{},
	}
}

func (s *sseRehydrator) Read(p []byte) (int, error) {
	// If we have buffered data, return it first
	if s.buf.Len() > 0 {
		return s.buf.Read(p)
	}

	if s.done {
		return 0, io.EOF
	}

	// Lazy-load mappings on first read
	if !s.loaded {
		mappings, err := s.vault.LookupAll(context.Background(), s.sessionID)
		if err != nil {
			log.Printf("[sse] failed to load vault mappings: %v", err)
		}
		s.mappings = mappings
		s.loaded = true
	}

	// Read next SSE line
	if !s.reader.Scan() {
		s.done = true
		if err := s.reader.Err(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}

	line := s.reader.Text()

	// Rehydrate any PII tokens found in this SSE line
	if len(s.mappings) > 0 && strings.Contains(line, "[") {
		for token, original := range s.mappings {
			line = strings.ReplaceAll(line, token, original)
		}
	}

	// Write the processed line + newline to buffer
	s.buf.WriteString(line)
	s.buf.WriteByte('\n')

	return s.buf.Read(p)
}

func (s *sseRehydrator) Close() error {
	return nil
}
