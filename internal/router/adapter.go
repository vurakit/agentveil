package router

import (
	"encoding/json"
	"fmt"
)

// UnifiedMessage is the internal message format used across providers
type UnifiedMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// UnifiedRequest is a provider-agnostic chat request
type UnifiedRequest struct {
	Model       string           `json:"model"`
	Messages    []UnifiedMessage `json:"messages"`
	MaxTokens   int              `json:"max_tokens,omitempty"`
	Temperature float64          `json:"temperature,omitempty"`
	Stream      bool             `json:"stream,omitempty"`
}

// UnifiedResponse is a provider-agnostic chat response
type UnifiedResponse struct {
	ID      string           `json:"id"`
	Model   string           `json:"model"`
	Content string           `json:"content"`
	Usage   *UnifiedUsage    `json:"usage,omitempty"`
}

// UnifiedUsage tracks token usage
type UnifiedUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AdaptToProvider converts a unified request to provider-specific JSON
func AdaptToProvider(provider string, req UnifiedRequest) ([]byte, error) {
	switch provider {
	case "openai":
		return adaptToOpenAI(req)
	case "anthropic":
		return adaptToAnthropic(req)
	case "gemini":
		return adaptToGemini(req)
	case "ollama":
		return adaptToOllama(req)
	default:
		// Default: pass through as OpenAI-compatible
		return adaptToOpenAI(req)
	}
}

// AdaptFromProvider converts a provider-specific response to unified format
func AdaptFromProvider(provider string, data []byte) (*UnifiedResponse, error) {
	switch provider {
	case "openai":
		return adaptFromOpenAI(data)
	case "anthropic":
		return adaptFromAnthropic(data)
	case "gemini":
		return adaptFromGemini(data)
	case "ollama":
		return adaptFromOllama(data)
	default:
		return adaptFromOpenAI(data)
	}
}

// === OpenAI ===

func adaptToOpenAI(req UnifiedRequest) ([]byte, error) {
	oai := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
		"stream":   req.Stream,
	}
	if req.MaxTokens > 0 {
		oai["max_tokens"] = req.MaxTokens
	}
	if req.Temperature > 0 {
		oai["temperature"] = req.Temperature
	}
	return json.Marshal(oai)
}

func adaptFromOpenAI(data []byte) (*UnifiedResponse, error) {
	var resp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse openai response: %w", err)
	}

	content := ""
	if len(resp.Choices) > 0 {
		content = resp.Choices[0].Message.Content
	}

	return &UnifiedResponse{
		ID:      resp.ID,
		Model:   resp.Model,
		Content: content,
		Usage: &UnifiedUsage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
		},
	}, nil
}

// === Anthropic ===

func adaptToAnthropic(req UnifiedRequest) ([]byte, error) {
	// Anthropic separates system from messages
	var systemPrompt string
	var messages []map[string]string
	for _, m := range req.Messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}
		messages = append(messages, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}

	ant := map[string]any{
		"model":      req.Model,
		"messages":   messages,
		"max_tokens": req.MaxTokens,
		"stream":     req.Stream,
	}
	if systemPrompt != "" {
		ant["system"] = systemPrompt
	}
	if req.Temperature > 0 {
		ant["temperature"] = req.Temperature
	}
	if req.MaxTokens == 0 {
		ant["max_tokens"] = 4096 // Anthropic requires max_tokens
	}
	return json.Marshal(ant)
}

func adaptFromAnthropic(data []byte) (*UnifiedResponse, error) {
	var resp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse anthropic response: %w", err)
	}

	content := ""
	for _, block := range resp.Content {
		if block.Type == "text" {
			content += block.Text
		}
	}

	return &UnifiedResponse{
		ID:      resp.ID,
		Model:   resp.Model,
		Content: content,
		Usage: &UnifiedUsage{
			InputTokens:  resp.Usage.InputTokens,
			OutputTokens: resp.Usage.OutputTokens,
		},
	}, nil
}

// === Gemini ===

func adaptToGemini(req UnifiedRequest) ([]byte, error) {
	var parts []map[string]any
	for _, m := range req.Messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		if role == "system" {
			role = "user" // Gemini doesn't have system role, prepend to first user message
		}
		parts = append(parts, map[string]any{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}

	gemini := map[string]any{
		"contents": parts,
	}
	if req.MaxTokens > 0 || req.Temperature > 0 {
		genConfig := map[string]any{}
		if req.MaxTokens > 0 {
			genConfig["maxOutputTokens"] = req.MaxTokens
		}
		if req.Temperature > 0 {
			genConfig["temperature"] = req.Temperature
		}
		gemini["generationConfig"] = genConfig
	}
	return json.Marshal(gemini)
}

func adaptFromGemini(data []byte) (*UnifiedResponse, error) {
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse gemini response: %w", err)
	}

	content := ""
	if len(resp.Candidates) > 0 {
		for _, part := range resp.Candidates[0].Content.Parts {
			content += part.Text
		}
	}

	return &UnifiedResponse{
		ID:    "",
		Model: "",
		Content: content,
		Usage: &UnifiedUsage{
			InputTokens:  resp.UsageMetadata.PromptTokenCount,
			OutputTokens: resp.UsageMetadata.CandidatesTokenCount,
		},
	}, nil
}

// === Ollama ===

func adaptToOllama(req UnifiedRequest) ([]byte, error) {
	ollama := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
		"stream":   req.Stream,
	}
	if req.MaxTokens > 0 {
		ollama["options"] = map[string]any{
			"num_predict": req.MaxTokens,
		}
	}
	if req.Temperature > 0 {
		opts, _ := ollama["options"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		opts["temperature"] = req.Temperature
		ollama["options"] = opts
	}
	return json.Marshal(ollama)
}

func adaptFromOllama(data []byte) (*UnifiedResponse, error) {
	var resp struct {
		Model   string `json:"model"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		PromptEvalCount int `json:"prompt_eval_count"`
		EvalCount       int `json:"eval_count"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse ollama response: %w", err)
	}

	return &UnifiedResponse{
		ID:      "",
		Model:   resp.Model,
		Content: resp.Message.Content,
		Usage: &UnifiedUsage{
			InputTokens:  resp.PromptEvalCount,
			OutputTokens: resp.EvalCount,
		},
	}, nil
}
