// Package mcp implements a Model Context Protocol (MCP) server for Vura.
//
// MCP allows AI tools (Claude Code, Cursor, etc.) to discover and use
// Vura capabilities as tools: PII scanning, auditing, compliance checking.
//
// Usage:
//
//	server := mcp.NewServer(mcp.Config{ProxyURL: "http://localhost:8080"})
//	server.ListenAndServe(":9090")
package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ToolName constants
const (
	ToolScanPII         = "vura_scan_pii"
	ToolAuditSkill      = "vura_audit_skill"
	ToolCheckCompliance = "vura_check_compliance"
	ToolHealthCheck     = "vura_health"
)

// Config for the MCP server
type Config struct {
	ProxyURL string // Vura proxy URL
}

// Server implements MCP protocol endpoints
type Server struct {
	config Config
}

// NewServer creates an MCP server
func NewServer(cfg Config) *Server {
	return &Server{config: cfg}
}

// Tool represents an MCP tool definition
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolResult is the response from executing a tool
type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock represents a content block in MCP response
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ListToolsResponse is the response for tools/list
type ListToolsResponse struct {
	Tools []Tool `json:"tools"`
}

// Handler returns the HTTP handler for MCP endpoints
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/tools/list", s.handleListTools)
	mux.HandleFunc("/mcp/tools/call", s.handleCallTool)
	mux.HandleFunc("/mcp/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","protocol":"mcp","version":"2024-11-05"}`))
	})
	return mux
}

func (s *Server) handleListTools(w http.ResponseWriter, r *http.Request) {
	tools := ListToolsResponse{
		Tools: []Tool{
			{
				Name:        ToolScanPII,
				Description: "Scan text for PII (Personally Identifiable Information). Detects Vietnamese CCCD, phone, address, and international PII like credit cards, SSN.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"text": {"type": "string", "description": "Text to scan for PII"}
					},
					"required": ["text"]
				}`),
			},
			{
				Name:        ToolAuditSkill,
				Description: "Audit an AI agent skill.md file for security compliance against Vietnam AI Law 2026 and international standards.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"content": {"type": "string", "description": "Skill.md content to audit"}
					},
					"required": ["content"]
				}`),
			},
			{
				Name:        ToolCheckCompliance,
				Description: "Check system compliance status against Vietnam AI Law 2026, EU AI Act, and GDPR frameworks.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"framework": {
							"type": "string",
							"enum": ["vietnam_ai_2026", "eu_ai_act", "gdpr", "all"],
							"description": "Regulatory framework to check against"
						}
					},
					"required": ["framework"]
				}`),
			},
			{
				Name:        ToolHealthCheck,
				Description: "Check the health status of the Vura privacy proxy.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {}
				}`),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tools)
}

func (s *Server) handleCallTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name   string          `json:"name"`
		Params json.RawMessage `json:"arguments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeToolError(w, "invalid request body")
		return
	}

	var result ToolResult

	switch req.Name {
	case ToolScanPII:
		result = s.callScanPII(req.Params)
	case ToolAuditSkill:
		result = s.callAuditSkill(req.Params)
	case ToolCheckCompliance:
		result = s.callCheckCompliance(req.Params)
	case ToolHealthCheck:
		result = s.callHealthCheck()
	default:
		writeToolError(w, fmt.Sprintf("unknown tool: %s", req.Name))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) callScanPII(params json.RawMessage) ToolResult {
	var input struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	resp, err := http.Post(s.config.ProxyURL+"/scan", "application/json",
		jsonReader(map[string]string{"text": input.Text}))
	if err != nil {
		return errorResult("scan failed: " + err.Error())
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	text, _ := json.MarshalIndent(result, "", "  ")
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(text)}},
	}
}

func (s *Server) callAuditSkill(params json.RawMessage) ToolResult {
	var input struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	resp, err := http.Post(s.config.ProxyURL+"/audit", "application/json",
		jsonReader(map[string]string{"content": input.Content}))
	if err != nil {
		return errorResult("audit failed: " + err.Error())
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	text, _ := json.MarshalIndent(result, "", "  ")
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(text)}},
	}
}

func (s *Server) callCheckCompliance(params json.RawMessage) ToolResult {
	var input struct {
		Framework string `json:"framework"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	resp, err := http.Get(s.config.ProxyURL + "/compliance?framework=" + input.Framework)
	if err != nil {
		return errorResult("compliance check failed: " + err.Error())
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	text, _ := json.MarshalIndent(result, "", "  ")
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(text)}},
	}
}

func (s *Server) callHealthCheck() ToolResult {
	resp, err := http.Get(s.config.ProxyURL + "/health")
	if err != nil {
		return errorResult("health check failed: " + err.Error())
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	text, _ := json.MarshalIndent(result, "", "  ")
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: string(text)}},
	}
}

func errorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func writeToolError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(errorResult(msg))
}

func jsonReader(v any) io.Reader {
	data, _ := json.Marshal(v)
	return bytes.NewReader(data)
}
