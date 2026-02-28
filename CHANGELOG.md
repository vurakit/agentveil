# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Core Proxy
- Core reverse proxy with `httputil.ReverseProxy`
- Real-time PII detection and anonymization (inbound)
- Outbound rehydration for JSON and SSE streaming responses
- `/v1/*` OpenAI-compatible proxy endpoint
- `/audit` skill.md analysis endpoint
- `/health` health check endpoint
- Docker and Docker Compose deployment
- Graceful shutdown with signal handling

#### Privacy & PII (GĐ2)
- Vietnam-specific PII patterns: CCCD, CMND, MST, SĐT, Bank Account, Address, Military ID, Passport
- International PII patterns: SSN, Credit Card, IBAN, NHS Number, US/EU/JP/KR Passport
- Multimedia PII extraction: image OCR and PDF text scanning
- Confidence scoring and contextual validation for reduced false positives

#### Security (GĐ1)
- API key authentication with HMAC-SHA256 and Redis-backed storage
- AES-256-GCM encrypted vault with per-session token isolation
- Structured logging with audit trail
- Per-IP rate limiting with configurable burst
- TLS support via environment variables

#### AI Security (GĐ3)
- Skill.md static auditor with 10 security rules and risk scoring
- Prompt injection protection: 11 input patterns, 4 output patterns
- Vietnamese-language prompt injection detection
- Canary token system for data leak detection (zero-width char injection)
- Runtime guardrails: token limits, harmful content blocking, topic filtering
- Per-session sliding window rate limiting in guardrails
- Compliance framework: Vietnam AI Law 2026 (7 requirements), EU AI Act (5), GDPR (6)
- Weighted compliance scoring with evidence tracking and auto-recommendations

#### Multi-Provider & Routing (GĐ4)
- Multi-provider LLM routing: OpenAI, Anthropic, Gemini, Ollama
- Unified request/response format adapters across all providers
- Load balancing: round-robin, weighted, priority strategies
- Auto-failover with health monitoring and 30s recovery
- Path-based and header-based route resolution

#### CLI Tool (GĐ4)
- `agentveil proxy start` — Start the proxy server
- `agentveil wrap -- <cmd>` — Auto-route Claude/Cursor/Aider through proxy
- `agentveil scan <text>` — Scan text for PII with confidence scores
- `agentveil audit <file>` — Analyze skill.md for security risks
- `agentveil compliance check` — Check against Vietnam AI Law / EU AI Act / GDPR

#### SDKs (GĐ4)
- Go SDK: HTTP transport wrapper for any Go HTTP client
- Python SDK: `activate()` monkey-patch, session management, audit API
- Node.js/TypeScript SDK: full client with streaming, scanning, audit
- LangChain integration: Agent VeilCallbackHandler + Agent VeilChatModel
- MCP server for Claude Code / Cursor integration

#### Integrations (GĐ4)
- Webhook dispatcher with async delivery and retry with backoff
- HMAC-SHA256 webhook signature verification
- Slack integration with formatted messages
- 8 event types: pii.detected, prompt_injection.detected, guardrail.violation, etc.

#### DevOps
- GitHub Actions CI: test, lint, build with 80% coverage threshold
- GoReleaser for cross-platform builds (Linux, macOS, Windows; amd64, arm64)
- Makefile with standard development targets
- Issue templates and PR template
