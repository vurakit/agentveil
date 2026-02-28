# Agent Veil — Security Proxy for AI Agents

> Real-time PII protection, prompt injection defense, and compliance enforcement between your app and LLM APIs. Zero code changes required.

```
┌──────────────┐          ┌─────────────────────────┐          ┌──────────────┐
│  Your App    │ ──PII──▶ │      VURA Proxy         │ ──safe──▶│   LLM API    │
│  Claude Code │          │  • PII anonymization     │          │  OpenAI      │
│  Cursor      │ ◀──PII── │  • Injection protection  │ ◀─safe──│  Anthropic   │
│  Aider       │          │  • Guardrails            │          │  Gemini      │
│  Any SDK     │          │  • Compliance checking   │          │  Ollama      │
└──────────────┘          └─────────────────────────┘          └──────────────┘
```

[![CI](https://github.com/vurakit/agentveil/actions/workflows/ci.yml/badge.svg)](https://github.com/vurakit/agentveil/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

### Privacy & PII Protection
- **Real-time PII Shield** — Detects and anonymizes PII before sending to LLM, restores on response
- **Vietnam PII** — CCCD, CMND, Tax ID, Phone, Bank Account, Address, Military ID, Passport
- **International PII** — SSN, Credit Card, IBAN, NHS, Passport (US/EU/UK/JP/KR)
- **Multimedia PII** — Extract and scan text from images (OCR) and PDF documents
- **AES-256-GCM Vault** — Encrypted token storage in Redis with session isolation
- **Role-based Masking** — `admin` sees full data, `viewer` sees 70% masked, `operator` sees partial

### Security
- **Prompt Injection Protection** — 11 attack patterns detected (instruction override, jailbreak, DAN, encoding attacks, Vietnamese-language attacks)
- **Canary Token System** — Invisible markers to detect data leaks from LLM outputs
- **Runtime Guardrails** — Token limits, harmful content blocking, topic filtering, per-session rate limiting
- **API Key Authentication** — HMAC-SHA256 key management with Redis-backed storage
- **Rate Limiting** — Configurable per-IP rate limits with burst support

### Compliance
- **Vietnam AI Law 2026** — 7 requirements, 4-level risk scoring
- **EU AI Act** — 5 requirements with weighted scoring
- **GDPR** — 6 requirements with evidence tracking
- **Auto Recommendations** — Generated fix suggestions for non-compliant items

### Multi-Provider Routing
- **4 Providers** — OpenAI, Anthropic, Gemini, Ollama with unified format adapters
- **Smart Routing** — Path-based, header-based, or load-balanced routing
- **Load Balancing** — Round-robin, weighted, priority strategies
- **Auto Failover** — Health monitoring with automatic recovery after 30s

### Integrations
- **Skill.md Auditor** — Static security analysis for AI agent instructions
- **Webhooks** — Async event delivery with HMAC signing and Slack integration
- **OpenAI-compatible API** — Works with any OpenAI SDK, just change `base_url`
- **SSE Streaming** — Line-by-line rehydration without breaking AI output

### SDKs
- **Go** — HTTP transport wrapper for any Go HTTP client
- **Python** — `activate()` monkey-patch, session management, audit API
- **Node.js/TypeScript** — Full client with streaming, scanning, audit
- **LangChain** — Agent VeilCallbackHandler + Agent VeilChatModel drop-in replacement
- **MCP Server** — Model Context Protocol server for Claude Code / Cursor

### CLI Tool
- `agentveil proxy start` — Start the proxy server
- `agentveil wrap -- <cmd>` — Auto-route AI tools (Claude, Cursor, Aider) through proxy
- `agentveil scan <text>` — Scan text for PII
- `agentveil audit <file>` — Analyze skill.md for security risks
- `agentveil compliance check` — Check regulatory compliance

## Quick Start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/vurakit/agentveil.git && cd agentveil
cp .env.example .env    # Edit configuration
docker compose up -d
```

### Option 2: Build from source

```bash
git clone https://github.com/vurakit/agentveil.git && cd agentveil
make build              # Builds bin/agentveil-proxy and bin/agentveil

# Start Redis
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run proxy
TARGET_URL=https://api.openai.com ./bin/agentveil-proxy
```

### Option 3: Go install

```bash
go install github.com/vurakit/agentveil/cmd/proxy@latest
go install github.com/vurakit/agentveil/cmd/vura@latest
```

### Connect your AI tool

```bash
# Claude Code
ANTHROPIC_BASE_URL=http://localhost:8080/v1 claude

# Cursor / Aider / any OpenAI-compatible tool
OPENAI_BASE_URL=http://localhost:8080/v1 aider

# Or use the CLI wrapper (auto-detects tool)
agentveil wrap -- claude
agentveil wrap -- aider

# Python
client = OpenAI(base_url="http://localhost:8080/v1", api_key="sk-...")
```

That's it. All PII is now automatically protected.

## How It Works

1. **You send**: `"CCCD của tôi là 012345678901"`
2. **LLM receives**: `"CCCD của tôi là [CCCD_1]"` — real data never leaves your infra
3. **LLM responds**: `"Đã nhận [CCCD_1] của bạn"`
4. **You receive**: `"Đã nhận 012345678901 của bạn"` — seamlessly restored

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /v1/*` | OpenAI-compatible proxy (auto PII shield) |
| `POST /audit` | Analyze skill.md for security risks |
| `GET /health` | Health check |

## Headers

| Header | Values | Description |
|--------|--------|-------------|
| `X-User-Role` | `admin` / `viewer` / `operator` | Controls data masking level |
| `X-Session-ID` | Any string | Groups PII mappings per session |
| `X-Agent Veil-Provider` | `openai` / `anthropic` / `gemini` / `ollama` | Route to specific provider |
| `Authorization` | `Bearer <api-key>` | API authentication |

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `https://api.openai.com` | Upstream LLM API |
| `LISTEN_ADDR` | `:8080` | Proxy listen address |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | _(empty)_ | Redis password |
| `VEIL_ENCRYPTION_KEY` | _(empty)_ | AES-256 key (64 hex chars). Generate: `openssl rand -hex 32` |
| `TLS_CERT` / `TLS_KEY` | _(empty)_ | TLS certificate and key paths |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

## Project Structure

```
cmd/
  proxy/              → Proxy server entry point
  vura/               → CLI tool (wrap, scan, audit, compliance)
internal/
  proxy/              → Reverse proxy, middleware, SSE streaming
  detector/           → PII scanner and anonymization engine
  vault/              → Redis-backed encrypted PII token vault
  auth/               → API key authentication (HMAC-SHA256)
  ratelimit/          → Per-IP rate limiting
  promptguard/        → Prompt injection detection & canary tokens
  guardrail/          → Runtime safety guardrails
  compliance/         → Regulatory compliance framework
  auditor/            → skill.md static security analyzer
  router/             → Multi-provider LLM routing & load balancing
  webhook/            → Webhook dispatcher with Slack integration
  media/              → Multimedia PII extraction (image OCR, PDF)
  logging/            → Structured logging
pkg/pii/              → Shared PII regex patterns (Vietnam + international)
sdk/
  go/                 → Go SDK (HTTP transport wrapper)
  python/             → Python SDK (activate, session, audit)
  node/               → Node.js/TypeScript SDK
  langchain/          → LangChain integration
  mcp/                → MCP server for Claude Code / Cursor
examples/             → Integration examples (Python, Go, Docker)
```

## Development

```bash
make help             # Show all available commands
make test             # Run tests with race detection
make test-cover       # Run tests with coverage report
make lint             # Run golangci-lint
make fmt              # Format code
make build            # Build both binaries
make docker-up        # Start with Docker Compose
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[AGPL-3.0](LICENSE)
