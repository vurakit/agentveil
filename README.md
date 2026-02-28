<p align="center">
  <h1 align="center">Agent Veil</h1>
  <p align="center">Security Proxy for AI Agents — PII protection, prompt injection defense, multi-provider routing, and compliance enforcement. Zero code changes.</p>
</p>

<p align="center">
  <a href="https://github.com/vurakit/agentveil/actions/workflows/ci.yml"><img src="https://github.com/vurakit/agentveil/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go" alt="Go 1.23"></a>
</p>

---

## How It Works

```
                           Agent Veil Proxy
                         ┌──────────────────────────────────┐
                         │                                  │
┌─────────────┐   PII    │  ┌────────────┐  ┌───────────┐  │  Safe     ┌──────────────┐
│ Claude Code ├─────────►│  │ PII Shield │  │ Prompt    │  ├─────────►│ Anthropic    │
│ Cursor      │          │  │ Anonymize  │  │ Injection │  │          │ api.anthropic│
│ Aider       │          │  │ ──────►    │  │ Guard     │  │          └──────────────┘
│ Any SDK     │          │  └────────────┘  └───────────┘  │
│             │          │                                  │  Safe     ┌──────────────┐
│             │   PII    │  ┌────────────┐  ┌───────────┐  ├─────────►│ OpenAI       │
│             │◄─────────┤  │ Rehydrate  │  │ Guardrail │  │          │ api.openai   │
│             │          │  │ ◄──────    │  │ Enforce   │  │          └──────────────┘
└─────────────┘          │  └────────────┘  └───────────┘  │
                         │                                  │  Safe     ┌──────────────┐
                         │  ┌─────────────────────────────┐ ├─────────►│ Gemini       │
                         │  │ Redis Vault (AES-256-GCM)   │ │          │ googleapis   │
                         │  │ Session-isolated PII tokens │ │          └──────────────┘
                         │  └─────────────────────────────┘ │
                         └──────────────────────────────────┘
```

### Request/Response Flow

```
1. You send:      "CCCD cua toi la 012345678901, email thinh@gmail.com"
                              │
                              ▼
2. Proxy anonymizes:  "CCCD cua toi la [CCCD_1], email [EMAIL_1]"
   Vault stores:       [CCCD_1] → 012345678901 (encrypted, 30min TTL)
                       [EMAIL_1] → thinh@gmail.com
                              │
                              ▼
3. LLM receives:      "CCCD cua toi la [CCCD_1], email [EMAIL_1]"
   LLM responds:      "Da nhan CCCD [CCCD_1] va email [EMAIL_1]"
                              │
                              ▼
4. Proxy rehydrates:  "Da nhan CCCD 012345678901 va email thinh@gmail.com"
   You receive:        ▲ Real data restored seamlessly
```

### Role-Based Masking

```
                    ┌─────────────────────────────────┐
                    │         Same Response            │
                    └─────────┬───────────┬───────────┘
                              │           │
              ┌───────────────┘           └───────────────┐
              ▼                                           ▼
   X-User-Role: admin                          X-User-Role: viewer
   "Phone: 0369275275"                         "Phone: 03xxxxxx75"
   Full data visible                           70% masked
```

---

## Features

### Privacy & PII Protection
- **Real-time PII Shield** — Anonymize on inbound, rehydrate on outbound, including SSE streaming
- **Vietnam PII** — CCCD, CMND, Tax ID (TIN), Phone, Bank Account, Address, Military ID, Passport, License Plate, BHXH
- **International PII** — SSN, Credit Card, IBAN, NHS, Passport (US/EU/UK/JP/KR), IP Address
- **Secret Detection** — API keys (OpenAI, Anthropic, AWS, GitHub, Stripe...), PEM keys, JWTs, connection strings
- **AES-256-GCM Vault** — Encrypted token storage in Redis with per-session isolation and TTL
- **Role-based Masking** — `admin` (full), `viewer` (70% masked), `operator` (partial)
- **Multimedia PII** — OCR extraction from images (Tesseract), text extraction from PDFs

### Security
- **Prompt Injection Protection** — 11+ attack patterns (instruction override, jailbreak, DAN, encoding, Vietnamese-language attacks)
- **Canary Token System** — Invisible markers to detect data leaks in LLM outputs
- **Runtime Guardrails** — Token limits, harmful content blocking, topic filtering, session rate limiting, duration limits
- **API Key Authentication** — HMAC-SHA256 with Redis-backed key management
- **Rate Limiting** — Per-IP sliding window with configurable burst

### Multi-Provider Routing
- **4 Providers** — OpenAI, Anthropic, Gemini, Ollama with unified format adapters
- **Smart Routing** — Path-based, header-based (`X-Veil-Provider`), or load-balanced
- **Load Balancing** — Round-robin, weighted, priority strategies
- **Auto Failover** — Health monitoring with automatic recovery

### Compliance
- **Vietnam AI Law 2026** — 7 requirements, 4-level risk scoring (minimal/limited/high/unacceptable)
- **EU AI Act** — 5 requirements with weighted scoring
- **GDPR** — 6 requirements with evidence tracking
- **Auto Recommendations** — Generated fix suggestions for non-compliant items

### Webhooks & Notifications
- **Discord** — Rich embed notifications with color-coded severity
- **Slack** — Channel/username customizable webhook messages
- **Custom Webhooks** — HMAC-SHA256 signed payloads with retry support
- **Event Types** — PII detected, high risk PII, prompt injection, guardrail violation, audit alerts, rate limit hits, provider failover

### SDKs
- **Go** — HTTP transport wrapper
- **Python** — `activate()` monkey-patch, session management, audit API
- **Node.js/TypeScript** — Full client with streaming
- **LangChain** — CallbackHandler + ChatModel drop-in
- **MCP Server** — Model Context Protocol for Claude Code / Cursor

---

## Quick Start

### Option 1: Native Setup (recommended)

```bash
git clone https://github.com/vurakit/agentveil.git && cd agentveil
./setup.sh
source ~/.zshrc   # apply env vars
```

This will:
1. Build the proxy binary natively (requires Go)
2. Install to `~/.agentveil/` with config and router
3. Start Redis (via Docker or Homebrew)
4. Register as a background service (launchd on macOS, systemd on Linux)
5. Inject environment variables into your shell profile

The proxy auto-starts on login and auto-restarts on crash.

```bash
./setup.sh --status     # Check all components
./setup.sh --restart    # Rebuild + restart (after code changes)
./setup.sh --logs       # Tail proxy logs
./setup.sh --stop       # Stop proxy
./setup.sh --start      # Start proxy
./setup.sh --uninstall  # Remove completely
```

### Option 2: Docker Compose

```bash
git clone https://github.com/vurakit/agentveil.git && cd agentveil
cp .env.example .env
# Edit .env — set TARGET_URL, VEIL_ENCRYPTION_KEY, etc.
docker compose up -d
```

Verify:
```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### Option 3: Build from Source

```bash
git clone https://github.com/vurakit/agentveil.git && cd agentveil
make build    # outputs bin/agentveil-proxy + bin/agentveil

# Start Redis
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run proxy
export VEIL_ENCRYPTION_KEY=$(openssl rand -hex 32)
TARGET_URL=https://api.openai.com ./bin/agentveil-proxy
```

### Option 4: Go Install

```bash
go install github.com/vurakit/agentveil/cmd/proxy@latest
go install github.com/vurakit/agentveil/cmd/vura@latest
```

---

## Connect Your AI Tool

```bash
# Claude Code
ANTHROPIC_BASE_URL=http://localhost:8080 claude

# Cursor / Aider / any OpenAI-compatible tool
OPENAI_BASE_URL=http://localhost:8080/v1 aider

# Or use the CLI wrapper (auto-detects tool)
agentveil wrap -- claude
agentveil wrap -- cursor
agentveil wrap -- aider
```

### Python

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sk-...",
    default_headers={
        "X-Session-ID": "my-session",
        "X-User-Role": "admin",
    },
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "CCCD cua toi la 012345678901"}],
)
# PII was anonymized before reaching OpenAI, then restored in the response
```

### Go

```go
import agentveil "github.com/vurakit/agentveil/sdk/go"

cfg := agentveil.Config{
    ProxyURL:  "http://localhost:8080",
    Role:      "admin",
    SessionID: "my-session",
}
httpClient := agentveil.NewHTTPClient(cfg)
// Use httpClient with any Go HTTP library or OpenAI SDK
```

### Python SDK (activate pattern)

```python
import agentveil

agentveil.activate(api_key="sk-...", role="admin")
# All OpenAI calls now go through Agent Veil automatically

# Audit a skill.md file
result = agentveil.audit_skill(open("skill.md").read())
print(result["risk_level"])
```

---

## CLI Reference

```bash
# Start the proxy server
agentveil proxy start

# Wrap any AI tool to route through proxy (auto-detects tool)
agentveil wrap -- claude
agentveil wrap -- cursor
agentveil wrap -- aider

# Scan text for PII
agentveil scan "CCCD: 012345678901, phone: 0369275275"
agentveil scan --json "email: test@example.com"
echo "some text" | agentveil scan -    # stdin

# Audit skill.md for security risks
agentveil audit skill.md
agentveil audit --format json skill.md
agentveil audit --format html skill.md > report.html
cat skill.md | agentveil audit -       # stdin

# Check compliance
agentveil compliance check --framework vietnam
agentveil compliance check --framework eu
agentveil compliance check --framework gdpr
agentveil compliance check --framework all --format json

# Show config
agentveil config show

# Setup / uninstall
agentveil setup
agentveil setup --status
agentveil setup --undo
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/*` | POST/PUT | OpenAI-compatible proxy with automatic PII shield |
| `/scan` | POST | Scan text for PII. Body: `{"text": "..."}` |
| `/audit` | POST | Audit skill.md for security risks. Body: `{"content": "..."}` |
| `/health` | GET | Health check |
| `/healthz` | GET | Health check (alias) |

### Request Headers

| Header | Values | Description |
|--------|--------|-------------|
| `X-User-Role` | `admin` / `viewer` / `operator` | Controls data masking level (default: `viewer`) |
| `X-Session-ID` | Any string | Groups PII mappings per session |
| `X-Veil-Provider` | `openai` / `anthropic` / `gemini` / `ollama` | Route to specific provider (router mode) |
| `Authorization` | `Bearer <key>` | API authentication |
| `x-api-key` | `<key>` | Alternative API key header |

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example).

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `https://api.openai.com` | Upstream LLM API URL |
| `LISTEN_ADDR` | `:8080` | Proxy listen address |
| `REDIS_ADDR` | `localhost:6379` | Redis connection |
| `REDIS_PASSWORD` | _(empty)_ | Redis password |
| `VEIL_ENCRYPTION_KEY` | _(empty)_ | AES-256 key (64 hex chars). Generate: `openssl rand -hex 32` |
| `TLS_CERT` / `TLS_KEY` | _(empty)_ | TLS certificate and key paths |
| `LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `VEIL_API_KEYS` | _(empty)_ | Comma-separated API keys for client authentication |
| `VEIL_RATE_LIMIT` | `60` | Requests per minute per IP |
| `VEIL_RATE_BURST` | `20` | Rate limit burst size |
| `VEIL_DEFAULT_ROLE` | `viewer` | Default role when `X-User-Role` header is absent (`admin` / `viewer` / `operator`) |
| `VEIL_ROUTER_CONFIG` | _(empty)_ | Path to router YAML for multi-provider mode |
| `VEIL_DISCORD_WEBHOOK_URL` | _(empty)_ | Discord webhook URL for notifications |
| `VEIL_SLACK_WEBHOOK_URL` | _(empty)_ | Slack webhook URL for notifications |
| `VEIL_WEBHOOK_URL` | _(empty)_ | Custom webhook endpoint |
| `VEIL_WEBHOOK_SECRET` | _(empty)_ | HMAC signing secret for custom webhooks |

---

## Multi-Provider Routing

Enable by setting `VEIL_ROUTER_CONFIG=router.yaml`. Example config:

```yaml
providers:
  - name: anthropic
    base_url: https://api.anthropic.com
    api_key: $ANTHROPIC_API_KEY       # env var reference
    auth_method: x-api-key            # Anthropic uses x-api-key header
    priority: 1
    enabled: true

  - name: gemini
    base_url: https://generativelanguage.googleapis.com
    api_key: $GOOGLE_API_KEY
    auth_method: query
    auth_param: key
    priority: 2
    enabled: true

routes:
  - path_prefix: /gemini
    provider: gemini
  # All other paths go to default_route

fallback:
  enabled: true
  max_attempts: 2
  retry_delay_sec: 1

load_balance: priority            # priority | round_robin | weighted
default_route: anthropic
```

```
                     ┌────────────────────────────────────┐
                     │          Agent Veil Router          │
                     │                                    │
  /v1/messages ─────►│  Path: /v1/* ───► default_route ──►│──► Anthropic
                     │                                    │
  /gemini/v1beta ───►│  Path: /gemini/* ─► strip prefix ─►│──► Gemini
                     │                                    │
  X-Veil-Provider ──►│  Header override ──────────────────│──► Any provider
                     │                                    │
                     │  Failover: anthropic → gemini      │
                     └────────────────────────────────────┘
```

---

## Webhook Notifications

Agent Veil sends real-time notifications when PII is detected or security events occur.

### Discord

Set `VEIL_DISCORD_WEBHOOK_URL` in `.env`. Events are sent as rich embeds with color-coded severity:
- **Red** — High risk PII, audit high risk, guardrail violations
- **Yellow** — PII detected, prompt injection, rate limit hits
- **Blue** — Informational events
- **Green** — Provider failover

### Slack

Set `VEIL_SLACK_WEBHOOK_URL` in `.env`.

### Event Types

| Event | Trigger |
|-------|---------|
| `pii.detected` | PII found and anonymized in request |
| `pii.high_risk` | High-risk PII detected (CCCD, SSN, credit card) |
| `prompt_injection.detected` | Prompt injection attempt blocked |
| `guardrail.violation` | Runtime guardrail violated |
| `audit.complete` | Skill.md audit completed |
| `audit.high_risk` | High-risk findings in skill.md audit |
| `rate_limit.hit` | Client hit rate limit |
| `provider.failover` | Provider failed, traffic rerouted |

---

## Project Structure

```
cmd/
  proxy/                 Entry point for the proxy server
  vura/                  CLI tool (wrap, scan, audit, compliance, setup)
internal/
  proxy/                 Reverse proxy, middleware, SSE streaming, PII shield
  detector/              PII scanner, anonymization engine, confidence scoring
  vault/                 Redis-backed AES-256-GCM encrypted token vault
  auth/                  API key authentication (HMAC-SHA256)
  ratelimit/             Per-IP sliding window rate limiting
  promptguard/           Prompt injection detection, canary tokens
  guardrail/             Runtime safety policies (token limits, content filter)
  compliance/            Vietnam AI Law 2026, EU AI Act, GDPR checker
  auditor/               skill.md static security analyzer
  router/                Multi-provider routing, load balancing, failover
  webhook/               Event dispatcher (Discord, Slack, custom webhooks)
  media/                 Multimedia PII extraction (OCR, PDF)
  logging/               Structured JSON logging (slog)
pkg/pii/                 Shared PII regex patterns (Vietnam + international)
sdk/
  go/                    Go SDK — HTTP transport wrapper
  python/                Python SDK — activate(), session, audit
  node/                  Node.js/TypeScript SDK
  langchain/             LangChain integration
  mcp/                   MCP server for Claude Code / Cursor
examples/                Integration examples (Python, Go, Docker deploy)
```

---

## Development

```bash
make help              # Show all available commands
make build             # Build proxy + CLI binaries
make test              # Run all tests with race detection
make test-cover        # Tests with coverage (80% threshold)
make lint              # Run golangci-lint
make fmt               # Format code + go mod tidy
make docker-up         # Start with Docker Compose
make docker-down       # Stop all services
make install           # Install to $GOPATH/bin
make clean             # Remove build artifacts
```

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./internal/proxy/... -v
go test ./internal/webhook/... -v
go test ./internal/detector/... -v

# With coverage
make test-cover
```

---

## MCP Server (Claude Code / Cursor)

Agent Veil includes an MCP server that integrates directly with Claude Code and Cursor.

Available tools:
- `scan_pii` — Scan text for PII
- `audit_skill` — Audit skill.md for security
- `check_compliance` — Check regulatory compliance
- `health_check` — Check proxy health

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE) — Copyright (c) 2026 Agent Veil Contributors
