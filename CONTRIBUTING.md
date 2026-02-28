# Contributing to Agent Veil

Thank you for your interest in contributing to Agent Veil! This guide will help you get started.

## Development Setup

### Prerequisites

- Go 1.23+
- Redis 7+ (for PII token vault)
- Docker & Docker Compose (optional, for easy setup)
- [golangci-lint](https://golangci-lint.run/welcome/install/) (for linting)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/vurakit/agentveil.git
cd agentveil

# Copy environment config
cp .env.example .env

# Start Redis (pick one)
docker run -d --name redis -p 6379:6379 redis:7-alpine  # Docker
# OR: brew install redis && brew services start redis    # macOS
# OR: sudo apt install redis-server                      # Ubuntu

# Install dependencies
go mod download

# Run tests
make test

# Build binaries
make build

# Start proxy
make run
```

### Using Docker Compose

```bash
docker compose up -d    # Start proxy + Redis
docker compose logs -f  # Watch logs
docker compose down     # Stop
```

## Project Structure

```
cmd/
  proxy/              → Proxy server entry point (main binary)
  vura/               → CLI tool (wrap, scan, audit, compliance)
internal/
  proxy/              → Reverse proxy, middleware chain, SSE streaming
  detector/           → PII regex scanner and anonymization engine
  vault/              → Redis-backed encrypted PII token vault (AES-256-GCM)
  auth/               → API key authentication (HMAC-SHA256)
  ratelimit/          → Per-IP rate limiting with burst support
  promptguard/        → Prompt injection detection & canary tokens
  guardrail/          → Runtime safety guardrails (token limits, topic filter)
  compliance/         → Regulatory compliance (Vietnam AI Law, EU AI Act, GDPR)
  auditor/            → skill.md static security analyzer
  router/             → Multi-provider LLM routing & load balancing
  webhook/            → Webhook dispatcher with HMAC signing & Slack
  media/              → Multimedia PII extraction (image OCR, PDF)
  logging/            → Structured logging
pkg/pii/              → Shared PII regex patterns (Vietnam + international)
sdk/                  → Multi-language SDKs (Go, Python, Node.js, LangChain, MCP)
examples/             → Integration examples
```

## Code Standards

- **Language**: Go 1.23+
- **Formatting**: `gofmt` (enforced by CI)
- **Linting**: `golangci-lint` — config in `.golangci.yml`
- **Testing**: `go test` with `-race` flag
- **Coverage**: Minimum 80% (enforced by CI)

## Available Make Commands

```bash
make help         # Show all commands
make build        # Build proxy + CLI
make test         # Run tests with race detection
make test-cover   # Tests with coverage report
make lint         # Run golangci-lint
make fmt          # Format code + tidy modules
make docker-build # Build Docker image
make install      # Install to $GOPATH/bin
make clean        # Remove build artifacts
```

## How to Contribute

### Reporting Bugs

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:
- Go version (`go version`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

### Suggesting Features

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) and describe:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Ensure all tests pass: `make test`
5. Ensure linting passes: `make lint`
6. Commit with clear messages: `git commit -m "feat: add credit card PII pattern"`
7. Push and create a Pull Request

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new PII pattern for bank accounts
fix: reduce false positives in CCCD detection
docs: update quickstart guide
test: add benchmark for detector
refactor: simplify vault TTL logic
```

### Adding New PII Patterns

1. Add regex pattern to `pkg/pii/patterns.go`
2. Add unit tests in `internal/detector/detector_test.go`
3. Include both true positives and false positives in test cases
4. Document the pattern format in your PR description

### Adding a New LLM Provider

1. Add adapter in `internal/router/adapter.go` (`AdaptToProvider` / `AdaptFromProvider`)
2. Add provider config in `internal/router/config.go`
3. Add tests in `internal/router/router_test.go`
4. Update documentation

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## License

By contributing, you agree that your contributions will be licensed under MIT.
