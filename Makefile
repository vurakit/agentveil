.PHONY: build build-proxy build-cli test test-cover test-component lint fmt run docker-build docker-up docker-down clean install help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

## help: Show this help message
help:
	@echo "Agent Veil — Security Proxy for AI Agents"
	@echo ""
	@echo "Usage:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
	@echo ""

## build: Build both proxy and CLI binaries
build: build-proxy build-cli

## build-proxy: Build the proxy server
build-proxy:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/agentveil-proxy ./cmd/proxy

## build-cli: Build the CLI tool
build-cli:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/agentveil ./cmd/vura

## test: Run all tests with race detection
test:
	go test -race ./...

## test-cover: Run tests with coverage report
test-cover:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
	@echo ""
	@echo "To view HTML report: go tool cover -html=coverage.out"

## test-component: Run Docker component tests (requires OPENROUTER_API_KEY)
test-component:
	@tests/component/run.sh

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## fmt: Format all Go files
fmt:
	gofmt -w .
	go mod tidy

## run: Start proxy with default config (requires Redis)
run: build-proxy
	./bin/agentveil-proxy

## docker-build: Build Docker image
docker-build:
	docker build -t agentveil:$(VERSION) -t agentveil:latest .

## docker-up: Start all services with Docker Compose
docker-up:
	docker compose up -d

## docker-down: Stop all Docker Compose services
docker-down:
	docker compose down

## install: Install binaries to $GOPATH/bin
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/proxy
	go install -ldflags="$(LDFLAGS)" ./cmd/vura

## clean: Remove build artifacts
clean:
	rm -rf bin/ dist/ coverage.out
