#!/usr/bin/env bash
set -euo pipefail

# === Agent Veil — One-Command Setup ===

MARKER_START="# >>> Agent Veil >>>"
MARKER_END="# <<< Agent Veil <<<"
PROXY_URL="http://localhost:8080"
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
HEALTH_TIMEOUT=60

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail()  { echo -e "${RED}[fail]${NC}  $*"; }

# Detect shell profile file
detect_shell_profile() {
    local shell_name
    shell_name="$(basename "${SHELL:-/bin/bash}")"
    case "$shell_name" in
        zsh)  echo "${HOME}/.zshrc" ;;
        bash)
            if [[ -f "${HOME}/.bash_profile" ]]; then
                echo "${HOME}/.bash_profile"
            else
                echo "${HOME}/.bashrc"
            fi
            ;;
        fish) echo "${HOME}/.config/fish/config.fish" ;;
        *)    echo "${HOME}/.profile" ;;
    esac
}

# ─── Pre-flight checks ───────────────────────────────────────────
preflight() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        fail "docker not found. Install: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        fail "docker compose not found. Install Docker Desktop or the compose plugin."
        missing=1
    fi

    if [[ $missing -ne 0 ]]; then
        exit 1
    fi

    ok "docker and docker compose found"
}

# ─── Generate .env ────────────────────────────────────────────────
generate_env() {
    if [[ -f "$ENV_FILE" ]]; then
        info ".env already exists, keeping it"
        return
    fi

    if [[ ! -f "$ENV_EXAMPLE" ]]; then
        fail ".env.example not found — are you in the agentveil repo root?"
        exit 1
    fi

    cp "$ENV_EXAMPLE" "$ENV_FILE"

    # Auto-generate encryption key
    local key
    key="$(openssl rand -hex 32)"
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "s/^VEIL_ENCRYPTION_KEY=.*/VEIL_ENCRYPTION_KEY=${key}/" "$ENV_FILE"
        sed -i '' "s|^TARGET_URL=.*|TARGET_URL=https://api.anthropic.com|" "$ENV_FILE"
    else
        sed -i "s/^VEIL_ENCRYPTION_KEY=.*/VEIL_ENCRYPTION_KEY=${key}/" "$ENV_FILE"
        sed -i "s|^TARGET_URL=.*|TARGET_URL=https://api.anthropic.com|" "$ENV_FILE"
    fi

    ok "Generated .env with encryption key"
}

# ─── Start services ──────────────────────────────────────────────
start_services() {
    info "Building and starting containers..."
    docker compose -f "$COMPOSE_FILE" up -d --build
    ok "Containers started"
}

# ─── Health check ─────────────────────────────────────────────────
wait_for_health() {
    info "Waiting for proxy to be healthy (max ${HEALTH_TIMEOUT}s)..."
    local elapsed=0
    while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
        if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
            ok "Proxy is healthy"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    fail "Proxy did not become healthy within ${HEALTH_TIMEOUT}s"
    echo "  Check logs: docker compose logs proxy"
    exit 1
}

# ─── Inject shell env vars ────────────────────────────────────────
inject_shell_env() {
    local profile
    profile="$(detect_shell_profile)"

    # Skip if already injected
    if grep -qF "$MARKER_START" "$profile" 2>/dev/null; then
        info "Shell env vars already in ${profile}, skipping"
        return
    fi

    local shell_name
    shell_name="$(basename "${SHELL:-/bin/bash}")"

    if [[ "$shell_name" == "fish" ]]; then
        cat >> "$profile" <<EOF

$MARKER_START
set -gx ANTHROPIC_BASE_URL ${PROXY_URL}
set -gx OPENAI_API_BASE ${PROXY_URL}/v1
set -gx OPENAI_BASE_URL ${PROXY_URL}/v1
set -gx GEMINI_API_BASE ${PROXY_URL}/gemini
$MARKER_END
EOF
    else
        cat >> "$profile" <<EOF

$MARKER_START
export ANTHROPIC_BASE_URL=${PROXY_URL}
export OPENAI_API_BASE=${PROXY_URL}/v1
export OPENAI_BASE_URL=${PROXY_URL}/v1
export GEMINI_API_BASE=${PROXY_URL}/gemini
$MARKER_END
EOF
    fi

    ok "Added env vars to ${profile}"
}

# ─── Export for current session ────────────────────────────────────
export_current_session() {
    export ANTHROPIC_BASE_URL="${PROXY_URL}"
    export OPENAI_API_BASE="${PROXY_URL}/v1"
    export OPENAI_BASE_URL="${PROXY_URL}/v1"
    export GEMINI_API_BASE="${PROXY_URL}/gemini"
}

# ─── Print success ────────────────────────────────────────────────
print_success() {
    local profile
    profile="$(detect_shell_profile)"

    echo ""
    echo -e "${GREEN}=== Agent Veil is ready! ===${NC}"
    echo ""
    echo "  All AI tools will now route through the security proxy."
    echo ""
    echo "  To apply env vars in your current terminal:"
    echo -e "    ${BLUE}source ${profile}${NC}"
    echo ""
    echo "  Test commands:"
    echo "    curl -s ${PROXY_URL}/health"
    echo "    curl -s -X POST ${PROXY_URL}/scan \\"
    echo '      -H "Content-Type: application/json" \'
    echo '      -d '\''{"text":"sk-ant-api03-abcdef1234567890"}'\'''
    echo ""
    echo "  Uninstall:"
    echo "    ./setup.sh --uninstall"
    echo ""
}

# ─── Uninstall ────────────────────────────────────────────────────
do_uninstall() {
    info "Uninstalling Agent Veil..."

    # Remove env block from shell profile
    local profile
    profile="$(detect_shell_profile)"

    if [[ -f "$profile" ]] && grep -qF "$MARKER_START" "$profile"; then
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        else
            sed -i "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        fi
        # Remove trailing blank line left behind
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$profile" 2>/dev/null || true
        else
            sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$profile" 2>/dev/null || true
        fi
        ok "Removed env vars from ${profile}"
    else
        info "No env vars found in ${profile}"
    fi

    # Stop containers
    if [[ -f "$COMPOSE_FILE" ]]; then
        info "Stopping containers..."
        docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
        ok "Containers stopped and volumes removed"
    fi

    # Remove .env
    if [[ -f "$ENV_FILE" ]]; then
        rm "$ENV_FILE"
        ok "Removed .env"
    fi

    echo ""
    echo -e "${GREEN}Agent Veil uninstalled.${NC}"
    echo "  Restart your shell or run: source ${profile}"
}

# ─── Status ───────────────────────────────────────────────────────
do_status() {
    echo "=== Agent Veil Status ==="
    echo ""

    # Proxy health
    if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
        ok "Proxy:           healthy (${PROXY_URL})"
    else
        fail "Proxy:           unreachable (${PROXY_URL})"
    fi

    # Docker containers
    if docker compose -f "$COMPOSE_FILE" ps --status running 2>/dev/null | grep -q "proxy"; then
        ok "Container proxy: running"
    else
        fail "Container proxy: not running"
    fi

    if docker compose -f "$COMPOSE_FILE" ps --status running 2>/dev/null | grep -q "redis"; then
        ok "Container redis: running"
    else
        fail "Container redis: not running"
    fi

    # Shell env vars
    local profile
    profile="$(detect_shell_profile)"
    if grep -qF "$MARKER_START" "$profile" 2>/dev/null; then
        ok "Shell profile:   configured (${profile})"
    else
        warn "Shell profile:   not configured (${profile})"
    fi

    # Current session env
    echo ""
    echo "  Current session env:"
    echo "    ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL:-<not set>}"
    echo "    OPENAI_API_BASE=${OPENAI_API_BASE:-<not set>}"
    echo "    OPENAI_BASE_URL=${OPENAI_BASE_URL:-<not set>}"
    echo "    GEMINI_API_BASE=${GEMINI_API_BASE:-<not set>}"
    echo ""

    # .env file
    if [[ -f "$ENV_FILE" ]]; then
        ok ".env file:       present"
    else
        warn ".env file:       missing"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────
main() {
    case "${1:-}" in
        --uninstall|-u)
            do_uninstall
            ;;
        --status|-s)
            do_status
            ;;
        --help|-h)
            echo "Usage: ./setup.sh [option]"
            echo ""
            echo "Options:"
            echo "  (none)         Full setup: build, start, configure shell"
            echo "  --uninstall    Remove Agent Veil (containers, env, .env)"
            echo "  --status       Check current status"
            echo "  --help         Show this help"
            ;;
        "")
            echo ""
            echo -e "${BLUE}=== Agent Veil Setup ===${NC}"
            echo ""
            preflight
            generate_env
            start_services
            wait_for_health
            inject_shell_env
            export_current_session
            print_success
            ;;
        *)
            fail "Unknown option: $1"
            echo "Run ./setup.sh --help for usage"
            exit 1
            ;;
    esac
}

main "$@"
