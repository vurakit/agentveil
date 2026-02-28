#!/usr/bin/env bash
set -euo pipefail

# === Agent Veil — Native Setup ===
# Builds the proxy binary natively (no Docker for proxy).
# Redis runs via Docker. Proxy runs as a launchd/systemd service.

MARKER_START="# >>> Agent Veil >>>"
MARKER_END="# <<< Agent Veil <<<"
PROXY_URL="http://localhost:8080"
INSTALL_DIR="${HOME}/.agentveil"
BIN_DIR="${INSTALL_DIR}/bin"
LOG_DIR="${INSTALL_DIR}/logs"
CONF_DIR="${INSTALL_DIR}"
BINARY="${BIN_DIR}/agentveil-proxy"
ENV_FILE="${CONF_DIR}/.env"
ROUTER_YAML="${CONF_DIR}/router.yaml"
PLIST_NAME="com.agentveil.proxy"
PLIST_PATH="${HOME}/Library/LaunchAgents/${PLIST_NAME}.plist"
SYSTEMD_DIR="${HOME}/.config/systemd/user"
SYSTEMD_UNIT="agentveil.service"
HEALTH_TIMEOUT=30

# Source repo directory (where this script lives)
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ ok ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
fail()  { echo -e "${RED}[fail]${NC}  $*"; }
step()  { echo -e "${CYAN}[step]${NC}  ${BOLD}$*${NC}"; }

is_macos() { [[ "$(uname)" == "Darwin" ]]; }

# ─── Detect shell profile ────────────────────────────────────────
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

# ─── 1. Pre-flight checks ────────────────────────────────────────
preflight() {
    step "Checking requirements..."
    local missing=0

    # Go is required to build
    if ! command -v go &>/dev/null; then
        fail "Go not found. Install: https://go.dev/dl/"
        missing=1
    else
        ok "Go $(go version | awk '{print $3}')"
    fi

    # Docker needed for Redis only
    if ! command -v docker &>/dev/null; then
        warn "Docker not found — Redis must be provided manually"
        warn "  Install Docker: https://docs.docker.com/get-docker/"
        warn "  Or install Redis: brew install redis"
    else
        ok "Docker found (for Redis)"
    fi

    if [[ $missing -ne 0 ]]; then
        exit 1
    fi
}

# ─── 2. Build binary ─────────────────────────────────────────────
build_binary() {
    step "Building Agent Veil proxy..."

    mkdir -p "$BIN_DIR" "$LOG_DIR"

    local version
    version="$(cd "$REPO_DIR" && git describe --tags --always --dirty 2>/dev/null || echo "dev")"

    (cd "$REPO_DIR" && CGO_ENABLED=0 go build \
        -ldflags="-s -w -X main.version=${version}" \
        -o "$BINARY" \
        ./cmd/proxy)

    (cd "$REPO_DIR" && CGO_ENABLED=0 go build \
        -ldflags="-s -w -X main.version=${version}" \
        -o "${BIN_DIR}/agentveil" \
        ./cmd/vura)

    chmod +x "$BINARY" "${BIN_DIR}/agentveil"
    ok "Built proxy + CLI (${version})"
}

# ─── 3. Install config files ─────────────────────────────────────
install_config() {
    step "Installing config..."

    # router.yaml
    if [[ -f "$ROUTER_YAML" ]]; then
        info "router.yaml already exists, keeping it"
    else
        cp "${REPO_DIR}/router.yaml" "$ROUTER_YAML"
        ok "Installed router.yaml"
    fi

    # .env
    if [[ -f "$ENV_FILE" ]]; then
        info ".env already exists, keeping it"
    else
        cp "${REPO_DIR}/.env.example" "$ENV_FILE"

        # Generate encryption key
        local key
        key="$(openssl rand -hex 32)"

        if is_macos; then
            sed -i '' "s/^VEIL_ENCRYPTION_KEY=.*/VEIL_ENCRYPTION_KEY=${key}/" "$ENV_FILE"
            sed -i '' "s|^TARGET_URL=.*|TARGET_URL=https://api.anthropic.com|" "$ENV_FILE"
            sed -i '' "s/^LOG_LEVEL=.*/LOG_LEVEL=info/" "$ENV_FILE"
            # Enable router mode
            sed -i '' "s|^# VEIL_ROUTER_CONFIG=.*|VEIL_ROUTER_CONFIG=${ROUTER_YAML}|" "$ENV_FILE"
        else
            sed -i "s/^VEIL_ENCRYPTION_KEY=.*/VEIL_ENCRYPTION_KEY=${key}/" "$ENV_FILE"
            sed -i "s|^TARGET_URL=.*|TARGET_URL=https://api.anthropic.com|" "$ENV_FILE"
            sed -i "s/^LOG_LEVEL=.*/LOG_LEVEL=info/" "$ENV_FILE"
            sed -i "s|^# VEIL_ROUTER_CONFIG=.*|VEIL_ROUTER_CONFIG=${ROUTER_YAML}|" "$ENV_FILE"
        fi

        ok "Generated .env with encryption key"
    fi
}

# ─── 4. Start Redis ──────────────────────────────────────────────
start_redis() {
    step "Starting Redis..."

    # Check if Redis is already running
    if redis-cli ping &>/dev/null 2>&1; then
        ok "Redis already running"
        return
    fi

    # Try Docker
    if command -v docker &>/dev/null; then
        # Check if container already exists
        if docker ps -a --format '{{.Names}}' | grep -q '^agentveil-redis$'; then
            if docker ps --format '{{.Names}}' | grep -q '^agentveil-redis$'; then
                ok "Redis container already running"
            else
                docker start agentveil-redis >/dev/null
                ok "Redis container restarted"
            fi
        else
            docker run -d \
                --name agentveil-redis \
                --restart unless-stopped \
                -p 6379:6379 \
                redis:7-alpine >/dev/null
            ok "Redis started via Docker (agentveil-redis)"
        fi

        # Wait for Redis
        local elapsed=0
        while [[ $elapsed -lt 10 ]]; do
            if docker exec agentveil-redis redis-cli ping &>/dev/null; then
                return
            fi
            sleep 1
            elapsed=$((elapsed + 1))
        done
        warn "Redis may not be ready yet"
        return
    fi

    # Try brew services (macOS)
    if is_macos && command -v brew &>/dev/null; then
        if brew list redis &>/dev/null 2>&1; then
            brew services start redis >/dev/null 2>&1 || true
            ok "Redis started via Homebrew"
            return
        fi
    fi

    warn "Could not start Redis automatically"
    warn "  Option 1: docker run -d --name agentveil-redis -p 6379:6379 redis:7-alpine"
    warn "  Option 2: brew install redis && brew services start redis"
}

# ─── 5. Install service (launchd / systemd) ──────────────────────
install_service() {
    step "Installing background service..."

    if is_macos; then
        install_launchd
    else
        install_systemd
    fi
}

install_launchd() {
    # Stop existing service if running
    if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
    fi

    # Build environment variables from .env
    local env_plist=""
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ -z "$key" || "$key" == \#* ]] && continue
        # Remove surrounding quotes
        value="${value%\"}"
        value="${value#\"}"
        # Skip empty values and commented-out vars
        [[ -z "$value" ]] && continue
        env_plist+="            <key>${key}</key>
            <string>${value}</string>
"
    done < "$ENV_FILE"

    cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${BINARY}</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
${env_plist}    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/proxy.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/proxy.err.log</string>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
PLIST

    launchctl load "$PLIST_PATH"
    ok "Installed launchd service (auto-start on login, auto-restart on crash)"
    info "  Plist: ${PLIST_PATH}"
    info "  Logs:  ${LOG_DIR}/proxy.log"
}

install_systemd() {
    mkdir -p "$SYSTEMD_DIR"

    # Build Environment lines from .env
    local env_lines=""
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        value="${value%\"}"
        value="${value#\"}"
        [[ -z "$value" ]] && continue
        env_lines+="Environment=${key}=${value}\n"
    done < "$ENV_FILE"

    cat > "${SYSTEMD_DIR}/${SYSTEMD_UNIT}" <<UNIT
[Unit]
Description=Agent Veil Security Proxy
After=network.target

[Service]
Type=simple
ExecStart=${BINARY}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
$(echo -e "$env_lines")
StandardOutput=append:${LOG_DIR}/proxy.log
StandardError=append:${LOG_DIR}/proxy.err.log

[Install]
WantedBy=default.target
UNIT

    systemctl --user daemon-reload
    systemctl --user enable --now "$SYSTEMD_UNIT"
    ok "Installed systemd user service (auto-start, auto-restart)"
    info "  Unit: ${SYSTEMD_DIR}/${SYSTEMD_UNIT}"
    info "  Logs: journalctl --user -u ${SYSTEMD_UNIT} -f"
}

# ─── 6. Health check ─────────────────────────────────────────────
wait_for_health() {
    step "Waiting for proxy..."
    local elapsed=0
    while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
        if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
            ok "Proxy healthy at ${PROXY_URL}"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    fail "Proxy not healthy after ${HEALTH_TIMEOUT}s"
    echo ""
    echo "  Check logs: tail -f ${LOG_DIR}/proxy.log"
    echo "  Check err:  tail -f ${LOG_DIR}/proxy.err.log"
    exit 1
}

# ─── 7. Inject shell env vars ────────────────────────────────────
inject_shell_env() {
    step "Configuring shell..."
    local profile
    profile="$(detect_shell_profile)"

    # Remove old block if present
    if grep -qF "$MARKER_START" "$profile" 2>/dev/null; then
        if is_macos; then
            sed -i '' "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        else
            sed -i "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        fi
    fi

    local shell_name
    shell_name="$(basename "${SHELL:-/bin/bash}")"

    if [[ "$shell_name" == "fish" ]]; then
        cat >> "$profile" <<EOF

$MARKER_START
fish_add_path ${BIN_DIR}
set -gx ANTHROPIC_BASE_URL ${PROXY_URL}
set -gx OPENAI_API_BASE ${PROXY_URL}/v1
set -gx OPENAI_BASE_URL ${PROXY_URL}/v1
set -gx GEMINI_API_BASE ${PROXY_URL}/gemini
set -gx VEIL_DEFAULT_ROLE viewer
$MARKER_END
EOF
    else
        cat >> "$profile" <<EOF

$MARKER_START
export PATH="${BIN_DIR}:\$PATH"
export ANTHROPIC_BASE_URL="${PROXY_URL}"
export OPENAI_API_BASE="${PROXY_URL}/v1"
export OPENAI_BASE_URL="${PROXY_URL}/v1"
export GEMINI_API_BASE="${PROXY_URL}/gemini"
export VEIL_DEFAULT_ROLE="viewer"
$MARKER_END
EOF
    fi

    ok "Updated ${profile}"
}

# ─── Print success ────────────────────────────────────────────────
print_success() {
    local profile
    profile="$(detect_shell_profile)"

    echo ""
    echo -e "${GREEN}${BOLD}=== Agent Veil is running! ===${NC}"
    echo ""
    echo -e "  ${BOLD}Architecture:${NC}"
    echo "    Claude Code (macOS) → localhost:8080 (Agent Veil native) → LLM APIs"
    echo "                                  ↕"
    echo "                          localhost:6379 (Redis)"
    echo ""
    echo -e "  ${BOLD}Installed to:${NC}  ${INSTALL_DIR}/"
    echo -e "  ${BOLD}Binary:${NC}        ${BINARY}"
    echo -e "  ${BOLD}Config:${NC}        ${ENV_FILE}"
    echo -e "  ${BOLD}Router:${NC}        ${ROUTER_YAML}"
    echo -e "  ${BOLD}Logs:${NC}          ${LOG_DIR}/proxy.log"
    echo ""
    echo -e "  ${BOLD}Apply env vars now:${NC}"
    echo -e "    ${CYAN}source ${profile}${NC}"
    echo ""
    echo -e "  ${BOLD}Test:${NC}"
    echo "    curl -s ${PROXY_URL}/health"
    echo "    curl -s -X POST ${PROXY_URL}/scan \\"
    echo '      -H "Content-Type: application/json" \'
    echo '      -d '\''{"text":"CCCD: 012345678901"}'\'''
    echo ""
    echo -e "  ${BOLD}Service commands:${NC}"
    if is_macos; then
        echo "    ./setup.sh --stop        Stop proxy"
        echo "    ./setup.sh --start       Start proxy"
        echo "    ./setup.sh --restart     Restart proxy (after config change)"
        echo "    ./setup.sh --logs        Tail proxy logs"
        echo "    ./setup.sh --status      Check everything"
        echo "    ./setup.sh --uninstall   Remove completely"
    else
        echo "    systemctl --user stop agentveil"
        echo "    systemctl --user start agentveil"
        echo "    systemctl --user restart agentveil"
        echo "    journalctl --user -u agentveil -f"
    fi
    echo ""
}

# ─── Service control ─────────────────────────────────────────────
do_stop() {
    info "Stopping Agent Veil..."
    if is_macos; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
    else
        systemctl --user stop "$SYSTEMD_UNIT" 2>/dev/null || true
    fi
    ok "Stopped"
}

do_start() {
    info "Starting Agent Veil..."
    if is_macos; then
        launchctl load "$PLIST_PATH" 2>/dev/null || true
    else
        systemctl --user start "$SYSTEMD_UNIT" 2>/dev/null || true
    fi

    sleep 1
    if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
        ok "Proxy healthy at ${PROXY_URL}"
    else
        warn "Proxy may still be starting — check: tail -f ${LOG_DIR}/proxy.log"
    fi
}

do_restart() {
    do_stop
    sleep 1
    # Rebuild if source changed
    if [[ -d "$REPO_DIR" ]] && [[ -f "${REPO_DIR}/cmd/proxy/main.go" ]]; then
        build_binary
    fi
    # Reload config into service
    if is_macos; then
        install_launchd
    fi
    sleep 1
    if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
        ok "Proxy healthy at ${PROXY_URL}"
    else
        warn "Proxy may still be starting — check: tail -f ${LOG_DIR}/proxy.log"
    fi
}

do_logs() {
    if [[ -f "${LOG_DIR}/proxy.log" ]]; then
        tail -f "${LOG_DIR}/proxy.log" "${LOG_DIR}/proxy.err.log"
    else
        fail "No logs found at ${LOG_DIR}/"
    fi
}

# ─── Status ───────────────────────────────────────────────────────
do_status() {
    echo -e "${BOLD}=== Agent Veil Status ===${NC}"
    echo ""

    # Binary
    if [[ -x "$BINARY" ]]; then
        ok "Binary:    ${BINARY}"
    else
        fail "Binary:    not found"
    fi

    # Service
    if is_macos; then
        if launchctl list 2>/dev/null | grep -q "$PLIST_NAME"; then
            ok "Service:   loaded (launchd)"
        else
            fail "Service:   not loaded"
        fi
    else
        if systemctl --user is-active "$SYSTEMD_UNIT" &>/dev/null; then
            ok "Service:   active (systemd)"
        else
            fail "Service:   inactive"
        fi
    fi

    # Proxy health
    if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
        ok "Proxy:     healthy (${PROXY_URL})"
    else
        fail "Proxy:     unreachable (${PROXY_URL})"
    fi

    # Redis
    if redis-cli ping &>/dev/null 2>&1; then
        ok "Redis:     connected"
    elif docker exec agentveil-redis redis-cli ping &>/dev/null 2>&1; then
        ok "Redis:     connected (Docker)"
    else
        fail "Redis:     unreachable"
    fi

    # Config
    if [[ -f "$ENV_FILE" ]]; then
        ok "Config:    ${ENV_FILE}"
    else
        warn "Config:    missing"
    fi

    if [[ -f "$ROUTER_YAML" ]]; then
        ok "Router:    ${ROUTER_YAML}"
    else
        warn "Router:    missing"
    fi

    # Shell env
    local profile
    profile="$(detect_shell_profile)"
    if grep -qF "$MARKER_START" "$profile" 2>/dev/null; then
        ok "Shell:     configured (${profile})"
    else
        warn "Shell:     not configured"
    fi

    # Current env
    echo ""
    echo "  Current session:"
    echo "    ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL:-<not set>}"
    echo "    OPENAI_BASE_URL=${OPENAI_BASE_URL:-<not set>}"
    echo ""

    # Recent logs
    if [[ -f "${LOG_DIR}/proxy.log" ]]; then
        echo "  Recent logs:"
        tail -5 "${LOG_DIR}/proxy.log" 2>/dev/null | sed 's/^/    /'
        echo ""
    fi
}

# ─── Uninstall ────────────────────────────────────────────────────
do_uninstall() {
    info "Uninstalling Agent Veil..."

    # Stop service
    if is_macos; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        rm -f "$PLIST_PATH"
        ok "Removed launchd service"
    else
        systemctl --user disable --now "$SYSTEMD_UNIT" 2>/dev/null || true
        rm -f "${SYSTEMD_DIR}/${SYSTEMD_UNIT}"
        systemctl --user daemon-reload 2>/dev/null || true
        ok "Removed systemd service"
    fi

    # Stop Redis container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^agentveil-redis$'; then
        docker stop agentveil-redis >/dev/null 2>&1 || true
        docker rm agentveil-redis >/dev/null 2>&1 || true
        ok "Removed Redis container"
    fi

    # Remove shell env block
    local profile
    profile="$(detect_shell_profile)"
    if [[ -f "$profile" ]] && grep -qF "$MARKER_START" "$profile"; then
        if is_macos; then
            sed -i '' "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        else
            sed -i "/${MARKER_START}/,/${MARKER_END}/d" "$profile"
        fi
        ok "Removed env vars from ${profile}"
    fi

    # Remove install dir
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        ok "Removed ${INSTALL_DIR}"
    fi

    echo ""
    echo -e "${GREEN}Agent Veil uninstalled.${NC}"
    echo "  Restart your shell or run: source ${profile}"
}

# ─── Rebuild (quick update) ──────────────────────────────────────
do_rebuild() {
    step "Rebuilding and restarting..."
    build_binary
    do_restart
}

# ─── Main ─────────────────────────────────────────────────────────
main() {
    case "${1:-}" in
        --stop)
            do_stop ;;
        --start)
            do_start ;;
        --restart)
            do_restart ;;
        --rebuild)
            do_rebuild ;;
        --logs|-l)
            do_logs ;;
        --status|-s)
            do_status ;;
        --uninstall|-u)
            do_uninstall ;;
        --help|-h)
            echo -e "${BOLD}Agent Veil Setup${NC}"
            echo ""
            echo "Usage: ./setup.sh [command]"
            echo ""
            echo "Commands:"
            echo "  (none)         Full install: build, configure, start service"
            echo "  --stop         Stop the proxy service"
            echo "  --start        Start the proxy service"
            echo "  --restart      Rebuild + restart (use after code changes)"
            echo "  --rebuild      Same as --restart"
            echo "  --logs, -l     Tail proxy logs"
            echo "  --status, -s   Check status of all components"
            echo "  --uninstall    Remove everything"
            echo "  --help         Show this help"
            echo ""
            echo "Install directory: ${INSTALL_DIR}/"
            echo ""
            ;;
        "")
            echo ""
            echo -e "${BLUE}${BOLD}=== Agent Veil — Native Setup ===${NC}"
            echo ""
            preflight
            build_binary
            install_config
            start_redis
            install_service
            wait_for_health
            inject_shell_env
            print_success
            ;;
        *)
            fail "Unknown command: $1"
            echo "Run ./setup.sh --help"
            exit 1
            ;;
    esac
}

main "$@"
