#!/bin/bash
# ============================================================
# Script triển khai PrivacyGuard cho khách hàng
# Chạy: chmod +x deploy.sh && ./deploy.sh
# ============================================================

set -e

echo "=== PrivacyGuard PaaS - Deployment ==="

# 1. Cấu hình (khách hàng sửa các biến này)
export TARGET_URL="${TARGET_URL:-https://api.openai.com}"
export LISTEN_ADDR="${LISTEN_ADDR:-:8080}"
export REDIS_ADDR="${REDIS_ADDR:-localhost:6379}"

echo "→ Target LLM:  $TARGET_URL"
echo "→ Listen:       $LISTEN_ADDR"
echo "→ Redis:        $REDIS_ADDR"

# 2. Khởi chạy bằng Docker Compose
echo ""
echo "=== Starting services ==="
docker compose up -d --build

echo ""
echo "=== Health check ==="
sleep 3
curl -sf http://localhost:8080/health && echo " ✓ Proxy is running" || echo " ✗ Proxy failed to start"

echo ""
echo "=== Done! ==="
echo "Proxy is live at http://localhost:8080"
echo ""
echo "Cách sử dụng:"
echo "  1. Set base_url='http://localhost:8080/v1' trong OpenAI client"
echo "  2. Thêm header X-User-Role: admin|viewer"
echo "  3. (Tùy chọn) Thêm header X-Session-ID cho session tracking"
