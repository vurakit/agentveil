"""
Agent Veil SDK for Python.

Cách 1 - Tự động (monkey-patch OpenAI):
    import agentveil
    agentveil.activate(proxy_url="http://localhost:8080", role="admin")

Cách 2 - OpenAI client với base_url:
    from openai import OpenAI
    client = OpenAI(base_url="http://localhost:8080/v1", api_key="sk-...")

Cách 3 - Wrap bất kỳ HTTP session nào:
    session = agentveil.create_session(proxy_url="...", role="viewer")
    resp = session.post(url, json=payload)
"""

import uuid
import os
from typing import Optional

import requests


_ACTIVE = False
_CONFIG = {}


def activate(
    proxy_url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
    role: str = "admin",
    session_id: Optional[str] = None,
):
    """
    Kích hoạt Agent Veil cho toàn bộ OpenAI calls.
    Chỉ cần gọi 1 lần khi khởi động app.
    """
    global _ACTIVE, _CONFIG

    _CONFIG = {
        "proxy_url": proxy_url.rstrip("/"),
        "api_key": api_key or os.environ.get("OPENAI_API_KEY", ""),
        "role": role,
        "session_id": session_id or str(uuid.uuid4()),
    }
    _ACTIVE = True

    # Set env var so OpenAI SDK picks up the proxy as base_url
    os.environ["OPENAI_BASE_URL"] = f"{_CONFIG['proxy_url']}/v1"

    return _CONFIG


def deactivate():
    """Tắt Agent Veil, khôi phục OpenAI gọi trực tiếp."""
    global _ACTIVE
    _ACTIVE = False
    os.environ.pop("OPENAI_BASE_URL", None)


def is_active() -> bool:
    return _ACTIVE


def create_session(
    proxy_url: str = "http://localhost:8080",
    api_key: Optional[str] = None,
    role: str = "admin",
    session_id: Optional[str] = None,
) -> requests.Session:
    """Tạo requests.Session đã cấu hình headers Agent Veil."""
    session = requests.Session()
    sid = session_id or str(uuid.uuid4())

    session.headers.update({
        "X-Session-ID": sid,
        "X-User-Role": role,
    })

    if api_key:
        session.headers["Authorization"] = f"Bearer {api_key}"

    return session


def audit_skill(proxy_url: str, content: str) -> dict:
    """Gửi nội dung skill.md để kiểm tra bảo mật."""
    resp = requests.post(
        f"{proxy_url.rstrip('/')}/audit",
        json={"content": content},
    )
    return resp.json()
