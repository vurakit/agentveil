"""
Vura PrivacyGuard LangChain Integration

Usage:
    from vura_langchain import VuraCallbackHandler, VuraChatModel

    # Option 1: Callback handler (works with any LLM)
    handler = VuraCallbackHandler(proxy_url="http://localhost:8080")
    llm = ChatOpenAI(callbacks=[handler])

    # Option 2: Drop-in ChatModel replacement
    llm = VuraChatModel(proxy_url="http://localhost:8080", model="gpt-4")
    result = llm.invoke("Hello, my CCCD is 012345678901")
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterator, List, Optional

import requests


class VuraCallbackHandler:
    """LangChain callback handler that scans PII before/after LLM calls."""

    def __init__(
        self,
        proxy_url: str | None = None,
        api_key: str | None = None,
        session_id: str | None = None,
        block_on_pii: bool = False,
    ):
        self.proxy_url = proxy_url or os.getenv("VURA_PROXY_URL", "http://localhost:8080")
        self.api_key = api_key or os.getenv("VURA_API_KEY", "")
        self.session_id = session_id or os.getenv("VURA_SESSION_ID", "langchain")
        self.block_on_pii = block_on_pii
        self._findings: list[dict] = []

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """Scan prompts for PII before sending to LLM."""
        for prompt in prompts:
            result = self._scan(prompt)
            if result and result.get("found"):
                self._findings.extend(result.get("entities", []))
                if self.block_on_pii:
                    raise PIIDetectedError(
                        f"PII detected in prompt: {len(result['entities'])} entities found"
                    )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Scan LLM output for PII leakage."""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    result = self._scan(gen.text)
                    if result and result.get("found"):
                        self._findings.extend(result.get("entities", []))

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        pass

    def get_findings(self) -> list[dict]:
        """Return all PII findings from this session."""
        return self._findings

    def clear_findings(self) -> None:
        self._findings = []

    def _scan(self, text: str) -> dict | None:
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            if self.session_id:
                headers["X-Session-ID"] = self.session_id

            resp = requests.post(
                f"{self.proxy_url}/scan",
                json={"text": text},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass
        return None


class VuraChatModel:
    """
    Drop-in LLM replacement that routes through Vura proxy.

    Compatible with LangChain's BaseChatModel interface pattern.
    """

    def __init__(
        self,
        proxy_url: str | None = None,
        api_key: str | None = None,
        provider_api_key: str | None = None,
        model: str = "gpt-4",
        provider: str | None = None,
        session_id: str | None = None,
        role: str = "admin",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        self.proxy_url = proxy_url or os.getenv("VURA_PROXY_URL", "http://localhost:8080")
        self.api_key = api_key or os.getenv("VURA_API_KEY", "")
        self.provider_api_key = provider_api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model
        self.provider = provider
        self.session_id = session_id or os.getenv("VURA_SESSION_ID", "langchain")
        self.role = role
        self.temperature = temperature
        self.max_tokens = max_tokens

    def invoke(self, input_text: str, **kwargs: Any) -> str:
        """Send a single message and get response."""
        messages = [{"role": "user", "content": input_text}]
        return self._chat(messages, **kwargs)

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        """Send messages and get response."""
        return self._chat(messages, **kwargs)

    def stream(self, input_text: str, **kwargs: Any) -> Iterator[str]:
        """Stream response chunks."""
        messages = [{"role": "user", "content": input_text}]
        return self._stream(messages, **kwargs)

    def _chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        headers = self._build_headers()
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        resp = requests.post(
            f"{self.proxy_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()

        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        return ""

    def _stream(self, messages: list[dict[str, str]], **kwargs: Any) -> Iterator[str]:
        headers = self._build_headers()
        headers["Accept"] = "text/event-stream"
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "stream": True,
        }

        resp = requests.post(
            f"{self.proxy_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            stream=True,
            timeout=120,
        )
        resp.raise_for_status()

        for line in resp.iter_lines(decode_unicode=True):
            if line and line.startswith("data: "):
                data = line[6:].strip()
                if data == "[DONE]":
                    return
                try:
                    chunk = json.loads(data)
                    if "choices" in chunk and len(chunk["choices"]) > 0:
                        delta = chunk["choices"][0].get("delta", {})
                        if "content" in delta:
                            yield delta["content"]
                except json.JSONDecodeError:
                    continue

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.provider_api_key:
            headers["Authorization"] = f"Bearer {self.provider_api_key}"

        if self.session_id:
            headers["X-Session-ID"] = self.session_id
        if self.role:
            headers["X-User-Role"] = self.role
        if self.provider:
            headers["X-Vura-Provider"] = self.provider

        return headers


class VuraAuditor:
    """Audit skill.md files via Vura API."""

    def __init__(
        self,
        proxy_url: str | None = None,
        api_key: str | None = None,
    ):
        self.proxy_url = proxy_url or os.getenv("VURA_PROXY_URL", "http://localhost:8080")
        self.api_key = api_key or os.getenv("VURA_API_KEY", "")

    def audit(self, content: str) -> dict:
        """Audit skill.md content and return compliance report."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        resp = requests.post(
            f"{self.proxy_url}/audit",
            json={"content": content},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def audit_file(self, path: str) -> dict:
        """Audit a skill.md file from disk."""
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return self.audit(content)


class PIIDetectedError(Exception):
    """Raised when PII is detected and block_on_pii is enabled."""
    pass
