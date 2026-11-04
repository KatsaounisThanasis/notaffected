"""The single place notaffected talks to an LLM — and only to extract structured
precondition candidates from advisory prose.

The model NEVER evaluates host state, NEVER decides verdicts, and NEVER produces
shell commands. Every returned candidate is validated against PROBE_TYPES.

Supports:
- Local Ollama (`/api/generate`, default `http://localhost:11434/api/generate`)
- Any OpenAI-compatible `/v1/chat/completions` endpoint (LM Studio, vLLM,
  llama.cpp, or OpenAI when NOTAFFECTED_LLM_URL / OPENAI_API_KEY is configured).

Every failure returns `{}` instead of raising: "no model" is a normal state.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

LLM_URL = (
    os.environ.get("NOTAFFECTED_LLM_URL")
    or os.environ.get("NOTAFFECTED_OLLAMA_URL")
    or "http://localhost:11434/api/generate"
)
DEFAULT_MODEL = os.environ.get("NOTAFFECTED_LLM_MODEL", "qwen2.5-coder:3b")


def _is_openai_compatible(url: str) -> bool:
    path = urllib.parse.urlparse(url).path
    return "/v1/" in path or path.rstrip("/").endswith("chat/completions")


def _request_body(prompt: str, model: str | None, json_format: bool) -> dict[str, Any]:
    if _is_openai_compatible(LLM_URL):
        body: dict[str, Any] = {
            "model": model or DEFAULT_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "stream": False,
        }
        if json_format:
            body["response_format"] = {"type": "json_object"}
        return body

    body = {
        "model": model or DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }
    if json_format:
        body["format"] = "json"
    return body


def _response_text(resp: dict[str, Any]) -> str:
    if _is_openai_compatible(LLM_URL):
        choices = resp.get("choices") or []
        if not choices:
            return ""
        return str((choices[0].get("message") or {}).get("content", "") or "")
    return str(resp.get("response", "") or "")


def generate(
    prompt: str,
    model: str | None = None,
    timeout: int = 60,
    json_format: bool = True,
) -> str:
    """Query the configured model once. Returns response text or '' on any failure."""
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("NOTAFFECTED_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        req = urllib.request.Request(
            LLM_URL,
            data=json.dumps(_request_body(prompt, model, json_format)).encode("utf-8"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp_handle:
            resp = json.load(resp_handle)
        return _response_text(resp)
    except Exception:
        return ""


def generate_json(
    prompt: str,
    model: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """generate() plus strict JSON dict parsing. Returns {} on any error."""
    try:
        raw = generate(prompt, model=model, timeout=timeout, json_format=True)
        parsed = json.loads(raw)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}
