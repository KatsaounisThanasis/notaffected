"""The single place notaffected talks to an LLM — to extract schema-validated
precondition candidates from advisory prose or generate post-verdict remediation
briefings.

The model NEVER evaluates host state, NEVER decides verdicts, and NEVER executes
commands. Every returned precondition candidate is validated against PROBE_TYPES.

Supports (auto-detected or via NOTAFFECTED_LLM_PROVIDER):
- Google Gemini API (`GEMINI_API_KEY` or `GOOGLE_API_KEY`, default `gemini-2.5-flash`)
- Anthropic Claude API (`ANTHROPIC_API_KEY`, default `claude-3-5-sonnet-latest`)
- OpenAI-compatible `/v1/chat/completions` (`NOTAFFECTED_LLM_API_KEY` or `OPENAI_API_KEY`)
- Local Ollama (`/api/generate`, default `http://localhost:11434/api/generate`)

Every failure returns `{}` / `""` instead of raising: "no model" is a normal state.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from typing import Any

_CLAUDE_BARE_FLAGS = [
    "--bare",
    "--strict-mcp-config",
    "--tools",
    "",
    "--no-session-persistence",
]


def _is_openai_compatible(url: str) -> bool:
    path = urllib.parse.urlparse(url).path
    return "/v1/" in path or path.rstrip("/").endswith("chat/completions")


def detect_provider() -> str:
    """Detect which LLM provider to use.
    Defaults strictly to local 'ollama' (127.0.0.1:11434) so zero data leaves the
    machine unless an external provider or API key is explicitly configured.
    """
    explicit = (os.environ.get("NOTAFFECTED_LLM_PROVIDER") or "").strip().lower()
    if explicit in ("ollama", "claude-cli", "agy-cli", "gemini", "anthropic", "openai"):
        return explicit

    custom_url = os.environ.get("NOTAFFECTED_LLM_URL") or os.environ.get("NOTAFFECTED_OLLAMA_URL")
    if custom_url:
        return "openai" if _is_openai_compatible(custom_url) else "ollama"

    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("NOTAFFECTED_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "ollama"


def _run_claude_cli(prompt: str, model: str | None = None, timeout: int = 60) -> str:
    chosen_model = model or os.environ.get("NOTAFFECTED_LLM_MODEL")
    cmd = ["claude", "-p", *_CLAUDE_BARE_FLAGS]
    if chosen_model:
        cmd.extend(["--model", chosen_model])
    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _run_agy_cli(prompt: str, model: str | None = None, timeout: int = 60) -> str:
    chosen_model = (
        model
        or os.environ.get("NOTAFFECTED_LLM_MODEL")
        or "Gemini 3.8 Flash (Medium)"
    )
    cmd = [
        "agy",
        "-p",
        prompt,
        # Untrusted advisory text goes into the prompt: no permission bypass, sandboxed.
        "--sandbox",
        "--print-timeout",
        f"{max(1, timeout // 60)}m",
        "--model",
        chosen_model,
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout + 15,
            shell=False,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _build_http_request(
    provider: str,
    prompt: str,
    model: str | None,
    json_format: bool,
    max_tokens: int = 240,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    env_model = os.environ.get("NOTAFFECTED_LLM_MODEL")
    headers: dict[str, str] = {"Content-Type": "application/json"}

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        raw_model = (model or env_model or "gemini-2.5-flash").strip().removeprefix("models/")
        chosen_model = urllib.parse.quote(raw_model, safe="-_.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{chosen_model}:generateContent"
        headers["x-goog-api-key"] = api_key
        gen_cfg: dict[str, Any] = {"temperature": 0}
        if json_format:
            gen_cfg["responseMimeType"] = "application/json"
        body: dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": gen_cfg,
        }
        return url, headers, body

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY") or ""
        chosen_model = model or env_model or "claude-3-5-sonnet-latest"
        url = "https://api.anthropic.com/v1/messages"
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
        body = {
            "model": chosen_model,
            "max_tokens": 1024,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        }
        return url, headers, body

    if provider == "openai":
        url = (
            os.environ.get("NOTAFFECTED_LLM_URL")
            or "https://api.openai.com/v1/chat/completions"
        )
        chosen_model = model or env_model or "gpt-4o-mini"
        api_key = os.environ.get("NOTAFFECTED_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        body = {
            "model": chosen_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "stream": False,
        }
        if json_format:
            body["response_format"] = {"type": "json_object"}
        return url, headers, body

    # Default: ollama
    url = (
        os.environ.get("NOTAFFECTED_LLM_URL")
        or os.environ.get("NOTAFFECTED_OLLAMA_URL")
        or "http://localhost:11434/api/generate"
    )
    chosen_model = model or env_model or "qwen2.5-coder:1.5b"
    cpu_threads = max(4, min(10, (os.cpu_count() or 8) - 4))
    body = {
        "model": chosen_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": max_tokens,
            "num_ctx": 1024,
            "num_thread": cpu_threads,
        },
    }
    if json_format:
        body["format"] = "json"
    return url, headers, body


def _extract_response_text(provider: str, resp: dict[str, Any]) -> str:
    if provider == "gemini":
        candidates = resp.get("candidates") or []
        if not candidates:
            return ""
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return "".join(str(p.get("text") or "") for p in parts if isinstance(p, dict))

    if provider == "anthropic":
        content = resp.get("content") or []
        return "".join(
            str(block.get("text") or "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )

    if provider == "openai":
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
    max_tokens: int = 240,
) -> str:
    """Query the configured/detected model once. Returns response text or '' on any failure."""
    provider = detect_provider()
    if provider == "claude-cli":
        # No silent switch to another provider: a failure falls back to deterministic output.
        return _run_claude_cli(prompt, model=model, timeout=timeout)
    if provider == "agy-cli":
        return _run_agy_cli(prompt, model=model, timeout=timeout)

    url, headers, body = _build_http_request(
        provider, prompt, model, json_format, max_tokens=max_tokens
    )
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        return ""
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp_handle:
            resp = json.load(resp_handle)
        return _extract_response_text(provider, resp)
    except Exception:
        return ""


def generate_json(
    prompt: str,
    model: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """generate() plus strict JSON dict parsing. Returns {} on any error."""
    try:
        raw = generate(prompt, model=model, timeout=timeout, json_format=True, max_tokens=320)
        cleaned = raw.strip()
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif not cleaned.startswith("{"):
            brace_start = cleaned.find("{")
            brace_end = cleaned.rfind("}")
            if brace_start != -1 and brace_end > brace_start:
                cleaned = cleaned[brace_start : brace_end + 1]
        parsed = json.loads(cleaned)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def get_ai_status(timeout: float = 0.6) -> dict[str, Any]:
    """Return lightweight status of the active AI provider without spawning any daemon."""
    provider = detect_provider()
    env_model = (os.environ.get("NOTAFFECTED_LLM_MODEL") or "").strip()
    if provider == "ollama":
        chosen = env_model or "qwen2.5-coder:1.5b"
        base_url = (
            os.environ.get("NOTAFFECTED_LLM_URL")
            or os.environ.get("NOTAFFECTED_OLLAMA_URL")
            or "http://127.0.0.1:11434/api/generate"
        )
        parsed = urllib.parse.urlparse(base_url)
        ollama_host = (parsed.hostname or "127.0.0.1").lower()
        is_local = ollama_host in ("127.0.0.1", "localhost", "::1")
        tags_url = f"{parsed.scheme or 'http'}://{parsed.netloc or '127.0.0.1:11434'}/api/tags"
        online = False
        available_models: list[str] = []
        try:
            with urllib.request.urlopen(tags_url, timeout=timeout) as resp:
                data = json.load(resp)
            if isinstance(data, dict) and isinstance(data.get("models"), list):
                online = True
                available_models = [
                    str(m.get("name")) for m in data["models"] if isinstance(m, dict) and m.get("name")
                ]
        except Exception:
            online = False
        return {
            "provider": "ollama",
            "model": chosen,
            "online": online,
            "local_only": is_local,
            "available_models": available_models,
        }
    if provider == "claude-cli":
        return {
            "provider": "claude-cli",
            "model": env_model or "claude-default",
            "online": bool(shutil.which("claude")),
            "local_only": False,
        }
    if provider == "agy-cli":
        return {
            "provider": "agy-cli",
            "model": env_model or "Gemini 3.8 Flash (Medium)",
            "online": bool(shutil.which("agy")),
            "local_only": False,
        }
    return {
        "provider": provider,
        "model": env_model or "default",
        "online": True,
        "local_only": False,
    }
