"""The single place notaffected talks to an LLM — to extract schema-validated
precondition candidates from advisory prose or generate post-verdict remediation
briefings.

The model NEVER evaluates host state, NEVER decides verdicts, and NEVER executes
commands. Every returned precondition candidate is validated against PROBE_TYPES.

There is no default provider and no default model: with nothing configured the tool is
deterministic only. The user picks both (`NOTAFFECTED_LLM_PROVIDER`, `NOTAFFECTED_LLM_URL` or a
provider key, and `NOTAFFECTED_LLM_MODEL`), so any model, local or hosted, can be used:
- Google Gemini API (`GEMINI_API_KEY` or `GOOGLE_API_KEY`)
- Anthropic API (`ANTHROPIC_API_KEY`)
- OpenAI (`OPENAI_API_KEY`, sent to api.openai.com only) or any OpenAI-compatible
  `/v1/chat/completions` server (`NOTAFFECTED_LLM_URL`, plus `NOTAFFECTED_LLM_API_KEY` if needed)
- Ollama (`/api/generate` at `NOTAFFECTED_LLM_URL`, or `http://localhost:11434` when chosen explicitly)
- The `claude` and `agy` CLIs (their own default model unless `NOTAFFECTED_LLM_MODEL` is set)

`NOTAFFECTED_OLLAMA_URL` is a legacy alias of `NOTAFFECTED_LLM_URL`. A key alone picks the
provider only when keys for exactly one provider are present; otherwise
`NOTAFFECTED_LLM_PROVIDER` must choose.

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


PROVIDERS: tuple[str, ...] = ("ollama", "openai", "anthropic", "gemini", "claude-cli", "agy-cli")
# CLI providers fall back to the CLI's own configured default model; HTTP providers need one set.
_CLI_PROVIDERS: frozenset[str] = frozenset({"claude-cli", "agy-cli"})


_OPENAI_HOSTED_URL = "https://api.openai.com/v1/chat/completions"
_OLLAMA_DEFAULT_URL = "http://localhost:11434/api/generate"


def _llm_url() -> str:
    """The endpoint the user pointed at ('' if none). NOTAFFECTED_OLLAMA_URL is a legacy alias."""
    return (os.environ.get("NOTAFFECTED_LLM_URL") or os.environ.get("NOTAFFECTED_OLLAMA_URL") or "").strip()


def _endpoint(provider: str) -> str:
    """Where an openai/ollama request goes: the user's URL, else that provider's own default."""
    return _llm_url() or (_OPENAI_HOSTED_URL if provider == "openai" else _OLLAMA_DEFAULT_URL)


def _is_openai_host(url: str) -> bool:
    return (urllib.parse.urlparse(url).hostname or "").lower() == "api.openai.com"


def _openai_key(url: str) -> str:
    """NOTAFFECTED_LLM_API_KEY goes to the endpoint the user chose; OPENAI_API_KEY, often set in
    the shell for other tools, only ever goes to OpenAI itself."""
    key = os.environ.get("NOTAFFECTED_LLM_API_KEY") or ""
    if not key and _is_openai_host(url):
        key = os.environ.get("OPENAI_API_KEY") or ""
    return key


def _key_families() -> list[str]:
    """Hosted providers whose API key is present in the environment."""
    families: list[str] = []
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        families.append("gemini")
    if os.environ.get("ANTHROPIC_API_KEY"):
        families.append("anthropic")
    if os.environ.get("NOTAFFECTED_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        families.append("openai")
    return families


def detect_provider() -> str | None:
    """The configured LLM provider, or None when none is configured.

    None is the default: no provider is assumed, so nothing is contacted (and no data leaves
    the machine) until the user configures one. An unknown NOTAFFECTED_LLM_PROVIDER, or keys
    for several providers with no NOTAFFECTED_LLM_PROVIDER to choose, also give None: the
    destination is never a guess.
    """
    explicit = (os.environ.get("NOTAFFECTED_LLM_PROVIDER") or "").strip().lower()
    if explicit:
        return explicit if explicit in PROVIDERS else None

    custom_url = _llm_url()
    if custom_url:
        return "openai" if _is_openai_compatible(custom_url) else "ollama"

    families = _key_families()
    return families[0] if len(families) == 1 else None


def _unconfigured_reason() -> str:
    explicit = (os.environ.get("NOTAFFECTED_LLM_PROVIDER") or "").strip().lower()
    if explicit:
        return f"unknown NOTAFFECTED_LLM_PROVIDER '{explicit}' (one of: {', '.join(PROVIDERS)})"
    families = _key_families()
    if len(families) > 1:
        return (
            f"API keys for several providers are set ({', '.join(families)}); "
            "set NOTAFFECTED_LLM_PROVIDER to choose one"
        )
    return "No AI provider configured; analysis is deterministic only."


def resolve_model(provider: str | None, model: str | None = None) -> str | None:
    """The model the user chose (argument or NOTAFFECTED_LLM_MODEL); never a built-in default."""
    if provider is None:
        return None
    chosen = (model or os.environ.get("NOTAFFECTED_LLM_MODEL") or "").strip()
    return chosen or None


def _config_gap(provider: str, model: str | None) -> str:
    """Why an HTTP provider cannot be used yet ('' when it can). Nothing is sent while a gap
    remains, so a provider set without its key never ships a prompt that is bound to fail."""
    if model is None:
        return "NOTAFFECTED_LLM_MODEL is not set"
    if provider in ("openai", "ollama"):
        url = _endpoint(provider)
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            return "NOTAFFECTED_LLM_URL must start with http:// or https://"
        if provider == "openai" and _is_openai_host(url) and not _openai_key(url):
            return "OPENAI_API_KEY or NOTAFFECTED_LLM_API_KEY is not set"
    if provider == "gemini" and not (
        os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    ):
        return "GEMINI_API_KEY or GOOGLE_API_KEY is not set"
    if provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        return "ANTHROPIC_API_KEY is not set"
    return ""


def llm_configured() -> bool:
    """True when generate() would contact a model. Reads the environment only, no network."""
    provider = detect_provider()
    if provider is None:
        return False
    return provider in _CLI_PROVIDERS or not _config_gap(provider, resolve_model(provider))


def _run_claude_cli(prompt: str, model: str | None = None, timeout: int = 60) -> str:
    # `model` is already resolved by generate(); None means the CLI's own default.
    cmd = ["claude", "-p", *_CLAUDE_BARE_FLAGS]
    if model:
        cmd.extend(["--model", model])
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
    # `model` is already resolved by generate(); None means the CLI's own default.
    cmd = [
        "agy",
        "-p",
        prompt,
        # Untrusted advisory text goes into the prompt: no permission bypass, sandboxed.
        "--sandbox",
        "--print-timeout",
        f"{max(1, timeout // 60)}m",
    ]
    if model:
        cmd.extend(["--model", model])
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
    chosen_model = resolve_model(provider, model) or ""
    headers: dict[str, str] = {"Content-Type": "application/json"}

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        raw_model = chosen_model.removeprefix("models/")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{urllib.parse.quote(raw_model, safe='-_.')}:generateContent"
        )
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
        url = _endpoint("openai")
        api_key = _openai_key(url)
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

    # ollama; the context size is the model's (or the user's Ollama setting), not ours
    url = _endpoint("ollama")
    cpu_threads = max(4, min(10, (os.cpu_count() or 8) - 4))
    body = {
        "model": chosen_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": max_tokens,
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
    if provider is None:
        return ""  # no provider configured: deterministic only
    chosen_model = resolve_model(provider, model)
    if provider == "claude-cli":
        # No silent switch to another provider: a failure falls back to deterministic output.
        return _run_claude_cli(prompt, model=chosen_model, timeout=timeout)
    if provider == "agy-cli":
        return _run_agy_cli(prompt, model=chosen_model, timeout=timeout)
    if _config_gap(provider, chosen_model):
        return ""  # no built-in default model, and no keyless call to a hosted API

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


def _is_loopback_url(url: str) -> bool:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1")


def get_ai_status(timeout: float = 0.6) -> dict[str, Any]:
    """What the AI advisor would use right now, without spawning any daemon.

    `configured` is exactly "generate() would send": False when no provider is set (or the
    setting is unknown or ambiguous), a provider needs a model that is not set, or a hosted
    provider has no key. `online` is True/False only where it is actually checked (Ollama
    answers, CLI on PATH); elsewhere it is None: configured, but nothing was sent to check.
    """
    provider = detect_provider()
    model = resolve_model(provider)
    base: dict[str, Any] = {"provider": provider, "model": model, "online": None, "local_only": False}
    if provider is None:
        return {**base, "configured": False, "local_only": True, "detail": _unconfigured_reason()}

    if provider in _CLI_PROVIDERS:
        binary = "claude" if provider == "claude-cli" else "agy"
        on_path = bool(shutil.which(binary))
        return {
            **base,
            "configured": True,
            "model": model or "CLI default",
            "online": on_path,
            "detail": "" if on_path else f"'{binary}' is not on PATH",
        }

    gap = _config_gap(provider, model)
    if gap:
        return {**base, "configured": False, "detail": gap}

    if provider == "ollama":
        base_url = _endpoint("ollama")
        parsed = urllib.parse.urlparse(base_url)
        tags_url = f"{parsed.scheme}://{parsed.netloc}/api/tags"
        host_port = parsed.netloc.rpartition("@")[2]  # never echo credentials from the URL
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
            **base,
            "configured": True,
            "online": online,
            "local_only": _is_loopback_url(base_url),
            "available_models": available_models,
            "detail": "" if online else f"no answer from {host_port}",
        }

    if provider == "openai":
        url = _endpoint("openai")
        return {**base, "configured": True, "local_only": _is_loopback_url(url), "detail": ""}

    # gemini / anthropic: a key is present; nothing was sent to check it
    return {**base, "configured": True, "detail": ""}
