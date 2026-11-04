"""Fetches structured vulnerability advisories from OSV.dev with local caching."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "notaffected" / "osv"
_SAFE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")


def fetch_osv_advisory(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 8,
) -> dict[str, Any] | None:
    """Fetch OSV JSON record for `cve_id` from cache or `https://api.osv.dev/v1/vulns/<id>`."""
    norm_id = cve_id.strip().upper()
    if not _SAFE_ID_RE.fullmatch(norm_id) or ".." in norm_id:
        return None
    cdir = cache_dir or DEFAULT_CACHE_DIR
    cache_file = cdir / f"{norm_id}.json"

    if cache_file.is_file():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    url = f"https://api.osv.dev/v1/vulns/{norm_id}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
        if isinstance(data, dict):
            try:
                cdir.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except OSError:
                pass
            return data
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    return None
