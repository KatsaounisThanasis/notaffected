"""Fetches structured vulnerability advisories from OSV.dev with local caching."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "notaffected" / "osv"
_SAFE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
_OSV_MISS_CACHE: set[str] = set()


def fetch_osv_advisory(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 8,
    offline: bool = False,
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

    if offline or (cache_dir is None and norm_id in _OSV_MISS_CACHE):
        return None

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
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and cache_dir is None:
            _OSV_MISS_CACHE.add(norm_id)
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    return None


def fetch_ubuntu_osv_advisory(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 8,
    offline: bool = False,
) -> dict[str, Any] | None:
    """Fetch Ubuntu-specific OSV record (`UBUNTU-CVE-...`) for `cve_id`."""
    norm_id = cve_id.strip().upper()
    if norm_id.startswith("CVE-"):
        ubuntu_id = f"UBUNTU-{norm_id}"
    elif norm_id.startswith("UBUNTU-CVE-"):
        ubuntu_id = norm_id
    else:
        return None
    return fetch_osv_advisory(ubuntu_id, cache_dir=cache_dir, timeout=timeout, offline=offline)


def fetch_mitre_cve_as_osv(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 8,
    offline: bool = False,
) -> dict[str, Any] | None:
    """Fetch official MITRE CVE v5 record (`cveawg.mitre.org`) and normalize to OSV shape."""
    norm_id = cve_id.strip().upper()
    if not norm_id.startswith("CVE-") or not _SAFE_ID_RE.fullmatch(norm_id) or ".." in norm_id:
        return None
    cdir = cache_dir or DEFAULT_CACHE_DIR
    cache_file = cdir / f"MITRE-{norm_id}.json"

    if cache_file.is_file():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and (
                offline
                or "mitre_affected" in (cached.get("database_specific") or {})
            ):
                return cached
        except Exception:
            pass

    if offline:
        return None

    url = f"https://cveawg.mitre.org/api/cve/{norm_id}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.load(resp)
        if not isinstance(raw, dict):
            return None
        cna = (raw.get("containers") or {}).get("cna") or {}
        title = str(cna.get("title") or "").strip()
        descs = cna.get("descriptions") or []
        eng_desc = ""
        for d in descs:
            if isinstance(d, dict) and d.get("value"):
                eng_desc = str(d["value"]).strip()
                if str(d.get("lang") or "").startswith("en"):
                    break
        severity = "HIGH"
        for m in cna.get("metrics") or []:
            if not isinstance(m, dict):
                continue
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if isinstance(m.get(k), dict) and m[k].get("baseSeverity"):
                    severity = str(m[k]["baseSeverity"]).upper()
                    break
        refs = [
            {"type": "ADVISORY", "url": str(r.get("url"))}
            for r in (cna.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]
        mitre_affected = [
            a for a in (cna.get("affected") or []) if isinstance(a, dict)
        ]
        normalized: dict[str, Any] = {
            "id": norm_id,
            "summary": title or eng_desc[:160] or norm_id,
            "details": eng_desc or title,
            "affected": [],
            "references": refs,
            "database_specific": {
                "severity": severity,
                "mitre_affected": mitre_affected,
            },
        }
        try:
            cdir.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        except OSError:
            pass
        return normalized
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None



def fetch_advisories_concurrent(
    cve_ids: list[str],
    cache_dir: Path | None = None,
    max_workers: int = 8,
    timeout: int = 8,
) -> dict[str, dict[str, Any]]:
    """Fetch multiple CVE OSV records concurrently using a thread pool."""
    unique_ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c.strip()))
    if not unique_ids:
        return {}

    results: dict[str, dict[str, Any]] = {}
    workers = min(max_workers, len(unique_ids))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_id = {
            pool.submit(fetch_osv_advisory, cid, cache_dir, timeout): cid
            for cid in unique_ids
        }
        for fut in concurrent.futures.as_completed(future_to_id):
            cid = future_to_id[fut]
            try:
                data = fut.result()
                if isinstance(data, dict):
                    results[cid] = data
            except Exception:
                continue
    return results


def strip_html_to_text(raw_html: str) -> str:
    """Strip <script>, <style>, and HTML tags into compact plain text."""
    no_scripts = re.sub(
        r"<(script|style)[^>]*>.*?</\1>",
        " ",
        raw_html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    no_tags = re.sub(r"<[^>]+>", " ", no_scripts)
    return re.sub(r"\s+", " ", no_tags).strip()


def _is_safe_public_https_url(url: str) -> bool:
    """Ensure reference URL uses https:// and does not point to localhost or private IPs."""
    if not url.startswith("https://"):
        return False
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host or host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        pass
    return True


def fetch_reference_snippets(
    osv_data: dict[str, Any],
    max_urls: int = 2,
    timeout: int = 4,
) -> str:
    """Follow up to `max_urls` advisory/fix reference links to gather technical details."""
    refs = osv_data.get("references") or []
    candidate_urls: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not _is_safe_public_https_url(url):
            continue
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host == "msrc.microsoft.com":
            continue
        ref_type = str(ref.get("type") or "").upper()
        if ref_type in ("ADVISORY", "FIX", "ARTICLE", "REPORT") or any(
            host == dom or host.endswith(f".{dom}")
            for dom in ("github.com", "kernel.org", "openwall.com", "debian.org", "redhat.com")
        ):
            candidate_urls.append(url)

    snippets: list[str] = []
    for url in candidate_urls[:max_urls]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "notaffected/0.3 (+https://openvex.dev)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(65536)
            text = raw_bytes.decode("utf-8", errors="ignore")
            cleaned = strip_html_to_text(text)
            if cleaned:
                snippets.append(f"[Reference {url}]: {cleaned[:1500]}")
        except Exception:
            continue
    return "\n".join(snippets)



