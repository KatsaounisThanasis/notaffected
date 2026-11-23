"""Fetches structured vulnerability advisories from OSV.dev with local caching."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from notaffected import __version__

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "notaffected" / "osv"
_SAFE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
_OSV_MISS_CACHE: set[str] = set()
_REDHAT_MISS_CACHE: set[str] = set()
_MSRC_MISS_CACHE: set[str] = set()
_MAX_MSRC_BYTES = 20 * 1024 * 1024


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


def fetch_debian_osv_advisory(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 8,
    offline: bool = False,
) -> dict[str, Any] | None:
    """Fetch Debian-specific OSV record (`DEBIAN-CVE-...`) for `cve_id`."""
    norm_id = cve_id.strip().upper()
    if norm_id.startswith("CVE-"):
        debian_id = f"DEBIAN-{norm_id}"
    elif norm_id.startswith("DEBIAN-CVE-"):
        debian_id = norm_id
    else:
        return None
    return fetch_osv_advisory(debian_id, cache_dir=cache_dir, timeout=timeout, offline=offline)


_RH_PKG_VER_RE = re.compile(r"^(.+?)-(\d+:[^-]+-[^-]+)$")
_RH_CPE_MAJOR_RE = re.compile(r"enterprise_linux:(\d+)", re.IGNORECASE)


def fetch_redhat_advisory_as_osv(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 6,
    offline: bool = False,
) -> dict[str, Any] | None:
    """Fetch official Red Hat Security Data API CVE JSON and normalize to OSV shape."""
    norm_id = cve_id.strip().upper()
    if not norm_id.startswith("CVE-") or not _SAFE_ID_RE.fullmatch(norm_id) or ".." in norm_id:
        return None
    cdir = cache_dir or DEFAULT_CACHE_DIR
    cache_file = cdir / f"REDHAT-{norm_id}.json"

    if cache_file.is_file():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(cached, dict):
                return cached
        except Exception:
            pass

    if offline or (cache_dir is None and norm_id in _REDHAT_MISS_CACHE):
        return None

    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{norm_id}.json"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": f"notaffected/{__version__} (+https://openvex.dev)",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.load(resp)
        if not isinstance(raw, dict):
            return None

        affected: list[dict[str, Any]] = []
        seen_rel_pkg: set[tuple[str, str]] = set()
        for rel in raw.get("affected_release") or []:
            if not isinstance(rel, dict):
                continue
            cpe = str(rel.get("cpe") or "")
            pkg_str = str(rel.get("package") or "").strip()
            m_maj = _RH_CPE_MAJOR_RE.search(cpe)
            m_pkg = _RH_PKG_VER_RE.match(pkg_str)
            if not m_maj or not m_pkg:
                continue
            eco = f"Red Hat:{m_maj.group(1)}"
            pkg_name, fixed_ver = m_pkg.group(1).strip(), m_pkg.group(2).strip()
            key = (eco, pkg_name)
            if key in seen_rel_pkg:
                continue
            seen_rel_pkg.add(key)
            affected.append(
                {
                    "package": {"name": pkg_name, "ecosystem": eco},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": fixed_ver}],
                        }
                    ],
                }
            )

        details_list = raw.get("details") or []
        details = "\n".join(str(d).strip() for d in details_list if d).strip()
        sev_map = {
            "critical": "CRITICAL",
            "important": "HIGH",
            "moderate": "MEDIUM",
            "low": "LOW",
        }
        sev = sev_map.get(str(raw.get("threat_severity") or "").strip().lower(), "HIGH")
        refs = [
            {"type": "ADVISORY", "url": f"https://access.redhat.com/security/cve/{norm_id.lower()}"}
        ]
        normalized: dict[str, Any] = {
            "id": norm_id,
            "summary": details[:160] or norm_id,
            "details": details,
            "affected": affected,
            "references": refs,
            "database_specific": {
                "source": "redhat",
                "severity": sev,
                "package_state": raw.get("package_state") or [],
            },
        }
        try:
            cdir.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        except OSError:
            pass
        return normalized
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and cache_dir is None:
            _REDHAT_MISS_CACHE.add(norm_id)
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def fetch_msrc_advisory_as_osv(
    cve_id: str,
    cache_dir: Path | None = None,
    timeout: int = 10,
    offline: bool = False,
) -> dict[str, Any] | None:
    """Fetch official Microsoft MSRC CVRF v3.0 data for `cve_id` and normalize to OSV shape."""
    norm_id = cve_id.strip().upper()
    if not norm_id.startswith("CVE-") or not _SAFE_ID_RE.fullmatch(norm_id) or ".." in norm_id:
        return None
    cdir = cache_dir or DEFAULT_CACHE_DIR
    cache_file = cdir / f"MSRC-{norm_id}.json"

    if cache_file.is_file():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(cached, dict):
                return cached
        except Exception:
            pass

    if offline or (cache_dir is None and norm_id in _MSRC_MISS_CACHE):
        return None

    headers = {
        "Accept": "application/json",
        "User-Agent": f"notaffected/{__version__} (+https://openvex.dev)",
    }
    updates_url = f"https://api.msrc.microsoft.com/cvrf/v3.0/updates/{norm_id}"
    try:
        req = urllib.request.Request(updates_url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            updates_raw = json.load(resp)
        entries = updates_raw.get("value") if isinstance(updates_raw, dict) else None
        if not isinstance(entries, list) or not entries:
            if cache_dir is None:
                _MSRC_MISS_CACHE.add(norm_id)
            return None
        cvrf_url = str(entries[0].get("CvrfUrl") or "").strip()
        parsed_cvrf = urllib.parse.urlparse(cvrf_url)
        if parsed_cvrf.scheme != "https" or (parsed_cvrf.hostname or "").lower() != "api.msrc.microsoft.com":
            return None

        req2 = urllib.request.Request(cvrf_url, headers=headers)
        with urllib.request.urlopen(req2, timeout=timeout) as resp2:
            cvrf_raw = json.loads(resp2.read(_MAX_MSRC_BYTES).decode("utf-8"))
        if not isinstance(cvrf_raw, dict):
            return None

        vuln_entry: dict[str, Any] | None = None
        for v in cvrf_raw.get("Vulnerability") or []:
            if isinstance(v, dict) and str(v.get("CVE") or "").strip().upper() == norm_id:
                vuln_entry = v
                break
        if vuln_entry is None:
            if cache_dir is None:
                _MSRC_MISS_CACHE.add(norm_id)
            return None

        title = str((vuln_entry.get("Title") or {}).get("Value") or "").strip()
        notes_text = " ".join(
            str(n.get("Value") or "").strip()
            for n in (vuln_entry.get("Notes") or [])
            if isinstance(n, dict) and n.get("Value")
        ).strip()

        fixed_builds: list[str] = []
        kbs: list[str] = []
        for rem in vuln_entry.get("Remediations") or []:
            if not isinstance(rem, dict):
                continue
            fb_raw = str(rem.get("FixedBuild") or "").strip()
            m_fb = re.match(r"^(?:10\.0\.|6\.\d\.)?(\d{4,5}\.\d+)$", fb_raw)
            if m_fb:
                cand = m_fb.group(1)
                if cand not in fixed_builds:
                    fixed_builds.append(cand)
            desc_val = str((rem.get("Description") or {}).get("Value") or "").strip()
            if re.fullmatch(r"\d{6,8}", desc_val):
                kb_tag = f"KB{desc_val}"
                if kb_tag not in kbs:
                    kbs.append(kb_tag)

        sev = "HIGH"
        for th in vuln_entry.get("Threats") or []:
            if isinstance(th, dict) and th.get("Type") == 3:
                sv = str((th.get("Description") or {}).get("Value") or "").strip().upper()
                if sv in ("CRITICAL", "IMPORTANT", "MODERATE", "LOW"):
                    sev = "HIGH" if sv == "IMPORTANT" else sv
                    break

        normalized: dict[str, Any] = {
            "id": norm_id,
            "summary": title or norm_id,
            "details": notes_text or title,
            "affected": [],
            "references": [
                {
                    "type": "ADVISORY",
                    "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{norm_id}",
                }
            ],
            "database_specific": {
                "source": "msrc",
                "severity": sev,
                "msrc_fixed_builds": fixed_builds,
                "msrc_kbs": kbs,
            },
        }
        try:
            cdir.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        except OSError:
            pass
        return normalized
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and cache_dir is None:
            _MSRC_MISS_CACHE.add(norm_id)
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


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
    """Ensure reference URL uses https:// and does not point to localhost or private/non-global IPs."""
    if not url.startswith("https://"):
        return False
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if (
        not host
        or host in ("localhost", "localhost.localdomain")
        or host.endswith((".local", ".internal"))
    ):
        return False
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+(?:\.\d+){0,2})", host):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            addr = info[4][0]
            ip_obj = ipaddress.ip_address(addr)
            if not ip_obj.is_global:
                return False
    except OSError:
        return False
    return True


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every HTTP redirect target against _is_safe_public_https_url."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if not _is_safe_public_https_url(str(newurl)):
            raise urllib.error.URLError(f"Blocked unsafe redirect target: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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

    opener = urllib.request.build_opener(_SafeRedirectHandler)
    snippets: list[str] = []
    for url in candidate_urls[:max_urls]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"notaffected/{__version__} (+https://openvex.dev)"},
            )
            with opener.open(req, timeout=timeout) as resp:
                raw_bytes = resp.read(65536)
            text = raw_bytes.decode("utf-8", errors="ignore")
            cleaned = strip_html_to_text(text)
            if cleaned:
                snippets.append(f"[Reference {url}]: {cleaned[:1500]}")
        except Exception:
            continue
    return "\n".join(snippets)



