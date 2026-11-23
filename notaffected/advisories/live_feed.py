"""Live CVE discovery via CISA Known Exploited Vulnerabilities (KEV) feed and
OSV.dev `/v1/querybatch` against installed host packages.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Any

from notaffected import __version__
from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.extractor import extract_from_osv_payload, resolve_check_spec
from notaffected.advisories.fetcher import DEFAULT_CACHE_DIR
from notaffected.model import CheckSpec
from notaffected.probes.primitives import _dpkg_status_installed
from notaffected.probes.runner import HostRunner

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
KEV_CACHE_TTL_SECONDS = 6 * 3600

WATCHED_LINUX_PACKAGES: tuple[str, ...] = (
    "openssh-server",
    "cups-browsed",
    "nginx",
    "openssl",
    "sudo",
    "curl",
    "systemd",
)

_RELEVANT_KEV_RE = re.compile(
    r"\b(linux|kernel|openbsd|openssh|canonical|ubuntu|debian|gnu|isc|nginx|"
    r"openprinting|cups|openssl|sudo|curl|systemd|microsoft)\b",
    re.IGNORECASE,
)

_RELEVANT_WINDOWS_KEYWORDS = (
    "windows",
    "spooler",
    "tcp/ip",
    "ipv6",
    "message queuing",
    "msmq",
    "active directory",
    "kerberos",
    "ntlm",
    "smb",
)
MAX_FEED_BYTES = 15 * 1024 * 1024


def fetch_cisa_kev_cves(
    limit: int = 5,
    cache_dir: Path | None = None,
    timeout: int = 8,
    exclude_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch recent Linux & Windows Server CVEs from the live CISA KEV catalog."""
    cdir = cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR
    cache_file = cdir / "cisa_kev_catalog.json"

    payload: dict[str, Any] | None = None
    if cache_file.is_file():
        try:
            age = time.time() - cache_file.stat().st_mtime
            if age < KEV_CACHE_TTL_SECONDS:
                loaded = json.loads(cache_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("vulnerabilities"), list):
                    payload = loaded
        except Exception:
            payload = None

    if payload is None:
        try:
            req = urllib.request.Request(
                CISA_KEV_URL,
                headers={
                    "Accept": "application/json",
                    "User-Agent": f"notaffected/{__version__} (+https://openvex.dev)",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(MAX_FEED_BYTES)
                raw = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("vulnerabilities"), list):
                payload = raw
                try:
                    cdir.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(json.dumps(payload), encoding="utf-8")
                except OSError:
                    pass
        except Exception:
            return []

    if not payload:
        return []

    vulns = payload.get("vulnerabilities") or []
    excluded = {cid.upper() for cid in (exclude_ids or set())}
    matched: list[dict[str, Any]] = []
    for item in vulns:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-") or cve_id in excluded:
            continue
        vendor = str(item.get("vendorProject") or "").lower()
        product = str(item.get("product") or "").lower()
        desc = str(item.get("shortDescription") or "").lower()
        combined = f"{vendor} {product} {desc}"

        if not _RELEVANT_KEV_RE.search(f"{vendor} {product}"):
            continue
        if "microsoft" in vendor and not any(k in combined for k in _RELEVANT_WINDOWS_KEYWORDS):
            continue
        matched.append(item)

    matched.sort(key=lambda x: str(x.get("dateAdded") or ""), reverse=True)
    return matched[: max(0, limit)]


def _probe_installed_watched_packages(runner: HostRunner) -> list[tuple[str, str, str]]:
    """Return `[(package_name, installed_version, ecosystem_hint)]` for watched packages on Linux."""
    installed: list[tuple[str, str, str]] = []
    if getattr(runner, "os_family", "linux") != "linux":
        return installed

    # Check dpkg first (Debian / Ubuntu)
    dpkg_works = False
    for pkg in WATCHED_LINUX_PACKAGES:
        res = runner.run(
            ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", pkg]
        )
        if not res.transport_error and (res.returncode == 0 or "no packages found" in res.stderr.lower()):
            dpkg_works = True
        if res.transport_error or res.returncode != 0:
            continue
        first_line = (res.stdout.strip().splitlines() or [""])[0]
        parts = first_line.split("\t")
        status_col = parts[0].strip() if parts else ""
        ver = parts[1].strip() if len(parts) > 1 else first_line.strip()
        if _dpkg_status_installed(status_col) and ver:
            installed.append((pkg, ver, "deb"))

    if dpkg_works or installed:
        return installed

    # Fallback to apk (Alpine)
    for pkg in WATCHED_LINUX_PACKAGES:
        res = runner.run(["apk", "info", "-e", "-v", pkg])
        if res.transport_error or res.returncode != 0 or not res.stdout.strip():
            continue
        line = res.stdout.strip().splitlines()[0].strip()
        prefix = f"{pkg}-"
        if line.startswith(prefix) and len(line) > len(prefix):
            installed.append((pkg, line[len(prefix) :], "apk"))
    if installed:
        return installed

    # Fallback to rpm (RHEL / Rocky / Alma / Fedora)
    for pkg in WATCHED_LINUX_PACKAGES:
        res = runner.run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", pkg])
        if res.transport_error or res.returncode != 0 or not res.stdout.strip():
            continue
        ver = res.stdout.strip().splitlines()[0].strip()
        if ver and "not installed" not in ver.lower():
            installed.append((pkg, ver, "rpm"))
    return installed


_BINARY_TO_OSV_SOURCE: dict[str, str] = {
    "openssh-server": "openssh",
    "libc6": "glibc",
}


def discover_host_package_cves(
    runners: list[HostRunner],
    timeout: int = 8,
) -> list[tuple[str, str]]:
    """Query OSV.dev `/v1/querybatch` for packages actually installed on the target Linux hosts.
    Returns a deduplicated list of `(cve_id, package_name)` pairs.
    """
    pkg_versions: list[tuple[str, str, str]] = []
    seen_triples: set[tuple[str, str, str]] = set()
    for runner in runners:
        if getattr(runner, "os_family", "linux") != "linux":
            continue
        for triple in _probe_installed_watched_packages(runner):
            if triple not in seen_triples:
                seen_triples.add(triple)
                pkg_versions.append(triple)

    if not pkg_versions:
        return []

    queries: list[dict[str, Any]] = []
    query_pkg_map: list[str] = []
    for pkg, ver, eco_kind in pkg_versions:
        osv_names = [pkg]
        if pkg in _BINARY_TO_OSV_SOURCE:
            osv_names.append(_BINARY_TO_OSV_SOURCE[pkg])
        ecosystems = (
            ("Alpine",)
            if eco_kind == "apk"
            else ("Red Hat", "Rocky Linux", "AlmaLinux")
            if eco_kind == "rpm"
            else ("Ubuntu", "Debian")
        )
        for qname in osv_names:
            for eco in ecosystems:
                queries.append({"package": {"name": qname, "ecosystem": eco}, "version": ver})
                query_pkg_map.append(pkg)

    try:
        req = urllib.request.Request(
            OSV_QUERYBATCH_URL,
            data=json.dumps({"queries": queries}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"notaffected/{__version__} (+https://openvex.dev)",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_batch = resp.read(MAX_FEED_BYTES)
            batch_data = json.loads(raw_batch.decode("utf-8"))
    except Exception:
        return []

    results = batch_data.get("results") if isinstance(batch_data, dict) else None
    if not isinstance(results, list):
        return []

    discovered: list[tuple[str, str]] = []
    seen_cves: set[str] = set()
    cve_re = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

    for idx, entry in enumerate(results):
        if not isinstance(entry, dict) or idx >= len(query_pkg_map):
            continue
        pkg_name = query_pkg_map[idx]
        for v in entry.get("vulns") or []:
            if not isinstance(v, dict):
                continue
            vid = str(v.get("id") or "")
            m = cve_re.search(vid)
            if m:
                cve_id = m.group(1).upper()
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    discovered.append((cve_id, pkg_name))
                if len(discovered) >= 6:
                    return discovered
    return discovered


def _kev_item_to_osv_like(item: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(item.get("cveID") or "").strip().upper()
    vendor = str(item.get("vendorProject") or "")
    product = str(item.get("product") or "")
    name = str(item.get("vulnerabilityName") or cve_id)
    desc = str(item.get("shortDescription") or "")
    action = str(item.get("requiredAction") or "")
    return {
        "id": cve_id,
        "summary": f"{vendor} {product} — {name}".strip(" —"),
        "details": f"{desc}\nRequired Action: {action}".strip(),
        "database_specific": {"severity": "CRITICAL", "source": "CISA-KEV"},
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        ],
    }


def collect_scan_specs(
    runners: list[HostRunner],
    offline: bool = False,
    use_llm: bool = False,
    max_kev: int = 4,
    cache_dir: Path | None = None,
) -> tuple[list[CheckSpec], dict[str, Any]]:
    """Build the full list of CheckSpecs for `notaffected scan`:
    1. All built-in golden specs (Linux + Windows Server).
    2. Live OSV `/v1/querybatch` results for installed packages on Linux targets.
    3. Live CISA KEV actively exploited vulnerabilities feed.
    """
    specs: list[CheckSpec] = list(BUILTIN_SPECS.values())
    seen_ids: set[str] = {s.cve_id.upper() for s in specs}
    osv_live_ids: list[str] = []
    kev_live_ids: list[str] = []

    if not offline:
        for cve_id, pkg_name in discover_host_package_cves(runners):
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            osv_live_ids.append(cve_id)
            specs.append(
                resolve_check_spec(
                    cve_id,
                    use_llm=use_llm,
                    cache_dir=cache_dir,
                    package_hint=pkg_name,
                )
            )

        kev_items = fetch_cisa_kev_cves(
            limit=max_kev, cache_dir=cache_dir, exclude_ids=seen_ids
        )
        for item in kev_items:
            cve_id = str(item.get("cveID") or "").strip().upper()
            if not cve_id or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            kev_live_ids.append(cve_id)
            spec = resolve_check_spec(cve_id, use_llm=use_llm, cache_dir=cache_dir)
            if spec.source == "fallback":
                osv_like = _kev_item_to_osv_like(item)
                spec = extract_from_osv_payload(cve_id, osv_like, use_llm=use_llm)
            specs.append(spec)

    feed_meta: dict[str, Any] = {
        "builtin_count": len(BUILTIN_SPECS),
        "osv_live_cves": osv_live_ids,
        "cisa_kev_cves": kev_live_ids,
        "total_cves": len(specs),
        "offline": offline,
    }
    return specs, feed_meta
