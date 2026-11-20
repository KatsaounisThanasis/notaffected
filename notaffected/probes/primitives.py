"""Closed set of 9 read-only deterministic probe primitives.

Every probe returns a ProbeResult with status in {MET, NOT_MET, UNKNOWN} and
a concrete evidence string containing the command output snippet.
"""

from __future__ import annotations

import ipaddress
import re

from notaffected.model import Precondition, ProbeResult, ProbeStatus
from notaffected.probes.runner import HostRunner


def run_probe(precondition: Precondition, runner: HostRunner) -> ProbeResult:
    """Dispatch a Precondition to its deterministic probe handler."""
    handlers = {
        "kernel_version_vulnerable": _probe_kernel_version,
        "package_installed_vulnerable": _probe_package_installed,
        "kernel_module_loaded": _probe_kernel_module,
        "sysctl_equals": _probe_sysctl_equals,
        "network_listener": _probe_network_listener,
        "firewall_allows_port": _probe_firewall_allows_port,
        "systemd_service_active": _probe_systemd_service,
        "process_running": _probe_process_running,
        "config_contains": _probe_config_contains,
        "windows_build_vulnerable": _probe_windows_build_vulnerable,
        "windows_registry_equals": _probe_windows_registry_equals,
        "windows_service_active": _probe_windows_service_active,
    }
    handler = handlers.get(precondition.probe)
    if handler is None:
        return ProbeResult(
            precondition=precondition,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Unknown probe type: {precondition.probe}",
            command="",
        )
    return handler(precondition, runner)


def _normalize_kernel_release(uname_r: str) -> str:
    """Strip flavor suffixes like '-generic', '-aws', '-azure' and Ubuntu '.upload~backport' tags."""
    cleaned = uname_r.strip()
    cleaned = re.sub(r"~.*$", "", cleaned)
    cleaned = re.sub(
        r"-(generic|lowlatency|aws|azure|gcp|kvm|virtual|oem|raspi|server).*$",
        "",
        cleaned,
    )
    cleaned = re.sub(r"^(\d+\.\d+\.\d+-\d+)\.\d+.*$", r"\1", cleaned)
    return cleaned


def _probe_kernel_version(pre: Precondition, runner: HostRunner) -> ProbeResult:
    fixed_version = str(pre.params.get("fixed_version") or "").strip()
    min_version = str(pre.params.get("min_version") or "").strip()
    cmd = ["uname", "-r"]
    res = runner.run(cmd)
    if res.transport_error or res.returncode != 0 or not res.stdout.strip():
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Failed to read kernel version via 'uname -r': {res.stderr.strip() or 'empty output'}",
            command="uname -r",
        )

    running_raw = res.stdout.strip()
    running_norm = _normalize_kernel_release(running_raw)
    fixed_norm = _normalize_kernel_release(fixed_version) if fixed_version else ""

    if min_version:
        min_norm = _normalize_kernel_release(min_version)
        cmp_min = runner.run(["dpkg", "--compare-versions", running_norm, "lt", min_norm])
        if cmp_min.transport_error:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Transport error comparing minimum kernel version: {cmp_min.stderr.strip()}",
                command=f"dpkg --compare-versions {running_norm} lt {min_norm}",
            )
        if cmp_min.returncode == 0:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Running kernel '{running_raw}' is older than minimum affected version '{min_version}'",
                command="uname -r",
            )
        if cmp_min.returncode not in (0, 1, 127):
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Could not compare kernel version '{running_norm}' with '{min_norm}': {cmp_min.stderr.strip()}",
                command=f"dpkg --compare-versions {running_norm} lt {min_norm}",
            )

    if not fixed_norm:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Running kernel is '{running_raw}' (no fixed_version threshold specified; unfixed)",
            command="uname -r",
        )

    cmp_res = runner.run(["dpkg", "--compare-versions", running_norm, "lt", fixed_norm])
    if cmp_res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error comparing kernel versions: {cmp_res.stderr.strip()}",
            command=f"dpkg --compare-versions {running_norm} lt {fixed_norm}",
        )
    if cmp_res.returncode == 127:
        # Fallback tuple comparison if dpkg is unavailable on a non-Debian Linux host
        is_vuln = _fallback_version_lt(running_norm, fixed_norm)
    elif cmp_res.returncode in (0, 1):
        is_vuln = cmp_res.returncode == 0
    else:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Invalid version comparison ('{running_norm}' vs '{fixed_norm}'): {cmp_res.stderr.strip()}",
            command=f"dpkg --compare-versions {running_norm} lt {fixed_norm}",
        )

    if is_vuln:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Running kernel '{running_raw}' (< '{fixed_version}') is in vulnerable range",
            command="uname -r",
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Running kernel '{running_raw}' is >= fixed version '{fixed_version}'",
        command="uname -r",
    )


def _fallback_version_lt(v1: str, v2: str) -> bool:
    def parts(v: str) -> list[int]:
        return [int(x) for x in re.findall(r"\d+", v)]

    return parts(v1) < parts(v2)


def _resolve_host_release_fix(
    runner: HostRunner,
    release_fixes: object,
    installed_ver: str,
    default_fix: str,
) -> str:
    """Select the distro-release-specific fixed version (e.g. ubuntu:22.04 vs ubuntu:24.04)."""
    if not isinstance(release_fixes, dict) or not release_fixes:
        return default_fix
    m_tilde = re.search(r"~(\d{2}\.\d{2})\b", installed_ver)
    if m_tilde:
        k = f"ubuntu:{m_tilde.group(1)}"
        if k in release_fixes:
            return str(release_fixes[k])
    os_res = runner.run(["cat", "/etc/os-release"])
    if not os_res.transport_error and os_res.returncode == 0 and os_res.stdout:
        distro_id = ""
        ver_id = ""
        for line in os_res.stdout.splitlines():
            if line.startswith("ID="):
                distro_id = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
            elif line.startswith("VERSION_ID="):
                ver_id = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
        if distro_id == "alpine" and ver_id:
            parts = ver_id.split(".")
            if len(parts) >= 2:
                ver_id = f"{parts[0]}.{parts[1]}"
        if distro_id and ver_id:
            key = f"{distro_id}:{ver_id}"
            if key in release_fixes:
                return str(release_fixes[key])
    return default_fix


def _try_apk_or_rpm_package(
    pkg: str, runner: HostRunner
) -> tuple[str | None, str | None, str] | None:
    """Fallback package lookup for Alpine (`apk`) and RHEL/Rocky/Alma/Fedora (`rpm`) hosts."""
    mock_resps = getattr(runner, "responses", None)
    apk_cmd = ("apk", "info", "-e", "-v", pkg)
    rpm_cmd = ("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", pkg)

    if mock_resps is None or apk_cmd in mock_resps:
        apk_res = runner.run(list(apk_cmd))
        if not apk_res.transport_error and apk_res.returncode != 127 and "unmocked command" not in apk_res.stderr.lower():
            if apk_res.returncode != 0 or not apk_res.stdout.strip():
                return ("absent", "", f"apk info -e -v {pkg}")
            first = apk_res.stdout.strip().splitlines()[0].strip()
            prefix = f"{pkg}-"
            ver = first[len(prefix):] if first.startswith(prefix) else first
            return ("ii", ver, f"apk info -e -v {pkg}")

    if mock_resps is None or rpm_cmd in mock_resps:
        rpm_res = runner.run(list(rpm_cmd))
        if not rpm_res.transport_error and rpm_res.returncode != 127 and "unmocked command" not in rpm_res.stderr.lower():
            if rpm_res.returncode != 0 or not rpm_res.stdout.strip():
                if rpm_res.returncode == 1 or "not installed" in (rpm_res.stdout + rpm_res.stderr).lower():
                    return ("absent", "", f"rpm -q {pkg}")
                return None
            first = rpm_res.stdout.strip().splitlines()[0].strip()
            return ("ii", first, f"rpm -q {pkg}")

    return None


def _probe_package_installed(pre: Precondition, runner: HostRunner) -> ProbeResult:
    pkg = str(pre.params.get("package") or "").strip()
    fixed_version = str(pre.params.get("fixed_version") or "").strip()
    release_fixes = pre.params.get("release_fixes")
    if not pkg:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'package' parameter in precondition",
            command="",
        )

    cmd = ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", pkg]
    res = runner.run(cmd)
    cmd_str = f"dpkg-query -W {pkg}"
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking package '{pkg}': {res.stderr.strip()}",
            command=cmd_str,
        )

    pkg_display = pkg
    if res.returncode != 0:
        stderr_lower = res.stderr.lower()
        if "no packages found" in stderr_lower or (res.returncode == 1 and not stderr_lower.strip()):
            src_res = runner.run(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n",
                ]
            )
            matched_bin = ""
            matched_ver = ""
            if not src_res.transport_error and src_res.returncode == 0 and src_res.stdout:
                candidates: list[tuple[str, str]] = []
                for sline in src_res.stdout.splitlines():
                    sparts = sline.split("\t")
                    if len(sparts) >= 4 and sparts[0].strip().startswith("ii"):
                        bin_name = sparts[1].strip().split(":")[0]
                        src_name = sparts[2].strip().split(" ")[0]
                        bin_ver = sparts[3].strip()
                        src_ver = sparts[4].strip() if len(sparts) > 4 else ""
                        if src_name == pkg:
                            candidates.append((bin_name, src_ver or bin_ver))
                if candidates:
                    preferred = next(
                        (
                            c
                            for c in candidates
                            if c[0] in (f"{pkg}-server", f"{pkg}d", "libc6")
                        ),
                        candidates[0],
                    )
                    matched_bin, matched_ver = preferred
            if matched_bin and matched_ver:
                status_abbrev = "ii"
                installed_ver = matched_ver
                pkg_display = f"{pkg} (binary: {matched_bin})"
            else:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.NOT_MET,
                    evidence=f"Package '{pkg}' is not installed (dpkg-query)",
                    command=cmd_str,
                )
        elif res.returncode == 127:
            alt = _try_apk_or_rpm_package(pkg, runner)
            if alt is not None:
                alt_status, alt_ver, alt_cmd = alt
                cmd_str = alt_cmd
                if alt_status != "ii":
                    mgr = "apk info" if alt_cmd.startswith("apk") else "rpm -q"
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.NOT_MET,
                        evidence=f"Package '{pkg}' is not installed ({mgr})",
                        command=cmd_str,
                    )
                status_abbrev = "ii"
                installed_ver = alt_ver or ""
            else:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.UNKNOWN,
                    evidence=f"Could not query package '{pkg}': {res.stderr.strip()}",
                    command=cmd_str,
                )
        else:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Could not query package '{pkg}': {res.stderr.strip()}",
                command=cmd_str,
            )
    else:
        line = res.stdout.strip().splitlines()[0] if res.stdout.strip() else ""
        parts = line.split("\t")
        status_abbrev = parts[0].strip() if parts else ""
        installed_ver = parts[1].strip() if len(parts) > 1 else ""

    if not status_abbrev.startswith("ii"):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Package '{pkg}' is not installed (dpkg status='{status_abbrev or 'absent'}')",
            command=cmd_str,
        )

    fixed_version = _resolve_host_release_fix(
        runner, release_fixes, installed_ver, fixed_version
    )

    if not fixed_version:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Package '{pkg_display}' is installed at version '{installed_ver}' (no fixed version specified)",
            command=cmd_str,
        )

    if cmd_str.startswith("apk "):
        apk_cmp = runner.run(["apk", "version", "-t", installed_ver, fixed_version])
        if (
            not apk_cmp.transport_error
            and apk_cmp.returncode == 0
            and apk_cmp.stdout.strip() in ("<", "=", ">")
        ):
            is_vuln = apk_cmp.stdout.strip() == "<"
        else:
            is_vuln = _fallback_version_lt(installed_ver, fixed_version)
    else:
        cmp_res = runner.run(["dpkg", "--compare-versions", installed_ver, "lt", fixed_version])
        if cmp_res.transport_error:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Transport error comparing versions for '{pkg_display}': {cmp_res.stderr.strip()}",
                command=cmd_str,
            )
        if cmp_res.returncode == 127:
            is_vuln = _fallback_version_lt(installed_ver, fixed_version)
        elif cmp_res.returncode in (0, 1):
            is_vuln = cmp_res.returncode == 0
        else:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Invalid version comparison for '{pkg_display}' ('{installed_ver}' vs '{fixed_version}'): {cmp_res.stderr.strip()}",
                command=cmd_str,
            )
    if is_vuln:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Package '{pkg_display}' installed version '{installed_ver}' is < fixed version '{fixed_version}'",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Package '{pkg_display}' installed version '{installed_ver}' is >= fixed version '{fixed_version}'",
        command=cmd_str,
    )


def _probe_kernel_module(pre: Precondition, runner: HostRunner) -> ProbeResult:
    mod_name = str(pre.params.get("module") or "").strip()
    if not mod_name:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'module' parameter",
            command="",
        )

    cmd = ["cat", "/proc/modules"]
    res = runner.run(cmd)
    if res.transport_error or res.returncode != 0:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not read /proc/modules: {res.stderr.strip()}",
            command="cat /proc/modules",
        )

    # Kernel module names normalize '-' and '_' interchangeably
    target_norm = mod_name.replace("-", "_")
    for line in res.stdout.splitlines():
        cols = line.split()
        if not cols:
            continue
        loaded_norm = cols[0].replace("-", "_")
        if loaded_norm == target_norm:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"Kernel module '{cols[0]}' is loaded (/proc/modules: '{line.strip()}')",
                command="cat /proc/modules",
            )

    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Kernel module '{mod_name}' is not loaded in /proc/modules",
        command="cat /proc/modules",
    )


def _probe_sysctl_equals(pre: Precondition, runner: HostRunner) -> ProbeResult:
    key = str(pre.params.get("key") or "").strip()
    expected = str(pre.params.get("value") or "").strip()
    if not key:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'key' parameter in sysctl_equals",
            command="",
        )

    cmd = ["sysctl", "-n", key]
    res = runner.run(cmd)
    cmd_str = f"sysctl -n {key}"
    if res.transport_error or res.returncode != 0:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not read sysctl '{key}': {res.stderr.strip() or 'non-zero exit'}",
            command=cmd_str,
        )

    actual = res.stdout.strip()
    if actual == expected:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"sysctl '{key}' equals '{actual}'",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"sysctl '{key}' is '{actual}' (required '{expected}')",
        command=cmd_str,
    )


def _is_loopback_host(host_part: str) -> bool:
    """Return True if host_part is strictly loopback (127.0.0.0/8 or ::1)."""
    cleaned = host_part.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    # Strip interface scope like '127.0.0.53%lo' or 'fe80::1%eth0'
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    if cleaned in ("*", "0.0.0.0", "::", ""):
        return False
    if cleaned.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
        return ip.is_loopback
    except ValueError:
        return False


def _split_addr_port(local_addr_col: str) -> tuple[str, int | None]:
    """Split an ss Local Address:Port column into (host_part, port_int)."""
    if ":" not in local_addr_col:
        return local_addr_col, None
    host_part, port_str = local_addr_col.rsplit(":", 1)
    try:
        return host_part, int(port_str)
    except ValueError:
        return host_part, None


def _probe_network_listener(pre: Precondition, runner: HostRunner) -> ProbeResult:
    proto_filter = str(pre.params.get("proto") or "").lower().strip()
    port_filter = pre.params.get("port")
    process_filter = str(pre.params.get("process") or "").lower().strip()
    scope = str(pre.params.get("scope") or "non_loopback").lower().strip()

    target_port: int | None = None
    if port_filter is not None and str(port_filter).strip().lower() != "any":
        try:
            target_port = int(port_filter)
        except (ValueError, TypeError):
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Invalid port filter parameter: {port_filter!r}",
                command="ss -tulpnH",
            )

    cmd = ["ss", "-tulpnH"]
    res = runner.run(cmd)
    if res.transport_error or res.returncode != 0:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not inspect listening sockets via 'ss -tulpnH': {res.stderr.strip()}",
            command="ss -tulpnH",
        )

    matching_non_loopback: list[str] = []
    matching_loopback: list[str] = []

    for line in res.stdout.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        netid = cols[0].lower()
        local_col = cols[4]
        host_part, port_num = _split_addr_port(local_col)

        if proto_filter and proto_filter != "any":
            if proto_filter == "tcp" and netid not in ("tcp", "mptcp"):
                continue
            elif proto_filter != "tcp" and netid != proto_filter:
                continue

        if target_port is not None and port_num != target_port:
            continue

        if process_filter and process_filter not in line.lower():
            continue

        is_loop = _is_loopback_host(host_part)
        summary = f"{netid} {local_col}"
        if len(cols) >= 7:
            summary += f" ({cols[6]})"
        if is_loop:
            matching_loopback.append(summary)
        else:
            matching_non_loopback.append(summary)

    if scope == "non_loopback":
        if matching_non_loopback:
            sample = ", ".join(matching_non_loopback[:4])
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"Exposed non-loopback listener(s) found: {sample}",
                command="ss -tulpnH",
            )
        if matching_loopback:
            sample = ", ".join(matching_loopback[:4])
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"No non-loopback listeners found; only loopback listener(s) active: {sample}",
                command="ss -tulpnH",
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence="No matching network listeners found in 'ss -tulpnH'",
            command="ss -tulpnH",
        )

    # scope == "any"
    all_matches = matching_non_loopback + matching_loopback
    if all_matches:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Matching listener(s) found: {', '.join(all_matches[:4])}",
            command="ss -tulpnH",
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence="No matching network listeners found in 'ss -tulpnH'",
        command="ss -tulpnH",
    )


def _probe_firewall_allows_port(pre: Precondition, runner: HostRunner) -> ProbeResult:
    port = str(pre.params.get("port") or "any").strip()
    proto = str(pre.params.get("proto") or "tcp").lower().strip()

    # Try `ufw status verbose` first
    res = runner.run(["ufw", "status", "verbose"])
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking firewall: {res.stderr.strip()}",
            command="ufw status verbose",
        )
    if res.returncode != 0 or not res.stdout.strip():
        # Try non-verbose `ufw status` in case mock or older ufw is used
        res = runner.run(["ufw", "status"])

    if res.returncode == 0 and res.stdout.strip():
        out = res.stdout.strip()
        out_lower = out.lower()
        if "status: inactive" in out_lower:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence="Host firewall (ufw) is inactive; incoming traffic is not blocked by ufw",
                command="ufw status verbose",
            )
        if "status: active" in out_lower:
            if "allow (incoming)" in out_lower:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence="ufw is active with 'Default: allow (incoming)'",
                    command="ufw status verbose",
                )
            # Check if specific port or general allow rules exist (excluding Default: summary line)
            allow_lines = [
                ln.strip()
                for ln in out.splitlines()
                if not ln.strip().lower().startswith("default:")
                and "ALLOW" in ln.upper()
                and "OUT" not in ln.upper()
            ]
            if port != "any":
                port_allowed = any(
                    re.search(rf"\b{re.escape(port)}(/{proto})?\b", ln, re.IGNORECASE)
                    for ln in allow_lines
                )
                if port_allowed:
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.MET,
                        evidence=f"ufw is active and explicitly ALLOWs port {port}/{proto}",
                        command="ufw status verbose",
                    )
                if "deny (incoming)" in out_lower or "reject (incoming)" in out_lower or not allow_lines:
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.NOT_MET,
                        evidence=f"ufw is active with default deny incoming and no ALLOW rule for {port}/{proto}",
                        command="ufw status verbose",
                    )
            else:
                if allow_lines:
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.MET,
                        evidence=f"ufw is active with incoming ALLOW rule(s): {'; '.join(allow_lines[:3])}",
                        command="ufw status verbose",
                    )
                if "deny (incoming)" in out_lower or "reject (incoming)" in out_lower:
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.NOT_MET,
                        evidence="ufw is active with 'Default: deny (incoming)' and no incoming ALLOW rules",
                        command="ufw status verbose",
                    )

    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=(
            f"Could not verify firewall policy without root privileges "
            f"({res.stderr.strip() or 'ufw status unavailable'})"
        ),
        command="ufw status verbose",
    )


def _probe_systemd_service(pre: Precondition, runner: HostRunner) -> ProbeResult:
    service = str(pre.params.get("service") or "").strip()
    if not service:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'service' parameter",
            command="",
        )

    cmd = ["systemctl", "is-active", service]
    res = runner.run(cmd)
    cmd_str = f"systemctl is-active {service}"
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking service '{service}': {res.stderr.strip()}",
            command=cmd_str,
        )

    state = res.stdout.strip().lower()
    if res.returncode == 0 and state == "active":
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"systemd unit '{service}' is active",
            command=cmd_str,
        )
    if state in ("inactive", "failed", "deactivating") or "could not be found" in res.stderr.lower() or res.returncode in (3, 4):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"systemd unit '{service}' is not active (state='{state or 'not-found'}')",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=f"Could not determine systemd unit '{service}' state: {res.stderr.strip() or state}",
        command=cmd_str,
    )


def _probe_process_running(pre: Precondition, runner: HostRunner) -> ProbeResult:
    proc_name = str(pre.params.get("process") or "").strip()
    if not proc_name:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'process' parameter in process_running",
            command="",
        )

    if getattr(runner, "os_family", "linux").lower() == "windows":
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Process | Select-Object -ExpandProperty ProcessName",
        ]
        res_win = runner.run(ps_cmd)
        cmd_win_str = "powershell Get-Process"
        if res_win.transport_error or res_win.returncode != 0:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Could not list Windows processes: {res_win.stderr.strip()}",
                command=cmd_win_str,
            )
        target_win = proc_name.lower().removesuffix(".exe")
        for line in res_win.stdout.splitlines():
            p_clean = line.strip().lower().removesuffix(".exe")
            if p_clean and p_clean == target_win:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"Windows process '{line.strip()}' is running",
                    command=cmd_win_str,
                )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Windows process '{proc_name}' is not running (Get-Process)",
            command=cmd_win_str,
        )

    cmd = ["ps", "-eo", "comm,args", "--no-headers"]
    res = runner.run(cmd)
    cmd_str = "ps -eo comm,args --no-headers"
    if res.transport_error or res.returncode != 0:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not list processes via '{cmd_str}': {res.stderr.strip()}",
            command=cmd_str,
        )

    target_lower = proc_name.lower()
    for line in res.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        cols = stripped.split(None, 1)
        comm = cols[0].lower()
        if comm == target_lower or re.search(rf"\b{re.escape(target_lower)}\b", stripped.lower()):
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"Process '{proc_name}' is running ('{stripped[:80]}')",
                command=cmd_str,
            )

    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Process '{proc_name}' is not running in 'ps -eo comm,args'",
        command=cmd_str,
    )


_ALLOWED_CONFIG_PREFIXES = ("/etc/", "/proc/sys/", "/usr/share/", "/usr/lib/")


def _probe_config_contains(pre: Precondition, runner: HostRunner) -> ProbeResult:
    path_str = str(pre.params.get("path") or "").strip()
    pattern = str(pre.params.get("pattern") or "").strip()
    raw_neg = pre.params.get("negate", False)
    negate = (
        raw_neg.strip().lower() in ("true", "1", "yes")
        if isinstance(raw_neg, str)
        else bool(raw_neg)
    )

    if not path_str or not pattern:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'path' or 'pattern' parameter in config_contains",
            command="",
        )

    if ".." in path_str.split("/") or not path_str.startswith(_ALLOWED_CONFIG_PREFIXES):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Disallowed or unsafe config path: {path_str!r}",
            command="",
        )

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Invalid regex pattern {pattern!r}: {exc}",
            command="",
        )

    cmd = ["cat", path_str]
    res = runner.run(cmd)
    cmd_str = f"cat {path_str}"
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error reading '{path_str}': {res.stderr.strip()}",
            command=cmd_str,
        )

    if res.returncode != 0:
        err_lower = res.stderr.lower()
        if "no such file" in err_lower:
            # If the config file does not exist and we require a setting to be present (`negate=False`),
            # it is NOT_MET; if `negate=True` (we require a mitigating setting to be absent), file absence means MET.
            if negate:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"Config file '{path_str}' does not exist (mitigating pattern '{pattern}' not set)",
                    command=cmd_str,
                )
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Config file '{path_str}' does not exist",
                command=cmd_str,
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not read '{path_str}': {res.stderr.strip() or 'non-zero exit'}",
            command=cmd_str,
        )

    matched_line: str | None = None
    for raw_line in res.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        active_line = stripped.split("#", 1)[0].strip()
        if not active_line:
            continue
        if regex.search(active_line):
            matched_line = active_line
            break

    if negate:
        if matched_line is not None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Mitigating setting active in '{path_str}': '{matched_line}'",
                command=cmd_str,
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Mitigating setting '{pattern}' not found in active lines of '{path_str}'",
            command=cmd_str,
        )

    if matched_line is not None:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Matched active setting in '{path_str}': '{matched_line}'",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Pattern '{pattern}' not present in active (non-comment) lines of '{path_str}'",
        command=cmd_str,
    )


_SAFE_REG_PATH_RE = re.compile(r"\A(?:HKLM|HKCU):\\[A-Za-z0-9_\\.\- ]+\Z", re.IGNORECASE)
_SAFE_REG_NAME_RE = re.compile(r"\A[A-Za-z0-9_.\- ]+\Z")
_SAFE_WIN_SVC_RE = re.compile(r"\A[A-Za-z0-9_.-]+\Z")


def _parse_win_build(build_str: str) -> tuple[int, int] | None:
    m = re.match(r"\A(\d+)\.(\d+)\Z", build_str.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _probe_windows_build_vulnerable(pre: Precondition, runner: HostRunner) -> ProbeResult:
    kb = str(pre.params.get("kb") or "").strip().upper()
    fixed_build = str(pre.params.get("fixed_build") or "").strip()
    if not kb and not fixed_build:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'kb' or 'fixed_build' parameter in windows_build_vulnerable",
            command="",
        )

    ps_script = (
        "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
        "$build = \"$($cv.CurrentBuildNumber).$($cv.UBR)\"; "
        "$kbs = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID) -join ','; "
        "Write-Output \"BUILD=$build|KBS=$kbs\""
    )
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
    res = runner.run(cmd)
    cmd_str = "powershell Get-HotFix / CurrentVersion UBR"
    if res.transport_error or res.returncode != 0 or "BUILD=" not in res.stdout:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Failed to query Windows OS build/hotfixes via PowerShell: {res.stderr.strip() or 'invalid output'}",
            command=cmd_str,
        )

    out_line = res.stdout.strip().splitlines()[-1]
    build_val = ""
    kbs_set: set[str] = set()
    for part in out_line.split("|"):
        if part.startswith("BUILD="):
            build_val = part.removeprefix("BUILD=").strip()
        elif part.startswith("KBS="):
            raw_kbs = part.removeprefix("KBS=").strip()
            kbs_set = {k.strip().upper() for k in raw_kbs.split(",") if k.strip()}

    if kb and kb in kbs_set:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Security update '{kb}' is installed on Windows build '{build_val}'",
            command=cmd_str,
        )

    actual_parsed = _parse_win_build(build_val)
    if actual_parsed is None:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not parse Windows OS build '{build_val}' (and KB '{kb or 'N/A'}' not found)",
            command=cmd_str,
        )

    if fixed_build:
        actual_major, actual_ubr = actual_parsed
        raw_branches = [b.strip() for b in fixed_build.split(",") if b.strip()]
        parsed_branches = [
            (b, _parse_win_build(b)) for b in raw_branches
        ]
        valid_branches = [
            (b_str, p[0], p[1]) for b_str, p in parsed_branches if p is not None
        ]
        if not valid_branches:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Invalid fixed_build format '{fixed_build}'",
                command=cmd_str,
            )
        matched_branch = next(
            ((b_str, fm, fu) for b_str, fm, fu in valid_branches if fm == actual_major),
            None,
        )
        if matched_branch is None:
            first_str, fixed_major, _ = valid_branches[0]
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=(
                    f"Windows OS major build '{actual_major}' ({build_val}) differs from "
                    f"target branch '{fixed_major}' ({first_str}) and '{kb or 'N/A'}' is not installed"
                ),
                command=cmd_str,
            )
        matched_str, _, fixed_ubr = matched_branch
        if actual_ubr >= fixed_ubr:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Windows OS build '{build_val}' is >= fixed build '{matched_str}'",
                command=cmd_str,
            )
        fixed_build = matched_str

    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.MET,
        evidence=(
            f"Windows OS build '{build_val}' is < fixed build '{fixed_build or 'N/A'}' "
            f"and security update '{kb or 'N/A'}' is not installed"
        ),
        command=cmd_str,
    )


def _registry_values_match(actual: str, expected: str) -> bool:
    act = actual.strip()
    exp = expected.strip()
    if act.lower() == exp.lower():
        return True
    try:
        return int(act, 0) == int(exp, 0)
    except ValueError:
        return False


def _probe_windows_registry_equals(pre: Precondition, runner: HostRunner) -> ProbeResult:
    reg_path = str(pre.params.get("path") or "").strip()
    reg_name = str(pre.params.get("name") or "").strip()
    expected = str(pre.params.get("value") or "").strip()
    raw_neg = pre.params.get("negate", False)
    negate = (
        raw_neg.strip().lower() in ("true", "1", "yes")
        if isinstance(raw_neg, str)
        else bool(raw_neg)
    )

    if not reg_path or not reg_name or expected == "":
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing 'path', 'name', or 'value' in windows_registry_equals",
            command="",
        )

    if not _SAFE_REG_PATH_RE.match(reg_path) or not _SAFE_REG_NAME_RE.match(reg_name):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Disallowed or unsafe Windows Registry path/name: {reg_path!r} / {reg_name!r}",
            command="",
        )

    ps_script = f"(Get-ItemProperty -Path '{reg_path}' -Name '{reg_name}' -ErrorAction Stop).'{reg_name}'"
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
    res = runner.run(cmd)
    cmd_str = f"powershell Get-ItemProperty {reg_path} {reg_name}"

    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error reading Windows Registry '{reg_path}': {res.stderr.strip()}",
            command=cmd_str,
        )

    if res.returncode != 0:
        err_lower = " ".join(res.stderr.lower().split())
        if "does not exist" in err_lower or "cannot find path" in err_lower:
            if negate:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"Registry value '{reg_name}' not set at '{reg_path}' (mitigation '{expected}' absent)",
                    command=cmd_str,
                )
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Registry value '{reg_name}' does not exist at '{reg_path}'",
                command=cmd_str,
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Could not read Windows Registry '{reg_path}': {res.stderr.strip()}",
            command=cmd_str,
        )

    actual = res.stdout.strip()
    matched = _registry_values_match(actual, expected)

    if negate:
        if matched:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Mitigating Registry value '{reg_name}={actual}' is active at '{reg_path}'",
                command=cmd_str,
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Registry value '{reg_name}' at '{reg_path}' is '{actual}' (mitigation '{expected}' not applied)",
            command=cmd_str,
        )

    if matched:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Registry value '{reg_name}' at '{reg_path}' equals '{actual}'",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Registry value '{reg_name}' at '{reg_path}' is '{actual}' (required '{expected}')",
        command=cmd_str,
    )


def _probe_windows_service_active(pre: Precondition, runner: HostRunner) -> ProbeResult:
    service = str(pre.params.get("service") or "").strip()
    if not service or not _SAFE_WIN_SVC_RE.match(service):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Missing or unsafe Windows service name: {service!r}",
            command="",
        )

    ps_script = f"(Get-Service -Name '{service}' -ErrorAction Stop).Status"
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
    res = runner.run(cmd)
    cmd_str = f"powershell Get-Service {service}"
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking Windows service '{service}': {res.stderr.strip()}",
            command=cmd_str,
        )

    state = res.stdout.strip().lower()
    err_lower = " ".join(res.stderr.lower().split())
    if res.returncode == 0 and state == "running":
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Windows service '{service}' is Running",
            command=cmd_str,
        )
    if (
        state in ("stopped", "stoppending", "paused")
        or "cannot find any service" in err_lower
        or "noservicefoundforgivenname" in err_lower
    ):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Windows service '{service}' is not running (status='{res.stdout.strip() or 'not-installed'}')",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=f"Could not determine Windows service '{service}' state: {res.stderr.strip() or state}",
        command=cmd_str,
    )



