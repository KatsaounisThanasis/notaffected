"""Closed set of 9 read-only deterministic probe primitives.

Every probe returns a ProbeResult with status in {MET, NOT_MET, UNKNOWN} and
a concrete evidence string containing the command output snippet.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import replace
from typing import NamedTuple

from notaffected.model import Precondition, ProbeResult, ProbeStatus
from notaffected.probes.runner import HostRunner

WIN_BUILD_PS_SCRIPT = (
    "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
    "$build = \"$($cv.CurrentBuildNumber).$($cv.UBR)\"; "
    "$kbs = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID) -join ','; "
    "Write-Output \"BUILD=$build|KBS=$kbs\""
)
# Read-only Windows build/KB query. Also used by the evaluator to confirm a host really is Windows.
WIN_BUILD_ARGV: list[str] = ["powershell", "-NoProfile", "-NonInteractive", "-Command", WIN_BUILD_PS_SCRIPT]


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
    try:
        return handler(precondition, runner)
    except Exception as exc:  # noqa: BLE001 - any probe/transport crash must resolve to UNKNOWN
        return ProbeResult(
            precondition=precondition,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Probe {precondition.probe} failed: {type(exc).__name__}: {exc}",
            command="",
        )


def _normalize_kernel_release(uname_r: str) -> str:
    """Reduce a kernel release to 'X.Y.Z-ABI' for comparison: drop '~backport' tags, any
    flavour suffix ('-generic', '-azure-fde', ...) and the Ubuntu upload number ('.111')."""
    cleaned = uname_r.strip()
    cleaned = re.sub(r"~.*$", "", cleaned)
    cleaned = re.sub(r"^(\d+\.\d+\.\d+-\d+)-[a-z].*$", r"\1", cleaned)
    cleaned = re.sub(r"^(\d+\.\d+\.\d+-\d+)\.\d+.*$", r"\1", cleaned)
    return cleaned


def _kernel_track(uname_r: str) -> tuple[str, str]:
    """(line, flavour) of a kernel release: '6.5.0-14-generic' -> ('6.5', 'generic').

    The flavour is the Ubuntu/Debian-style suffix after the ABI number; it is '' for kernels
    without one (RHEL, Fedora, Arch), whose build numbers are not comparable with Ubuntu's.
    """
    r = uname_r.strip()
    m_line = re.match(r"^(\d+)\.(\d+)", r)
    line = f"{m_line.group(1)}.{m_line.group(2)}" if m_line else ""
    m_flav = re.match(r"^\d+\.\d+\.\d+-\d+(?:\.\d+)*-([a-z][a-z0-9-]*)$", r)
    return line, (m_flav.group(1) if m_flav else "")


def _line_tuple(line: str) -> tuple[int, int] | None:
    m = re.match(r"^(\d+)\.(\d+)", line.strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


# Flavours that share Ubuntu's generic ABI numbering, so a legacy single fixed_version applies.
_GENERIC_KERNEL_FLAVOURS = frozenset({"generic", "lowlatency"})


def _probe_kernel_version(pre: Precondition, runner: HostRunner) -> ProbeResult:
    """Compare the running kernel only against fix data for its own track (line + flavour).

    Decision order: (1) a curated `mainline_from` line at or below the host's line means the
    upstream fix is in it; (2) `track_fixes` keyed 'ubuntu:<release>:<line>:<flavour>';
    (3) a legacy `fixed_version` on the same line, generic flavour only; otherwise UNKNOWN.
    """
    fixed_version = str(pre.params.get("fixed_version") or "").strip()
    min_version = str(pre.params.get("min_version") or "").strip()
    mainline_from = str(pre.params.get("mainline_from") or "").strip()
    track_fixes = pre.params.get("track_fixes") if isinstance(pre.params.get("track_fixes"), dict) else {}
    res = runner.run(["uname", "-r"])
    if res.transport_error or res.returncode != 0 or not res.stdout.strip():
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Failed to read kernel version via 'uname -r': {res.stderr.strip() or 'empty output'}",
            command="uname -r",
        )

    running_raw = res.stdout.strip()
    running_norm = _normalize_kernel_release(running_raw)
    line, flavour = _kernel_track(running_raw)
    host_line = _line_tuple(line)
    if host_line is None:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Unreadable kernel release '{running_raw}'",
            command="uname -r",
        )

    def _compare(fixed: str, label: str) -> ProbeResult:
        fixed_norm = _normalize_kernel_release(fixed)
        is_vuln = _compare_lt(runner, running_norm, fixed_norm)
        if is_vuln is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Could not compare kernel version '{running_raw}' with fixed version '{fixed}'",
                command=f"dpkg --compare-versions {running_norm} lt {fixed_norm}",
            )
        if is_vuln:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"Running kernel '{running_raw}' (< '{fixed}'{label}) is in vulnerable range",
                command="uname -r",
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Running kernel '{running_raw}' is >= fixed version '{fixed}'{label}",
            command="uname -r",
        )

    if min_version:
        min_line = _line_tuple(min_version)
        if min_line is None:
            older: bool | None = None
        elif host_line != min_line:
            older = host_line < min_line  # line order is real version order
        else:
            older = _compare_lt(runner, running_norm, _normalize_kernel_release(min_version))
        if older is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Could not compare kernel version '{running_raw}' with minimum '{min_version}'",
                command="uname -r",
            )
        if older:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Running kernel '{running_raw}' is older than minimum affected version '{min_version}'",
                command="uname -r",
            )

    mainline = _line_tuple(mainline_from) if mainline_from else None
    if mainline is not None and host_line >= mainline:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=(
                f"Running kernel '{running_raw}' is on line {line}, which includes the upstream fix "
                f"(mainline since {mainline_from})"
            ),
            command="uname -r",
        )

    if track_fixes:
        distro_id, ver_id = _read_os_release(runner)
        key = f"{distro_id}:{ver_id}:{line}:{flavour}"
        if distro_id and ver_id and flavour and key in track_fixes:
            fixed = str(track_fixes[key] or "")
            if not fixed:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"Running kernel '{running_raw}': track '{key}' is listed as affected with no fix",
                    command="uname -r",
                )
            return _compare(fixed, f" for track '{key}'")
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"No fix data for kernel track '{key}' (running '{running_raw}')",
            command="uname -r",
        )

    if not fixed_version:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Running kernel is '{running_raw}' (no fixed_version threshold specified; unfixed)",
            command="uname -r",
        )

    fixed_line = _line_tuple(fixed_version)
    if fixed_line == host_line and flavour in _GENERIC_KERNEL_FLAVOURS:
        return _compare(fixed_version, "")
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=(
            f"No fix data for kernel track {line}/{flavour or 'unknown flavour'} "
            f"(running '{running_raw}', fix '{fixed_version}' is for line "
            f"{'.'.join(map(str, fixed_line)) if fixed_line else 'unknown'} generic)"
        ),
        command="uname -r",
    )


def _compare_lt(runner: HostRunner, a: str, b: str) -> bool | None:
    """True if version `a` < `b` per the host's `dpkg --compare-versions`; None when it cannot tell.

    None covers a transport error, a missing dpkg (rc 127, e.g. rpm hosts), any rc other than 0/1,
    and any stderr output: dpkg's "bad syntax" warning comes with rc 1 for an unreadable version (which
    must not read as "patched") and is translated per locale, so no particular wording is relied on.
    There is deliberately no digit-list fallback: it mis-orders epochs, letters and distro suffixes.
    """
    res = runner.run(["dpkg", "--compare-versions", a, "lt", b])
    if res.transport_error or res.returncode not in (0, 1) or res.stderr.strip():
        return None
    return res.returncode == 0


def _dpkg_status_installed(status_abbrev: str) -> bool:
    """dpkg `${db:Status-Abbrev}` is desired/status/error; files are on disk unless status is n or c."""
    status = status_abbrev[1:2]
    return bool(status) and status not in ("n", "c")


def _read_os_release(runner: HostRunner) -> tuple[str, str]:
    """(ID, VERSION_ID) from /etc/os-release, lowercased; Alpine VERSION_ID cut to major.minor.
    Empty strings when the file cannot be read."""
    res = runner.run(["cat", "/etc/os-release"])
    if res.transport_error or res.returncode != 0 or not res.stdout:
        return "", ""
    distro_id = ""
    ver_id = ""
    for line in res.stdout.splitlines():
        if line.startswith("ID="):
            distro_id = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
        elif line.startswith("VERSION_ID="):
            ver_id = line.split("=", 1)[1].strip().strip('"').strip("'").lower()
    if distro_id == "alpine" and ver_id:
        parts = ver_id.split(".")
        if len(parts) >= 2:
            ver_id = f"{parts[0]}.{parts[1]}"
    return distro_id, ver_id


_RPM_TOKEN_RE = re.compile(r"^[A-Za-z0-9._+~^]+$")
_NON_RPM_FIX_RE = re.compile(
    r"(ubuntu|\+deb\d+|~deb\d+|~bpo\d+|\+dfsg|\+ds\d|build\d|-r\d+$)",
    re.IGNORECASE,
)
_RHEL_CLONE_IDS = frozenset({"rocky", "almalinux"})
_RPM_MAJOR_IDS = frozenset({"rhel", "rocky", "almalinux", "centos", "ol", "fedora"})


def _rpmvercmp(a: str, b: str) -> int:
    """Pure-Python implementation of RPM's `rpmvercmp` segment comparator.

    Matches upstream rpmio/rpmvercmp.c semantics:
    - Non-alphanumeric separators (other than `~` and `^`) are skipped.
    - `~` (pre-release) sorts before anything, including end-of-string.
    - `^` (post-release snapshot) sorts after end-of-string, before any other char.
    - Numeric segments always sort newer than alphabetic segments.
    - Numeric segments compare by integer value (ignoring leading zeros).
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    i = j = 0
    while i < la or j < lb:
        while i < la and not (a[i].isascii() and a[i].isalnum()) and a[i] not in ("~", "^"):
            i += 1
        while j < lb and not (b[j].isascii() and b[j].isalnum()) and b[j] not in ("~", "^"):
            j += 1

        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= la or j >= lb:
            break

        is_num_a = a[i].isdigit()
        is_num_b = b[j].isdigit()
        if is_num_a:
            start_a = i
            while i < la and a[i].isdigit():
                i += 1
            seg_a = a[start_a:i]
        else:
            start_a = i
            while i < la and a[i].isascii() and a[i].isalpha():
                i += 1
            seg_a = a[start_a:i]

        if is_num_b:
            start_b = j
            while j < lb and b[j].isdigit():
                j += 1
            seg_b = b[start_b:j]
        else:
            start_b = j
            while j < lb and b[j].isascii() and b[j].isalpha():
                j += 1
            seg_b = b[start_b:j]

        if is_num_a != is_num_b:
            return 1 if is_num_a else -1

        if is_num_a:
            na, nb = int(seg_a), int(seg_b)
            if na != nb:
                return -1 if na < nb else 1
        else:
            if seg_a != seg_b:
                return -1 if seg_a < seg_b else 1

    if i == la and j == lb:
        return 0
    return -1 if i == la else 1


def _split_rpm_evr(raw: str) -> tuple[int, bool, str, str] | None:
    """Parse an RPM EVR `[epoch:]version[-release]` into `(epoch, has_epoch, version, release)`."""
    s = raw.strip()
    if not s or any(ch.isspace() for ch in s):
        return None
    has_epoch = False
    epoch = 0
    if ":" in s:
        ep_str, s = s.split(":", 1)
        if not ep_str.isdigit():
            return None
        epoch = int(ep_str)
        has_epoch = True
    if not s:
        return None
    if "-" in s:
        ver, rel = s.split("-", 1)
        if not ver or not rel or "-" in rel:
            return None
    else:
        ver, rel = s, ""
    if not _RPM_TOKEN_RE.fullmatch(ver):
        return None
    if rel and not _RPM_TOKEN_RE.fullmatch(rel):
        return None
    return epoch, has_epoch, ver, rel


def _rpm_evr_lt(installed: str, fixed: str) -> bool | None:
    """Return True if RPM EVR `installed < fixed`, False if `>=`, or None if incomparable.

    Refuses cross-distro Debian/Ubuntu/Alpine fix strings and refuses comparing against a
    non-zero fixed epoch when the installed version omitted its epoch.
    """
    if not installed or not fixed:
        return None
    if _NON_RPM_FIX_RE.search(fixed):
        return None
    inst = _split_rpm_evr(installed)
    fix = _split_rpm_evr(fixed)
    if inst is None or fix is None:
        return None
    inst_ep, inst_has_ep, inst_ver, inst_rel = inst
    fix_ep, _, fix_ver, fix_rel = fix
    if not inst_has_ep and fix_ep != 0:
        return None
    if inst_ep != fix_ep:
        return inst_ep < fix_ep
    vcmp = _rpmvercmp(inst_ver, fix_ver)
    if vcmp != 0:
        return vcmp < 0
    if not fix_rel:
        return False
    if not inst_rel:
        return True
    return _rpmvercmp(inst_rel, fix_rel) < 0


def _match_release_fix_key(
    distro_id: str,
    ver_id: str,
    release_fixes: dict[object, object],
) -> str | None:
    """Find the matching key in `release_fixes` for `(distro_id, ver_id)`.

    Checks exact `<id>:<ver>`, then `<id>:<major>` for RPM distros whose `/etc/os-release`
    reports minor versions (e.g. `rhel:9.4` -> `rhel:9`, `rocky:9.4` -> `rocky:9`), and finally
    `rhel:<major>` for binary-compatible RHEL rebuilds (`rocky`, `almalinux`).
    """
    if not distro_id or not ver_id:
        return None
    exact = f"{distro_id}:{ver_id}"
    if exact in release_fixes:
        return exact
    if distro_id in _RPM_MAJOR_IDS:
        major = ver_id.split(".", 1)[0]
        if major.isdigit():
            major_key = f"{distro_id}:{major}"
            if major_key in release_fixes:
                return major_key
            if distro_id in _RHEL_CLONE_IDS:
                rhel_key = f"rhel:{major}"
                if rhel_key in release_fixes:
                    return rhel_key
    return None


def _resolve_host_release_fix(
    runner: HostRunner,
    release_fixes: object,
    installed_ver: str,
    default_fix: str,
) -> tuple[str, str] | None:
    """Pick the fix for the host's own distro release.

    Returns (fixed_version, host_release_key); fixed_version "" means the release is listed as
    affected with no fix yet. Without per-release data the default fix applies (key ""). When
    per-release data exists but the host's release is not in it, returns None: another release's
    fix must never be borrowed.
    """
    if not isinstance(release_fixes, dict) or not release_fixes:
        return default_fix, ""
    m_tilde = re.search(r"~(\d{2}\.\d{2})\b", installed_ver)
    if m_tilde:
        k = f"ubuntu:{m_tilde.group(1)}"
        if k in release_fixes:
            return str(release_fixes[k] or ""), k
    distro_id, ver_id = _read_os_release(runner)
    matched = _match_release_fix_key(distro_id, ver_id, release_fixes)
    if matched is not None:
        return str(release_fixes[matched] or ""), matched
    return None


def _release_not_covered(pre: Precondition, runner: HostRunner, release_fixes: object, cmd_str: str) -> ProbeResult | None:
    """UNKNOWN result when per-release fix data exists but does not cover this host's release."""
    if not isinstance(release_fixes, dict) or not release_fixes:
        return None
    distro_id, ver_id = _read_os_release(runner)
    if _match_release_fix_key(distro_id, ver_id, release_fixes) is not None:
        return None
    key = f"{distro_id}:{ver_id}" if distro_id and ver_id else ""
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=(
            f"No fix data for host release '{key or 'unknown'}' (advisory lists: {', '.join(sorted(release_fixes))}); "
            "package names and fixes differ across releases"
        ),
        command=cmd_str,
    )


def _try_apk_or_rpm_package(
    pkg: str, runner: HostRunner
) -> tuple[str | None, str | None, str] | None:
    """Fallback package lookup for Alpine (`apk`) and RHEL/Rocky/Alma/Fedora (`rpm`) hosts."""
    # rc 127 means the tool is absent on this host: try the next package manager.
    apk_res = runner.run(["apk", "info", "-e", "-v", pkg])
    if not apk_res.transport_error and apk_res.returncode != 127:
        if apk_res.returncode != 0 or not apk_res.stdout.strip():
            return ("absent", "", f"apk info -e -v {pkg}")
        first = apk_res.stdout.strip().splitlines()[0].strip()
        prefix = f"{pkg}-"
        ver = first[len(prefix):] if first.startswith(prefix) else first
        return ("ii", ver, f"apk info -e -v {pkg}")

    # Prefer EPOCHNUM:VERSION-RELEASE on RPM 4.11+ so epoch comparisons are exact;
    # fall back to VERSION-RELEASE if EPOCHNUM is unsupported or unmocked.
    rpm_res = runner.run(["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", pkg])
    if (
        rpm_res.transport_error
        or rpm_res.returncode == 127
        or (rpm_res.returncode == 0 and "%{EPOCHNUM}" in rpm_res.stdout)
    ):
        rpm_res = runner.run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", pkg])
    if not rpm_res.transport_error and rpm_res.returncode != 127:
        if rpm_res.returncode != 0 or not rpm_res.stdout.strip():
            if rpm_res.returncode == 1 or "not installed" in (rpm_res.stdout + rpm_res.stderr).lower():
                return ("absent", "", f"rpm -q {pkg}")
            return None
        first = rpm_res.stdout.strip().splitlines()[0].strip()
        return ("ii", first, f"rpm -q {pkg}")

    return None


def _probe_package_installed(pre: Precondition, runner: HostRunner) -> ProbeResult:
    """Package probe; whenever the package is found installed, the result carries its facts
    (type/namespace/name/version/epoch) so the verdict can name it by PURL in VEX."""
    facts: dict[str, str] = {}
    result = _package_probe_core(pre, runner, facts)
    return replace(result, facts=facts) if facts else result


def _record_package_facts(facts: dict[str, str], runner: HostRunner, purl_type: str, name: str, version: str) -> None:
    m_epoch = re.match(r"^(\d+):(.+)$", version)
    epoch_val = m_epoch.group(1) if m_epoch else ""
    if epoch_val == "0":
        epoch_val = ""
    facts.update(
        {
            "purl_type": purl_type,
            "name": name,
            "version": m_epoch.group(2) if m_epoch else version,
            "epoch": epoch_val,
            "namespace": _read_os_release(runner)[0],
        }
    )


def _package_probe_core(pre: Precondition, runner: HostRunner, facts: dict[str, str]) -> ProbeResult:
    pkg = str(pre.params.get("package") or "").strip()
    fixed_version = str(pre.params.get("fixed_version") or "").strip()
    release_fixes = pre.params.get("release_fixes")
    if not pkg or pkg.startswith("-"):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence="Missing or invalid 'package' parameter in precondition",
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
    matched_bin = ""
    matched_bin_ver = ""
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
            matched_ver = ""
            if src_res.transport_error or src_res.returncode != 0:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.UNKNOWN,
                    evidence=(
                        f"Package '{pkg}' not found by name and the source-package listing failed: "
                        f"{src_res.stderr.strip() or f'exit {src_res.returncode}'}"
                    ),
                    command=cmd_str,
                )
            if src_res.stdout:
                candidates: list[tuple[str, str, str]] = []
                for sline in src_res.stdout.splitlines():
                    sparts = sline.split("\t")
                    if len(sparts) >= 4 and _dpkg_status_installed(sparts[0]):
                        bin_name = sparts[1].strip().split(":")[0]
                        src_name = sparts[2].strip().split(" ")[0]
                        bin_ver = sparts[3].strip()
                        src_ver = sparts[4].strip() if len(sparts) > 4 else ""
                        if src_name == pkg:
                            candidates.append((bin_name, src_ver or bin_ver, bin_ver))
                if candidates:
                    preferred = next(
                        (
                            c
                            for c in candidates
                            if c[0] in (f"{pkg}-server", f"{pkg}d", "libc6")
                        ),
                        candidates[0],
                    )
                    matched_bin, matched_ver, matched_bin_ver = preferred
            if matched_bin and matched_ver:
                status_abbrev = "ii"
                installed_ver = matched_ver
                pkg_display = f"{pkg} (binary: {matched_bin})"
            else:
                gate = _release_not_covered(pre, runner, release_fixes, cmd_str)
                if gate is not None:
                    return gate
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
                    gate = _release_not_covered(pre, runner, release_fixes, cmd_str)
                    if gate is not None:
                        return gate
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

    if not _dpkg_status_installed(status_abbrev):
        gate = _release_not_covered(pre, runner, release_fixes, cmd_str)
        if gate is not None:
            return gate
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Package '{pkg}' is not installed (dpkg status='{status_abbrev or 'absent'}')",
            command=cmd_str,
        )

    purl_type = "apk" if cmd_str.startswith("apk ") else "rpm" if cmd_str.startswith("rpm ") else "deb"
    _record_package_facts(facts, runner, purl_type, matched_bin or pkg, matched_bin_ver or installed_ver)

    resolved = _resolve_host_release_fix(runner, release_fixes, installed_ver, fixed_version)
    if resolved is None:
        gate = _release_not_covered(pre, runner, release_fixes, cmd_str)
        return gate or ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"No fix data for this host's release for '{pkg_display}'",
            command=cmd_str,
        )
    fixed_version, release_key = resolved

    if not fixed_version and release_key:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=(
                f"Package '{pkg_display}' is installed at version '{installed_ver}'; "
                f"release '{release_key}' is listed as affected with no fix"
            ),
            command=cmd_str,
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
        if apk_cmp.transport_error or apk_cmp.returncode != 0 or apk_cmp.stdout.strip() not in ("<", "=", ">"):
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=(
                    f"Could not compare Alpine versions for '{pkg_display}' ('{installed_ver}' vs "
                    f"'{fixed_version}'): {apk_cmp.stderr.strip() or apk_cmp.stdout.strip()}"
                ),
                command=cmd_str,
            )
        is_vuln = apk_cmp.stdout.strip() == "<"
    elif cmd_str.startswith("rpm "):
        rpm_lt = _rpm_evr_lt(installed_ver, fixed_version)
        if rpm_lt is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=(
                    f"Could not compare RPM EVR versions for '{pkg_display}' ('{installed_ver}' vs "
                    f"'{fixed_version}'); cross-distro or unreadable EVR"
                ),
                command=cmd_str,
            )
        is_vuln = rpm_lt
    else:
        cmp_lt = _compare_lt(runner, installed_ver, fixed_version)
        if cmp_lt is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=(
                    f"Could not compare versions for '{pkg_display}' ('{installed_ver}' vs '{fixed_version}'); "
                    "no dpkg comparator on this host or the version is unreadable"
                ),
                command=cmd_str,
            )
        is_vuln = cmp_lt
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
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", mod_name):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Missing or invalid 'module' parameter: {mod_name!r}",
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

    # Not loaded is not proof: unprivileged users can trigger autoload (e.g. nf_tables through user
    # namespaces). It is proof only when loading is blocked.
    blocked = _module_load_blocked(runner, target_norm)
    if blocked:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"Kernel module '{mod_name}' is not loaded in /proc/modules and loading is blocked ({blocked})",
            command="cat /proc/modules; modprobe -c",
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=(
            f"Kernel module '{mod_name}' is not loaded in /proc/modules, but it is not blocked and can be "
            "loaded on demand (or is built in)"
        ),
        command="cat /proc/modules; modprobe -c",
    )


def _module_load_blocked(runner: HostRunner, module_norm: str) -> str:
    """Reason string when the module cannot be loaded ('' when it can or we cannot tell)."""
    res = runner.run(["modprobe", "-c"])
    if not res.transport_error and res.returncode == 0:
        for line in res.stdout.splitlines():
            parts = line.split()
            if (
                len(parts) >= 3
                and parts[0] == "install"
                and parts[1].replace("-", "_") == module_norm
                and parts[2] in ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true")
            ):
                return f"modprobe.d: '{line.strip()}'"
    dis = runner.run(["cat", "/proc/sys/kernel/modules_disabled"])
    if not dis.transport_error and dis.returncode == 0 and dis.stdout.strip() == "1":
        return "kernel.modules_disabled=1"
    return ""


def _probe_sysctl_equals(pre: Precondition, runner: HostRunner) -> ProbeResult:
    key = str(pre.params.get("key") or "").strip()
    expected = str(pre.params.get("value") or "").strip()
    # A leading '-' would turn `sysctl -n <key>` into an option such as --system (a write as root).
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", key):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Missing or invalid 'key' parameter in sysctl_equals: {key!r}",
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

    if proto_filter in ("mptcp", "sctp"):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"'{proto_filter}' listeners are not listed by 'ss -tulpnH'",
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
    hidden_process = 0  # matching sockets whose owner ss did not show (non-root, other user's socket)

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
            if "users:(" not in line:
                hidden_process += 1
            continue

        is_loop = _is_loopback_host(host_part)
        summary = f"{netid} {local_col}"
        if len(cols) >= 7:
            summary += f" ({cols[6]})"
        if is_loop:
            matching_loopback.append(summary)
        else:
            matching_non_loopback.append(summary)

    if hidden_process and not matching_non_loopback and (scope == "non_loopback" or not matching_loopback):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=(
                f"{hidden_process} matching socket(s) have their process name hidden "
                f"(ss run without root), so '{process_filter}' cannot be ruled out"
            ),
            command="ss -tulpnH",
        )

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


class UfwRule(NamedTuple):
    """One row of `ufw status [verbose]`: To / Action [Direction] / From."""

    ports: str  # "22", "8000:9000", "80,443", "any", or an app profile name
    proto: str | None
    action: str  # ALLOW | LIMIT | DENY | REJECT
    direction: str  # IN | OUT | FWD ("IN" when the non-verbose output omits it)
    source: str
    restricted_to: bool  # destination address or interface given in the To column


_UFW_RULE_RE = re.compile(
    r"^(?P<to>.+?)\s+(?P<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?P<dir>IN|OUT|FWD))?\s+(?P<src>.+?)\s*$"
)


def _parse_ufw_rules(out: str) -> list[UfwRule]:
    # Every row that looks like a rule counts, with or without the "To Action From" header:
    # missing a rule here would turn an open port into a false NOT_MET.
    rules: list[UfwRule] = []
    for raw in out.splitlines():
        line = re.sub(r"\s+#.*$", "", raw).rstrip()
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " "} or re.match(r"^To\s+Action\s+From$", stripped):
            continue
        if re.match(r"^(Status|Default|Logging|New profiles):", stripped, re.IGNORECASE):
            continue
        m = _UFW_RULE_RE.match(line.strip())
        if not m:
            continue
        to_clean = m.group("to").replace("(v6)", "").strip()
        restricted = " on " in f" {to_clean} "
        tokens = to_clean.split(" on ")[0].split()
        port_spec = tokens[-1] if tokens else "Anywhere"
        restricted = restricted or len(tokens) > 1
        if port_spec.lower() == "anywhere":
            ports, proto = "any", None
        elif "/" in port_spec:
            ports, proto = port_spec.split("/", 1)
        else:
            ports, proto = port_spec, None
        rules.append(
            UfwRule(
                ports=ports,
                proto=proto.lower() if proto else None,
                action=m.group("action"),
                direction=m.group("dir") or "IN",
                source=m.group("src").replace("(v6)", "").strip(),
                restricted_to=restricted,
            )
        )
    return rules


def _ufw_port_matches(rule_ports: str, port: int) -> bool | None:
    """True/False for numeric ports, lists and ranges; None for app profile names."""
    if rule_ports == "any":
        return True
    saw_name = False
    for item in rule_ports.split(","):
        item = item.strip()
        m_range = re.fullmatch(r"(\d+):(\d+)", item)
        if m_range and int(m_range.group(1)) <= port <= int(m_range.group(2)):
            return True
        if item.isdigit() and int(item) == port:
            return True
        if not m_range and not item.isdigit():
            saw_name = True
    return None if saw_name else False


def _docker_bridge_present(runner: HostRunner) -> bool | None:
    """Docker publishes ports through its own iptables/nft chains, around ufw.
    True/False when `ip` answered (rc 0 / rc 1); None when the check itself could not run."""
    res = runner.run(["ip", "-o", "link", "show", "docker0"])
    if res.transport_error:
        return None
    if res.returncode == 0:
        return True
    return False if res.returncode == 1 else None


_FIREWALLD_SERVICE_PORTS: dict[str, tuple[tuple[int, str], ...]] = {
    "ssh": ((22, "tcp"),),
    "http": ((80, "tcp"),),
    "https": ((443, "tcp"),),
    "dns": ((53, "tcp"), (53, "udp")),
    "ipp": ((631, "tcp"), (631, "udp")),
    "ipp-client": ((631, "udp"),),
    "mdns": ((5353, "udp"),),
    "dhcpv6-client": ((546, "udp"),),
    "samba": ((137, "udp"), (138, "udp"), (139, "tcp"), (445, "tcp")),
    "cockpit": ((9090, "tcp"),),
    "smtp": ((25, "tcp"),),
    "smtps": ((465, "tcp"),),
    "mysql": ((3306, "tcp"),),
    "postgresql": ((5432, "tcp"),),
    "redis": ((6379, "tcp"),),
    "ntp": ((123, "udp"),),
    "ldap": ((389, "tcp"),),
    "ldaps": ((636, "tcp"),),
    "rdp": ((3389, "tcp"), (3389, "udp")),
}


def _try_firewalld_probe(
    pre: Precondition,
    runner: HostRunner,
    port_raw: str,
    proto: str,
) -> ProbeResult | None:
    """Fallback firewall probe using `firewall-cmd` (RHEL / Rocky / Alma / Fedora)."""
    state_res = runner.run(["firewall-cmd", "--state"])
    if state_res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking firewalld: {state_res.stderr.strip()}",
            command="firewall-cmd --state",
        )
    if state_res.returncode == 127:
        return None
    if state_res.returncode != 0 or "running" not in state_res.stdout.lower():
        return None

    cmd_str = "firewall-cmd --list-all"
    list_res = runner.run(["firewall-cmd", "--list-all"])
    if list_res.transport_error or list_res.returncode != 0 or not list_res.stdout.strip():
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=(
                "firewalld is running, but `firewall-cmd --list-all` failed: "
                f"{list_res.stderr.strip() or f'exit {list_res.returncode}'}"
            ),
            command=cmd_str,
        )

    def _unknown(why: str) -> ProbeResult:
        return ProbeResult(precondition=pre, status=ProbeStatus.UNKNOWN, evidence=why, command=cmd_str)

    def _not_met(why: str) -> ProbeResult:
        docker = _docker_bridge_present(runner)
        if docker is None:
            return _unknown(f"{why}, but Docker could not be ruled out (`ip -o link show docker0` did not answer)")
        if docker:
            return _unknown(f"{why}, but Docker is present and its published ports bypass firewalld")
        return ProbeResult(precondition=pre, status=ProbeStatus.NOT_MET, evidence=why, command=cmd_str)

    target = ""
    services: list[str] = []
    ports: list[str] = []
    protocols: list[str] = []
    forward_ports: list[str] = []
    rich_rules: list[str] = []
    in_rich = False
    for raw_line in list_res.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if in_rich:
            if stripped.startswith("rule ") or not re.match(r"^[a-z-]+:", stripped):
                rich_rules.append(stripped)
                continue
            in_rich = False
        if stripped.startswith("target:"):
            target = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("services:"):
            services = [tok for tok in stripped.split(":", 1)[1].split() if tok]
        elif stripped.startswith("ports:"):
            ports = [tok for tok in stripped.split(":", 1)[1].split() if tok]
        elif stripped.startswith("protocols:"):
            protocols = [tok for tok in stripped.split(":", 1)[1].split() if tok]
        elif stripped.startswith("forward-ports:"):
            val = stripped.split(":", 1)[1].strip()
            if val:
                forward_ports.append(val)
        elif stripped.startswith("rich rules:"):
            val = stripped.split(":", 1)[1].strip()
            if val:
                rich_rules.append(val)
            in_rich = True

    if target.upper() == "ACCEPT":
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence="firewalld active zone has target: ACCEPT (incoming traffic allowed)",
            command=cmd_str,
        )
    if target.lower() not in ("default", "drop", "%%reject%%", "reject"):
        return _unknown(f"firewalld active zone has unrecognized target {target!r}")

    if port_raw.lower() != "any":
        if not port_raw.isdigit():
            return _unknown(f"Invalid port parameter {port_raw!r}")
        port = int(port_raw)
        for token in ports:
            if "/" not in token:
                continue
            p_spec, p_proto = token.split("/", 1)
            if p_proto.lower() != proto:
                continue
            m_range = re.fullmatch(r"(\d+)-(\d+)", p_spec)
            if (p_spec.isdigit() and int(p_spec) == port) or (
                m_range and int(m_range.group(1)) <= port <= int(m_range.group(2))
            ):
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"firewalld active zone explicitly allows port {token}",
                    command=cmd_str,
                )
        undecided: list[str] = []
        for svc in services:
            mapped = _FIREWALLD_SERVICE_PORTS.get(svc.lower())
            if mapped is None:
                undecided.append(f"service '{svc}'")
                continue
            if (port, proto) in mapped:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"firewalld active zone allows service '{svc}' ({port}/{proto})",
                    command=cmd_str,
                )
        if rich_rules:
            undecided.append(f"{len(rich_rules)} rich rule(s)")
        if protocols:
            undecided.append(f"protocols ({', '.join(protocols[:3])})")
        if forward_ports:
            undecided.append("forward-ports")
        if undecided:
            return _unknown(
                f"firewalld rules that may allow {port}/{proto} cannot be resolved: {', '.join(undecided[:3])}"
            )
        return _not_met(
            f"firewalld is running (target: {target}) with no open port or service matching {port}/{proto}"
        )

    # port_raw == "any"
    matching_ports = [p for p in ports if p.lower().endswith(f"/{proto}")]
    if matching_ports:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"firewalld active zone allows incoming {proto} port(s): {', '.join(matching_ports[:4])}",
            command=cmd_str,
        )
    matching_svcs = [
        svc
        for svc in services
        if any(sp_proto == proto for _, sp_proto in _FIREWALLD_SERVICE_PORTS.get(svc.lower(), ()))
    ]
    if matching_svcs:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"firewalld active zone allows incoming {proto} service(s): {', '.join(matching_svcs[:4])}",
            command=cmd_str,
        )
    unknown_svcs = [svc for svc in services if svc.lower() not in _FIREWALLD_SERVICE_PORTS]
    if unknown_svcs or rich_rules or protocols or forward_ports:
        return _unknown(
            "firewalld has custom services, protocols, or rich rules that cannot be resolved statically"
        )
    return _not_met(f"firewalld is running (target: {target}) with no incoming {proto} ports or services allowed")


def _nft_dport_matches(spec: str, port: int) -> bool | None:
    """Match an nftables dport expression (`22`, `8000-9000`, `{ 22, 80, 443 }`). None if unresolved."""
    cleaned = spec.strip()
    if not cleaned or cleaned.startswith("@"):
        return None
    if cleaned.startswith("{") and cleaned.endswith("}"):
        items = [x.strip() for x in cleaned[1:-1].split(",") if x.strip()]
    else:
        items = [cleaned]
    if not items:
        return None
    saw_unknown = False
    for item in items:
        m_range = re.fullmatch(r"(\d+)\s*-\s*(\d+)", item)
        if m_range:
            if int(m_range.group(1)) <= port <= int(m_range.group(2)):
                return True
            continue
        if item.isdigit():
            if int(item) == port:
                return True
            continue
        saw_unknown = True
    return None if saw_unknown else False


def _extract_nft_input_chains(ruleset: str) -> list[tuple[str, list[str]]]:
    """Extract `(policy, rule_lines)` for every `type filter hook input` chain in `nft list ruleset`."""
    chains: list[tuple[str, list[str]]] = []
    lines = ruleset.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("chain ") and "{" in line:
            depth = line.count("{") - line.count("}")
            body: list[str] = []
            i += 1
            while i < len(lines) and depth > 0:
                cur = lines[i]
                depth += cur.count("{") - cur.count("}")
                if depth > 0:
                    body.append(cur.strip())
                i += 1
            hook_line = next(
                (b for b in body if re.search(r"\bhook\s+input\b", b)),
                None,
            )
            if hook_line:
                m_pol = re.search(r"\bpolicy\s+(accept|drop|reject)\b", hook_line)
                policy = m_pol.group(1) if m_pol else "accept"
                rules = [b for b in body if b is not hook_line]
                chains.append((policy, rules))
            continue
        i += 1
    return chains


def _try_nftables_probe(
    pre: Precondition,
    runner: HostRunner,
    port_raw: str,
    proto: str,
) -> ProbeResult | None:
    """Fallback firewall probe using `nft list ruleset`."""
    cmd_str = "nft list ruleset"
    res = runner.run(["nft", "list", "ruleset"])
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking nftables: {res.stderr.strip()}",
            command=cmd_str,
        )
    if res.returncode != 0 or not res.stdout.strip():
        return None

    chains = _extract_nft_input_chains(res.stdout)
    if not chains:
        return None

    def _unknown(why: str) -> ProbeResult:
        return ProbeResult(precondition=pre, status=ProbeStatus.UNKNOWN, evidence=why, command=cmd_str)

    def _not_met(why: str) -> ProbeResult:
        docker = _docker_bridge_present(runner)
        if docker is None:
            return _unknown(f"{why}, but Docker could not be ruled out (`ip -o link show docker0` did not answer)")
        if docker:
            return _unknown(f"{why}, but Docker is present and its published ports may bypass input filter rules")
        return ProbeResult(precondition=pre, status=ProbeStatus.NOT_MET, evidence=why, command=cmd_str)

    deny_chains = [(pol, rules) for pol, rules in chains if pol in ("drop", "reject")]
    if not deny_chains:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence="nftables input chain(s) have policy accept (incoming traffic not blocked by default)",
            command=cmd_str,
        )

    if port_raw.lower() != "any" and not port_raw.isdigit():
        return _unknown(f"Invalid port parameter {port_raw!r}")
    port = int(port_raw) if port_raw.isdigit() else None

    undecided: list[str] = []
    for _pol, rules in deny_chains:
        for raw_rule in rules:
            rule = re.sub(r"\s*#.*$", "", raw_rule).strip().rstrip(";")
            if not rule:
                continue
            # Ignore loopback, established/related state, and ICMP-only accept rules.
            if re.search(r'\b(?:iif|iifname)\s+"?lo"?\b', rule):
                continue
            if re.search(r"\bct\s+state\b.*\b(?:established|related)\b", rule) and "new" not in rule.split():
                continue
            if re.search(r"\b(?:icmp|icmpv6|meta\s+l4proto\s+(?:icmp|icmpv6))\b", rule):
                continue
            if re.search(r"\b(?:jump|goto)\b", rule):
                undecided.append(f"non-inline jump/goto ({rule[:48]})")
                continue
            if not re.search(r"\baccept\b", rule):
                continue

            if port is None:
                # port == "any": any non-loopback/non-established accept rule for this proto or generic
                other_proto = "udp" if proto == "tcp" else "tcp"
                if re.search(rf"\b{other_proto}\s+dport\b", rule) and not re.search(rf"\b{proto}\s+dport\b", rule):
                    continue
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence=f"nftables input chain has incoming accept rule: {rule}",
                    command=cmd_str,
                )

            m_dport = re.search(
                r"\b(?P<p>tcp|udp|th)\s+dport\s+(?P<spec>\{[^}]+\}|@\S+|\d+\s*-\s*\d+|\d+)",
                rule,
            )
            if m_dport:
                r_proto = m_dport.group("p")
                if r_proto != "th" and r_proto != proto:
                    continue
                hit = _nft_dport_matches(m_dport.group("spec"), port)
                if hit is None:
                    undecided.append(f"unresolved port set ({rule[:48]})")
                elif hit:
                    if re.search(r"\b(?:ip|ip6)\s+saddr\b|\b(?:iif|iifname)\b", rule):
                        undecided.append(f"source/interface-restricted rule ({rule[:48]})")
                    else:
                        return ProbeResult(
                            precondition=pre,
                            status=ProbeStatus.MET,
                            evidence=f"nftables input chain accepts {port}/{proto}: {rule}",
                            command=cmd_str,
                        )
            else:
                undecided.append(f"broad accept rule ({rule[:48]})")

    if undecided:
        return _unknown(
            f"nftables rules that may allow {port_raw}/{proto} cannot be resolved: {'; '.join(undecided[:3])}"
        )
    return _not_met(
        f"nftables input chain has policy drop/reject with no incoming accept rule for {port_raw}/{proto}"
    )


def _probe_firewall_allows_port(pre: Precondition, runner: HostRunner) -> ProbeResult:
    port_raw = str(pre.params.get("port") or "any").strip()
    proto = str(pre.params.get("proto") or "tcp").lower().strip()
    cmd_str = "ufw status verbose"

    res = runner.run(["ufw", "status", "verbose"])
    if res.transport_error:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Transport error checking firewall: {res.stderr.strip()}",
            command=cmd_str,
        )
    if res.returncode != 0 or not res.stdout.strip():
        # Try non-verbose `ufw status` in case mock or older ufw is used
        res = runner.run(["ufw", "status"])

    def _unknown(why: str) -> ProbeResult:
        return ProbeResult(precondition=pre, status=ProbeStatus.UNKNOWN, evidence=why, command=cmd_str)

    def _not_met(why: str) -> ProbeResult:
        docker = _docker_bridge_present(runner)
        if docker is None:
            return _unknown(f"{why}, but Docker could not be ruled out (`ip -o link show docker0` did not answer)")
        if docker:
            return _unknown(f"{why}, but Docker is present and its published ports bypass ufw")
        return ProbeResult(precondition=pre, status=ProbeStatus.NOT_MET, evidence=why, command=cmd_str)

    if res.returncode == 0 and res.stdout.strip():
        out = res.stdout.strip()
        out_lower = out.lower()
        if "status: inactive" in out_lower:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence="Host firewall (ufw) is inactive; incoming traffic is not blocked by ufw",
                command=cmd_str,
            )
        if "status: active" in out_lower:
            if "allow (incoming)" in out_lower:
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.MET,
                    evidence="ufw is active with 'Default: allow (incoming)'",
                    command=cmd_str,
                )
            default_deny = "deny (incoming)" in out_lower or "reject (incoming)" in out_lower
            allowing = [r for r in _parse_ufw_rules(out) if r.action in ("ALLOW", "LIMIT") and r.direction == "IN"]
            if port_raw.lower() != "any":
                if not port_raw.isdigit():
                    return _unknown(f"Invalid port parameter {port_raw!r}")
                port = int(port_raw)
                undecided: list[str] = []
                for rule in allowing:
                    if rule.proto not in (None, proto):
                        continue
                    hit = _ufw_port_matches(rule.ports, port)
                    if hit is None:
                        undecided.append(f"{rule.ports} (application profile)")
                    elif hit and rule.source.lower() == "anywhere" and not rule.restricted_to:
                        return ProbeResult(
                            precondition=pre,
                            status=ProbeStatus.MET,
                            evidence=f"ufw is active and {rule.action}s {port}/{proto} from Anywhere ({rule.ports})",
                            command=cmd_str,
                        )
                    elif hit:
                        undecided.append(f"{rule.ports} from {rule.source}")
                if undecided:
                    return _unknown(
                        f"ufw rules that may allow {port}/{proto} cannot be resolved: {'; '.join(undecided[:3])}"
                    )
                if default_deny:
                    return _not_met(f"ufw is active with default deny incoming and no ALLOW rule for {port}/{proto}")
            else:
                if allowing:
                    sample = "; ".join(f"{r.ports}/{r.proto or 'any'} from {r.source}" for r in allowing[:3])
                    return ProbeResult(
                        precondition=pre,
                        status=ProbeStatus.MET,
                        evidence=f"ufw is active with incoming ALLOW rule(s): {sample}",
                        command=cmd_str,
                    )
                if default_deny:
                    return _not_met("ufw is active with 'Default: deny (incoming)' and no incoming ALLOW rules")

    # Fallback to firewalld (RHEL/Rocky/Alma/Fedora) and nftables when ufw is unavailable.
    if res.returncode != 0 or not res.stdout.strip():
        fwd_res = _try_firewalld_probe(pre, runner, port_raw, proto)
        if fwd_res is not None:
            return fwd_res
        nft_res = _try_nftables_probe(pre, runner, port_raw, proto)
        if nft_res is not None:
            return nft_res

    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.UNKNOWN,
        evidence=(
            f"Could not verify firewall policy without root privileges "
            f"({res.stderr.strip() or 'ufw, firewalld, and nftables unavailable'})"
        ),
        command=cmd_str,
    )


_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9@_.:\\-]+$")


def _valid_unit_name(name: str) -> bool:
    """systemd unit names only; a leading '-' would be read as an option (e.g. '-H host')."""
    return bool(name) and not name.startswith("-") and bool(_UNIT_NAME_RE.match(name))


def _unit_active(runner: HostRunner, unit: str) -> bool | None:
    """True/False from `systemctl is-active`; None when the check itself could not run."""
    res = runner.run(["systemctl", "is-active", unit])
    if res.transport_error or res.returncode == 127:
        return None
    return res.returncode == 0 and res.stdout.strip().lower() == "active"


def _probe_systemd_service(pre: Precondition, runner: HostRunner) -> ProbeResult:
    service = str(pre.params.get("service") or "").strip()
    if not _valid_unit_name(service):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"Missing or invalid 'service' parameter: {service!r}",
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
    if res.returncode == 4 or "could not be found" in res.stderr.lower():
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"systemd unit '{service}' not found; the daemon may run outside systemd",
            command=cmd_str,
        )
    if state in ("inactive", "failed", "deactivating"):
        load = runner.run(["systemctl", "show", "-p", "LoadState", "--value", service])
        load_state = load.stdout.strip().lower() if not load.transport_error and load.returncode == 0 else ""
        if load_state != "loaded":
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"systemd unit '{service}' is {state} but LoadState is '{load_state or 'unknown'}'",
                command=cmd_str,
            )
        base = service[: -len(".service")] if service.endswith(".service") else service
        socket_unit = f"{base}.socket"
        socket_state = _unit_active(runner, socket_unit)
        if socket_state is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"systemd unit '{service}' is {state}, but '{socket_unit}' could not be checked",
                command=f"systemctl is-active {socket_unit}",
            )
        if socket_state:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"systemd unit '{service}' is {state}, but '{socket_unit}' is active and starts it on demand",
                command=f"systemctl is-active {socket_unit}",
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.NOT_MET,
            evidence=f"systemd unit '{service}' is not active (state='{state}')",
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

    socket_unit = str(pre.params.get("socket_unit") or "").strip()
    if socket_unit:
        if not _valid_unit_name(socket_unit):
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Invalid 'socket_unit' parameter: {socket_unit!r}",
                command=cmd_str,
            )
        socket_state = _unit_active(runner, socket_unit)
        if socket_state is None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.UNKNOWN,
                evidence=f"Process '{proc_name}' is not running, and '{socket_unit}' could not be checked",
                command=f"systemctl is-active {socket_unit}",
            )
        if socket_state:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.MET,
                evidence=f"Process '{proc_name}' is not running now, but '{socket_unit}' is active and starts it on demand",
                command=f"systemctl is-active {socket_unit}",
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

    semantics = str(pre.params.get("semantics") or "").strip().lower()
    directive = str(pre.params.get("directive") or "").strip().lower()
    if semantics == "first" and not re.fullmatch(r"[a-z][a-z0-9]*", directive):
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.UNKNOWN,
            evidence=f"semantics 'first' needs a valid 'directive' parameter, got {directive!r}",
            command="",
        )
    if semantics == "first" and path_str == "/etc/ssh/sshd_config":
        # The effective sshd configuration (includes and Match defaults resolved); needs root.
        eff = runner.run(["sshd", "-T"])
        if not eff.transport_error and eff.returncode == 0 and eff.stdout.strip():
            eff_line = next(
                (ln.strip() for ln in eff.stdout.splitlines() if ln.strip().lower().split(" ", 1)[0] == directive),
                None,
            )
            hit = eff_line if eff_line is not None and regex.search(eff_line) else None
            return _config_result(pre, path_str, pattern, negate, hit, "sshd -T", effective=True)

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
        if not stripped or stripped.startswith(("#", ";")):
            continue
        active_line = stripped.split("#", 1)[0].strip()
        if not active_line:
            continue
        if semantics == "first":
            first_token = active_line.split(None, 1)[0].lower()
            if first_token == "include":
                return ProbeResult(
                    precondition=pre,
                    status=ProbeStatus.UNKNOWN,
                    evidence=(
                        f"'{path_str}' has an Include ('{active_line}') that can set '{directive}' first; "
                        "the effective value needs `sshd -T` (root)"
                    ),
                    command=cmd_str,
                )
            if first_token == "match":
                break  # later directives are conditional, not global
            if first_token != directive:
                continue
            # The first occurrence wins; later ones are ignored by the daemon.
            matched_line = active_line if regex.search(active_line) else None
            break
        if regex.search(active_line):
            matched_line = active_line
            break

    return _config_result(pre, path_str, pattern, negate, matched_line, cmd_str)


def _config_result(
    pre: Precondition,
    path_str: str,
    pattern: str,
    negate: bool,
    matched_line: str | None,
    cmd_str: str,
    effective: bool = False,
) -> ProbeResult:
    where = "the effective sshd configuration" if effective else f"'{path_str}'"
    if negate:
        if matched_line is not None:
            return ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence=f"Mitigating setting active in {where}: '{matched_line}'",
                command=cmd_str,
            )
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Mitigating setting '{pattern}' not found in active lines of {where}",
            command=cmd_str,
        )

    if matched_line is not None:
        return ProbeResult(
            precondition=pre,
            status=ProbeStatus.MET,
            evidence=f"Matched active setting in {where}: '{matched_line}'",
            command=cmd_str,
        )
    return ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence=f"Pattern '{pattern}' not present in active (non-comment) lines of {where}",
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

    cmd = list(WIN_BUILD_ARGV)
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



