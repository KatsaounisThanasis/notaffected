"""Live per-host patch availability tracker using `apt-cache policy <package>`.

When a host is AFFECTED (or UNDER_INVESTIGATION), this checks whether the
fixed package version has already arrived in the host's configured apt
repositories (and which pocket, e.g. `noble-security` vs `noble-proposed`).
"""

from __future__ import annotations

import re

from notaffected.model import CheckSpec, PatchInfo
from notaffected.probes.primitives import _resolve_host_release_fix
from notaffected.probes.runner import HostRunner


def resolve_host_patch_info(spec: CheckSpec, runner: HostRunner) -> PatchInfo:
    """Inspect `apt-cache policy` on `runner` to see if the fix for `spec` is ready in apt."""
    base_patch = spec.patch
    if getattr(runner, "os_family", "linux").lower() != "linux":
        return base_patch
    fixed_ver = (base_patch.fixed_version or "").strip()

    target_pkg: str | None = None
    release_fixes: object = None
    for pre in spec.preconditions:
        if pre.probe == "package_installed_vulnerable":
            target_pkg = str(pre.params.get("package") or "").strip() or None
            if not fixed_ver and pre.params.get("fixed_version"):
                fixed_ver = str(pre.params["fixed_version"]).strip()
            release_fixes = pre.params.get("release_fixes")
            break
        if pre.probe == "kernel_version_vulnerable":
            target_pkg = "linux-image-generic"
            if not fixed_ver and pre.params.get("fixed_version"):
                fixed_ver = str(pre.params["fixed_version"]).strip()
            break

    if not target_pkg or not fixed_ver:
        return base_patch

    fixed_ver = _resolve_host_release_fix(runner, release_fixes, "", fixed_ver)

    res = runner.run(["apt-cache", "policy", target_pkg])
    if res.transport_error or res.returncode != 0 or not res.stdout.strip():
        src_res = runner.run(
            [
                "dpkg-query",
                "-W",
                "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n",
            ]
        )
        if not src_res.transport_error and src_res.returncode == 0 and src_res.stdout:
            for sline in src_res.stdout.splitlines():
                sparts = sline.split("\t")
                if len(sparts) >= 3 and sparts[0].strip().startswith("ii"):
                    bin_name = sparts[1].strip().split(":")[0]
                    src_name = sparts[2].strip().split(" ")[0]
                    if src_name == target_pkg:
                        res = runner.run(["apt-cache", "policy", bin_name])
                        if not res.transport_error and res.returncode == 0 and res.stdout.strip():
                            break
    if res.transport_error or res.returncode != 0 or not res.stdout.strip():
        return base_patch

    candidate_ver: str | None = None
    for line in res.stdout.splitlines():
        cand_match = re.match(r"^\s*Candidate:\s*(\S+)", line)
        if cand_match:
            val = cand_match.group(1).strip()
            if val and val != "(none)":
                candidate_ver = val
            break

    if not candidate_ver:
        return base_patch

    detected_pocket: str | None = None
    fallback_pocket: str | None = None
    in_candidate_stanza = False
    for line in res.stdout.splitlines():
        ver_header = re.match(r"^\s*(?:\*\*\*\s+)?(\S+)\s+\d+\s*$", line)
        if ver_header:
            in_candidate_stanza = ver_header.group(1) == candidate_ver
            continue
        pocket_match = re.search(
            r"\b([a-z]+-(?:security|updates|proposed|backports))\b",
            line,
            re.IGNORECASE,
        )
        if pocket_match:
            if not fallback_pocket:
                fallback_pocket = pocket_match.group(1)
            if in_candidate_stanza and not detected_pocket:
                detected_pocket = pocket_match.group(1)

    detected_pocket = detected_pocket or fallback_pocket

    cmp_res = runner.run(["dpkg", "--compare-versions", candidate_ver, "ge", fixed_ver])
    if cmp_res.transport_error or cmp_res.returncode not in (0, 1):
        return base_patch

    pocket_final = detected_pocket or base_patch.pocket
    if cmp_res.returncode == 0:
        return PatchInfo(
            status=f"available-in-apt (candidate {candidate_ver})",
            fixed_version=fixed_ver,
            pocket=pocket_final,
            advisory_url=base_patch.advisory_url,
        )

    return PatchInfo(
        status=f"not-yet-in-apt (candidate {candidate_ver} < {fixed_ver})",
        fixed_version=fixed_ver,
        pocket=base_patch.pocket,
        advisory_url=base_patch.advisory_url,
    )
