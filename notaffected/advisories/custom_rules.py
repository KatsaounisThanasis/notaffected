"""Loader and strict schema validator for user-authored YAML CheckSpec rules (`--rules`).

Custom YAML rules let teams encode internal advisories, custom mitigations, or
overrides for built-in specs without modifying Python code. Every rule is
strictly validated against the closed set of 12 read-only probes (`PROBE_TYPES`)
and tagged `source="custom-yaml"`, `os_source="curated"`, `origin="curated"`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from notaffected.advisories.extractor import (
    LINUX_ALLOWED_PROBES,
    PROBE_DEFAULT_JUSTIFICATION,
    PROBE_OPTIONAL_PARAMS,
    PROBE_PARAM_SCHEMA,
    WINDOWS_ALLOWED_PROBES,
    validate_precondition_params,
)
from notaffected.model import (
    PROBE_TYPES,
    CheckSpec,
    PatchInfo,
    Precondition,
    VexJustification,
)

_RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"})
_VALID_OS_FAMILIES = frozenset({"linux", "windows"})
_VALID_CONFIDENCE = frozenset({"high", "low"})
_VALID_PATCH_STATUSES = frozenset({"released", "staged", "unfixed", "unknown"})


def _parse_single_rule(raw: Any, origin_label: str) -> CheckSpec:
    if not isinstance(raw, dict):
        raise ValueError(f"{origin_label}: rule must be a YAML mapping, got {type(raw).__name__}")

    cve_raw = str(raw.get("cve_id") or "").strip().upper()
    if not cve_raw or not _RULE_ID_RE.fullmatch(cve_raw):
        raise ValueError(
            f"{origin_label}: invalid or missing 'cve_id' ({cve_raw!r}); "
            "expected e.g. 'CVE-2026-12345' or an identifier matching [A-Za-z0-9._-]"
        )

    summary = str(raw.get("summary") or "").strip()
    if not summary:
        raise ValueError(f"{origin_label} ({cve_raw}): missing required non-empty 'summary'")

    severity = str(raw.get("severity") or "HIGH").strip().upper()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"{origin_label} ({cve_raw}): invalid 'severity' {severity!r}; "
            f"must be one of {sorted(_VALID_SEVERITIES)}"
        )

    os_family = str(raw.get("os_family") or "linux").strip().lower()
    if os_family not in _VALID_OS_FAMILIES:
        raise ValueError(
            f"{origin_label} ({cve_raw}): invalid 'os_family' {os_family!r}; "
            "must be 'linux' or 'windows'"
        )

    confidence = str(raw.get("confidence") or "high").strip().lower()
    if confidence not in _VALID_CONFIDENCE:
        raise ValueError(
            f"{origin_label} ({cve_raw}): invalid 'confidence' {confidence!r}; "
            "must be 'high' or 'low'"
        )

    raw_pres = raw.get("preconditions")
    if not isinstance(raw_pres, list) or not raw_pres:
        raise ValueError(
            f"{origin_label} ({cve_raw}): 'preconditions' must be a non-empty list"
        )

    allowed_probes = WINDOWS_ALLOWED_PROBES if os_family == "windows" else LINUX_ALLOWED_PROBES
    preconditions: list[Precondition] = []
    for idx, item in enumerate(raw_pres, 1):
        if not isinstance(item, dict):
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} must be a mapping"
            )
        probe_name = str(item.get("probe") or "").strip()
        if probe_name not in PROBE_TYPES:
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} has unsupported probe "
                f"{probe_name!r}; must be one of {sorted(PROBE_TYPES)}"
            )
        if probe_name not in allowed_probes:
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} probe {probe_name!r} "
                f"is not valid for os_family={os_family!r}"
            )
        params = item.get("params")
        if not isinstance(params, dict):
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                "'params' must be a mapping"
            )
        allowed_keys = set(PROBE_PARAM_SCHEMA.get(probe_name, ())) | set(
            PROBE_OPTIONAL_PARAMS.get(probe_name, ())
        )
        unknown_keys = sorted(set(params.keys()) - allowed_keys)
        if unknown_keys:
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                f"has unknown parameter(s) {unknown_keys}; allowed: {sorted(allowed_keys)}"
            )

        for p_key, p_val in params.items():
            if p_key in ("release_fixes", "track_fixes"):
                if not isinstance(p_val, dict) or not all(
                    isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip()
                    for k, v in p_val.items()
                ):
                    raise ValueError(
                        f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                        f"parameter {p_key!r} must be a mapping of non-empty strings"
                    )
            elif p_key == "negate":
                if not isinstance(p_val, bool):
                    raise ValueError(
                        f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                        f"parameter 'negate' must be a boolean, got {type(p_val).__name__}"
                    )
            elif p_val is not None and not isinstance(p_val, (str, int, float, bool)):
                raise ValueError(
                    f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                    f"parameter {p_key!r} must be a scalar value, got {type(p_val).__name__}"
                )

        just_raw = item.get("justification_if_not_met")
        if just_raw is None or str(just_raw).strip() == "":
            justification = PROBE_DEFAULT_JUSTIFICATION[probe_name]
        else:
            try:
                justification = VexJustification(str(just_raw).strip())
            except ValueError as exc:
                valid_vals = [j.value for j in VexJustification]
                raise ValueError(
                    f"{origin_label} ({cve_raw}): precondition #{idx} invalid "
                    f"'justification_if_not_met' {just_raw!r}; must be one of {valid_vals}"
                ) from exc

        desc = str(item.get("description") or "").strip() or f"Check {probe_name}"
        pre = Precondition(
            probe=probe_name,
            params=dict(params),
            description=desc,
            justification_if_not_met=justification,
            origin="curated",
        )
        if not validate_precondition_params(pre):
            req = list(PROBE_PARAM_SCHEMA.get(probe_name, ()))
            raise ValueError(
                f"{origin_label} ({cve_raw}): precondition #{idx} ({probe_name}) "
                f"missing required parameter(s); required: {req}"
            )
        preconditions.append(pre)

    raw_mit = raw.get("mitigation")
    mitigation: list[str] = []
    if raw_mit is not None:
        if not isinstance(raw_mit, list):
            raise ValueError(
                f"{origin_label} ({cve_raw}): 'mitigation' must be a list of strings"
            )
        for m in raw_mit:
            if not isinstance(m, str) or not m.strip():
                raise ValueError(
                    f"{origin_label} ({cve_raw}): every entry in 'mitigation' must be a non-empty string"
                )
            mitigation.append(m.strip())

    raw_patch = raw.get("patch")
    if raw_patch is None:
        patch = PatchInfo(status="unknown")
    else:
        if not isinstance(raw_patch, dict):
            raise ValueError(f"{origin_label} ({cve_raw}): 'patch' must be a mapping")
        p_status = str(raw_patch.get("status") or "unknown").strip().lower()
        if p_status not in _VALID_PATCH_STATUSES:
            raise ValueError(
                f"{origin_label} ({cve_raw}): invalid patch.status {p_status!r}; "
                f"must be one of {sorted(_VALID_PATCH_STATUSES)}"
            )
        patch = PatchInfo(
            status=p_status,
            fixed_version=(
                str(raw_patch["fixed_version"]).strip()
                if raw_patch.get("fixed_version") is not None
                and str(raw_patch["fixed_version"]).strip()
                else None
            ),
            pocket=(
                str(raw_patch["pocket"]).strip()
                if raw_patch.get("pocket") is not None and str(raw_patch["pocket"]).strip()
                else None
            ),
            advisory_url=(
                str(raw_patch["advisory_url"]).strip()
                if raw_patch.get("advisory_url") is not None
                and str(raw_patch["advisory_url"]).strip()
                else None
            ),
        )

    return CheckSpec(
        cve_id=cve_raw,
        summary=summary,
        severity=severity,
        preconditions=preconditions,
        mitigation=mitigation,
        patch=patch,
        confidence=confidence,
        source="custom-yaml",
        os_family=os_family,
        os_source="curated",
    )


def _load_yaml_file(file_path: Path) -> list[CheckSpec]:
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read custom rules file '{file_path}': {exc}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in custom rules file '{file_path}': {exc}") from exc

    if data is None:
        raise ValueError(f"Custom rules file '{file_path}' is empty")

    raw_items: list[Any]
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        if "rules" in data:
            if not isinstance(data["rules"], list) or not data["rules"]:
                raise ValueError(
                    f"'{file_path}': top-level 'rules' must be a non-empty list"
                )
            raw_items = data["rules"]
        else:
            raw_items = [data]
    else:
        raise ValueError(
            f"'{file_path}': expected a YAML mapping or list of rules, got {type(data).__name__}"
        )

    specs: list[CheckSpec] = []
    for idx, item in enumerate(raw_items, 1):
        label = f"{file_path}[#{idx}]" if len(raw_items) > 1 else str(file_path)
        specs.append(_parse_single_rule(item, label))
    return specs


def load_custom_rules(paths: list[Path] | tuple[Path, ...] | None) -> dict[str, CheckSpec]:
    """Load and validate custom CheckSpec rules from one or more YAML files or directories.

    Later files/rules override earlier ones with the same normalized `cve_id`.
    """
    if not paths:
        return {}

    rules: dict[str, CheckSpec] = {}
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ValueError(f"Custom rules path not found: {p}")
        if p.is_dir():
            yaml_files = sorted(
                f for f in p.iterdir() if f.is_file() and f.suffix.lower() in (".yaml", ".yml")
            )
            if not yaml_files:
                raise ValueError(f"Custom rules directory contains no .yaml/.yml files: {p}")
            for yf in yaml_files:
                for spec in _load_yaml_file(yf):
                    rules[spec.cve_id.upper()] = spec
        elif p.is_file():
            for spec in _load_yaml_file(p):
                rules[spec.cve_id.upper()] = spec
        else:
            raise ValueError(f"Custom rules path is neither a file nor a directory: {p}")
    return rules
