"""OpenVEX v0.2.0 JSON generator (`https://openvex.dev/ns/v0.2.0`)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from notaffected.model import HostVerdict, VerdictStatus, VexJustification


def build_openvex(
    verdicts: list[HostVerdict],
    author: str = "notaffected",
) -> dict[str, Any]:
    """Build a valid OpenVEX v0.2.0 document from a list of HostVerdicts."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = f"urn:uuid:{uuid.uuid4()}"
    # A document about one host may name the package itself as the product, which is what
    # scanners match (Trivy compares product PURLs). With several hosts that would make one
    # host's statement apply to all of them, so the package becomes a subcomponent of the host.
    # Repeated (CVE, package) pairs mean the "one host" is really several (or the caller merged
    # runs), so those documents keep the host-scoped form too.
    pkg_pairs = [(v.cve_id, v.component_purl) for v in verdicts if v.component_purl]
    single_host = len({v.host for v in verdicts}) == 1 and len(pkg_pairs) == len(set(pkg_pairs))

    statements: list[dict[str, Any]] = []
    for v in verdicts:
        st: dict[str, Any] = {
            "vulnerability": {"name": v.cve_id},
            "timestamp": now_iso,
            "products": [_product(v, single_host)],
            "status": v.status.value,
        }
        if v.status == VerdictStatus.NOT_AFFECTED:
            just = (
                v.justification.value
                if v.justification
                else VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value
            )
            st["justification"] = just
            st["impact_statement"] = f"[{v.host}] {v.reason}"
        elif v.status == VerdictStatus.AFFECTED:
            actions: list[str] = []
            if v.mitigation:
                actions.append("Temporary mitigation: " + " | ".join(v.mitigation))
            if v.patch and v.patch.fixed_version:
                pocket_str = f" ({v.patch.pocket})" if v.patch.pocket else ""
                actions.append(
                    f"Patch status: {v.patch.status} — fixed in {v.patch.fixed_version}{pocket_str}"
                )
            st["action_statement"] = (
                "; ".join(actions)
                if actions
                else f"Host {v.host} is affected ({v.reason}); apply vendor security updates."
            )
        else:
            st["status_notes"] = f"[{v.host}] {v.reason}"

        statements.append(st)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc_id,
        "author": author,
        "timestamp": now_iso,
        "version": 1,
        "statements": statements,
    }


def _product(v: HostVerdict, single_host: bool) -> dict[str, Any]:
    if not v.component_purl:
        return {"@id": v.product_id}
    if single_host:
        return {"@id": v.component_purl}
    return {"@id": v.product_id, "subcomponents": [{"@id": v.component_purl}]}


def write_openvex(
    verdicts: list[HostVerdict],
    path: Path,
    author: str = "notaffected",
) -> dict[str, Any]:
    """Write OpenVEX v0.2.0 JSON to `path` and return the dictionary."""
    doc = build_openvex(verdicts, author=author)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc
