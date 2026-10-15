"""Artifact builders.

The shareable report is rendered from `aggregate()` output only. The template never receives findings, paths,
code or remediation text, so leakage into the public tier is impossible by construction rather than by care.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import jsonschema
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .scanners import Finding

TEMPLATES = Path("/opt/caf/templates")
SCHEMAS = Path("/opt/caf/schemas")


def detailed_report(findings: list[Finding], analysis: dict, meta: dict) -> bytes:
    doc = {
        "format": "caf-detailed/v1",
        "meta": meta,
        "findings": [f.__dict__ for f in findings],
        "analysis": analysis,
    }
    jsonschema.validate(doc, json.loads((SCHEMAS / "findings.schema.json").read_text()))
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def aggregate(findings: list[Finding], analysis: dict) -> dict:
    """The ONLY input to the shareable report: counts, never content."""
    sev = Counter(f.severity for f in findings)
    owasp, attack = Counter(), Counter()
    for f in findings:
        m = analysis.get("mappings", {}).get(f.id, {})
        owasp.update(m.get("owasp", []))
        attack.update(m.get("attack", []))
    return {
        "severity_counts": dict(sev),
        "owasp_categories": dict(owasp),
        "attack_techniques": dict(attack),
        "kinds": dict(Counter(f.kind for f in findings)),
        "total": len(findings),
    }


def shareable_report(agg: dict, meta: dict) -> bytes:
    allowed_meta = {k: meta[k] for k in ("scan_id", "scanned_at", "vendor_display_name", "scope_summary")}
    doc = {"format": "caf-shareable/v1", "meta": allowed_meta, "summary": agg}
    jsonschema.validate(doc, json.loads((SCHEMAS / "shareable-report.schema.json").read_text()))
    env = Environment(loader=FileSystemLoader(TEMPLATES), undefined=StrictUndefined, autoescape=True)
    html = env.get_template("shareable-report.html.j2").render(report=doc)
    return json.dumps({"data": doc, "html": html}, sort_keys=True).encode()


def service_boms(lockfile: Path) -> tuple[bytes, bytes]:
    """SBOM and AIBOM of the scanning service itself, built from the measured lockfile.

    TODO: emit CycloneDX 1.6 (SBOM for components, ML-BOM profile for models with weight hashes,
    quantization and prompt-template hash).
    """
    lock = json.loads(lockfile.read_text())
    return json.dumps({"components": lock["components"]}).encode(), json.dumps({"models": lock["models"]}).encode()
