"""Deterministic scanners. These own every factual finding (CVE IDs, rule hits, file/line locations).

Each scanner runs as a separate process with no network (the VM has no internet route; the offline databases are
part of the measured image). Outputs are normalized to the findings schema (schemas/findings.schema.json).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

RULES = Path("/opt/caf/rules")
TIMEOUT_S = 1800


@dataclass
class Finding:
    id: str                      # stable hash of (tool, rule, location)
    tool: str
    rule_id: str
    kind: str                    # "cve" | "sast" | "iac" | "secret"
    severity: str                # "critical" | "high" | "medium" | "low" | "info"
    cwe: list[str] = field(default_factory=list)
    cve: str | None = None
    location: dict | None = None  # {"path": ..., "start_line": ..., "end_line": ...}; never leaves the detailed tier
    evidence: dict = field(default_factory=dict)


def _run(cmd: list[str], cwd: Path) -> dict:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=TIMEOUT_S, check=False)
    if proc.returncode not in (0, 1):  # most scanners exit 1 when findings exist
        raise RuntimeError(f"{cmd[0]} failed with exit code {proc.returncode}")
    return json.loads(proc.stdout or b"{}")


def run_all(src: Path, work: Path) -> tuple[list[Finding], dict]:
    """Run every scanner. Returns (findings, tool_versions)."""
    findings: list[Finding] = []
    sbom = work / "vendor-sbom.cdx.json"

    # 1. Inventory, then CVE matching against the inventory.
    subprocess.run(["syft", f"dir:{src}", "-o", f"cyclonedx-json={sbom}", "-q"], check=True, timeout=TIMEOUT_S)
    findings += normalize_grype(_run(["grype", f"sbom:{sbom}", "-o", "json", "--only-fixed=false"], cwd=src))

    # 2. SAST with project-maintained rules only (Semgrep Registry rules are not licensed for this use).
    findings += normalize_opengrep(_run(["opengrep", "scan", "--json", "--config", str(RULES / "code"), "."], cwd=src))

    # 3. IaC: Trivy (Terraform + CloudFormation), Checkov, cfn-nag.
    findings += normalize_trivy(_run(["trivy", "config", "--format", "json", "--offline-scan", "."], cwd=src))
    findings += normalize_checkov(_run(["checkov", "-d", ".", "-o", "json", "--quiet", "--skip-download"], cwd=src))
    findings += normalize_cfn_nag(src)

    return dedupe(findings), tool_versions()


# --- normalizers ------------------------------------------------------------------------------------------
# TODO: implement against each tool's JSON output; map severities onto the shared scale and attach CWE IDs.

def normalize_grype(raw: dict) -> list[Finding]:
    out = []
    for m in raw.get("matches", []):
        v = m.get("vulnerability", {})
        out.append(Finding(
            id="", tool="grype", rule_id=v.get("id", ""), kind="cve",
            severity=(v.get("severity") or "unknown").lower(), cve=v.get("id"),
            evidence={"package": m.get("artifact", {}).get("name"), "version": m.get("artifact", {}).get("version"),
                      "fixed_in": v.get("fix", {}).get("versions", [])},
        ))
    return out


def normalize_opengrep(raw: dict) -> list[Finding]:
    return []  # TODO


def normalize_trivy(raw: dict) -> list[Finding]:
    return []  # TODO


def normalize_checkov(raw: dict) -> list[Finding]:
    return []  # TODO


def normalize_cfn_nag(src: Path) -> list[Finding]:
    return []  # TODO: run cfn_nag_scan over detected CloudFormation templates


def dedupe(findings: list[Finding]) -> list[Finding]:
    return findings  # TODO: merge same CWE + location across tools, keep highest severity, record all tools


def tool_versions() -> dict:
    return {}  # TODO: read from /opt/scanners/VERSIONS.json written by tools/fetch_components.py
