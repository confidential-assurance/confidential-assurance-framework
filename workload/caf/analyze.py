"""LLM analysis: triage, reachability reasoning and framework mapping.

The model judges; it does not assert facts. It may change a finding's triage status, add a justification, and
choose framework mappings from candidate lists produced by static crosswalk tables. It may NOT add CVE IDs or
locations: findings it proposes are recorded separately as `model_observations` and labelled as analysis.
"""

from __future__ import annotations

import httpx

from .scanners import Finding

VLLM_URL = "http://127.0.0.1:8000/v1/chat/completions"  # loopback only; vLLM runs in the same TEE


def triage(findings: list[Finding], source_context: dict[str, str], model: str) -> dict:
    """Return {"triage": {finding_id: {...}}, "mappings": {...}, "model_observations": [...]}.

    TODO:
      - batch findings by file; include the minimal code window for each
      - constrain output with a JSON schema (vLLM guided decoding) so the model cannot emit free-form fields
      - validate every returned mapping ID against crosswalk candidates; drop anything else
    """
    result = {"triage": {}, "mappings": {}, "model_observations": []}
    with httpx.Client(timeout=600) as client:
        for f in findings:
            _ = client  # placeholder until prompts and schemas land
            result["mappings"][f.id] = candidate_mappings(f)
    return result


def candidate_mappings(f: Finding) -> dict:
    """Static CWE -> OWASP and CWE -> CAPEC -> ATT&CK candidates.

    TODO: load crosswalk tables (MITRE CWE, CAPEC, ATT&CK STIX bundles; OWASP Top 10 mappings) baked into the image.
    """
    return {"owasp": [], "attack": [], "capec": []}
