"""Attestation-backed Google credentials.

Confidential Space writes an attestation token (an EAT/OIDC JWT signed by Google Cloud Attestation) to a fixed
path inside the container. We hand it to STS through Workload Identity Federation; the pool provider's
attribute condition (infra/terraform/wip.tf) decides whether this exact image on this hardware gets credentials.
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

from google.auth import identity_pool

TOKEN_PATH = Path("/run/container_launcher/attestation_verifier_claims_token")

# Must match the launcher's format and the per-vendor IAM prefixes (infra/terraform/vendors.tf).
JOB_ID_RE = re.compile(r"^jobs/(?P<vendor>[a-z0-9-]{3,32})/(?P<upload>[A-Za-z0-9_-]{6,64})$")


def credentials(workload_identity_provider: str):
    """Return credentials whose principal is the attested principalSet for our image digest.

    workload_identity_provider: '//iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/providers/R'
    """
    if not TOKEN_PATH.exists():
        raise RuntimeError("no attestation token: not running inside Confidential Space")
    info = {
        "type": "external_account",
        "audience": workload_identity_provider,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {"file": str(TOKEN_PATH)},
    }
    return identity_pool.Credentials.from_info(info).with_scopes(
        ["https://www.googleapis.com/auth/cloud-platform"]
    )


def attestation_token() -> str:
    """Raw EAT token, embedded in the provenance statement so relying parties can check the claims themselves."""
    return TOKEN_PATH.read_text().strip()


def config_from_env() -> dict:
    """Per-job configuration from the two launch variables the attestation policy allows.

    CAF_JOB_ID       jobs/<vendor_id>/<upload_id>: object prefix in the ingest and results buckets
    CAF_DEPLOYMENT   JSON set by the launcher: project_id, workload_identity_provider, ingest_bucket,
                     results_bucket, sign_key_version, model, vendor_id, vendor_display_name
    Both values are recorded in the attestation token, so relying parties can see exactly what was configured.
    """
    job_id = os.environ.get("CAF_JOB_ID")
    raw = os.environ.get("CAF_DEPLOYMENT")
    if not job_id or not raw:
        raise RuntimeError("CAF_JOB_ID and CAF_DEPLOYMENT must be set at launch")
    m = JOB_ID_RE.match(job_id)
    if not m:
        raise ValueError("CAF_JOB_ID must look like jobs/<vendor_id>/<upload_id>")
    cfg = json.loads(raw)
    if cfg.get("vendor_id") != m.group("vendor"):
        raise ValueError("CAF_JOB_ID vendor does not match CAF_DEPLOYMENT vendor_id")
    cfg["job_id"] = job_id
    return cfg


def claims(token: str) -> dict:
    """Decode (without verifying) the token payload to read our own measured claims, such as the image digest.
    Verification is the job of STS/IAM and of relying parties, not of the workload itself."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))
