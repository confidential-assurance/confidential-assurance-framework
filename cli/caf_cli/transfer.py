"""Upload an encrypted bundle to the CAF ingest bucket, and download signed results.

Upload order is part of the protocol: payload.bin first, manifest.json last. The manifest's upload event is what
starts the scan, so writing it last guarantees the payload is complete when the job begins.
"""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

from .verify import ARTIFACTS

VENDOR_RE = re.compile(r"^[a-z0-9-]{3,32}$")
UPLOAD_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")


def new_upload_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def job_id(vendor_id: str, upload_id: str) -> str:
    if not VENDOR_RE.match(vendor_id):
        raise ValueError("vendor ID must be 3-32 lowercase letters, digits or hyphens")
    if not UPLOAD_RE.match(upload_id):
        raise ValueError("upload ID must be 6-64 letters, digits, underscores or hyphens")
    return f"jobs/{vendor_id}/{upload_id}"


def upload(bundle_dir: Path, bucket, vendor_id: str, upload_id: str | None = None) -> str:
    """bucket: a google.cloud.storage Bucket (injected so the order can be tested). Returns the job ID."""
    jid = job_id(vendor_id, upload_id or new_upload_id())
    payload, manifest = bundle_dir / "payload.bin", bundle_dir / "manifest.json"
    if not payload.is_file() or not manifest.is_file():
        raise FileNotFoundError("bundle directory must contain payload.bin and manifest.json (run caf bundle)")
    # if_generation_match=0: create only, never overwrite an existing object.
    bucket.blob(f"{jid}/payload.bin").upload_from_filename(str(payload), if_generation_match=0)
    bucket.blob(f"{jid}/manifest.json").upload_from_filename(str(manifest), if_generation_match=0)
    return jid


def download(bucket, jid: str, dest: Path) -> list[str]:
    """Fetch every signed artifact and its signature for a job. Object names are fixed, so no listing is needed."""
    dest.mkdir(parents=True, exist_ok=True)
    names = [n for a in ARTIFACTS for n in (a, f"{a}.sig")]
    for name in names:
        bucket.blob(f"{jid}/{name}").download_to_filename(str(dest / name))
    return names
