"""Launcher decisions, free of web and GCP client code so they can be unit-tested.

Upload protocol (one job per upload):
    jobs/<vendor_id>/<upload_id>/payload.bin     written first
    jobs/<vendor_id>/<upload_id>/manifest.json   written last; its OBJECT_FINALIZE event starts the job
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

JOB_PREFIX_RE = re.compile(r"^jobs/(?P<vendor>[a-z0-9-]{3,32})/(?P<upload>[A-Za-z0-9_-]{6,64})$")
MANIFEST_RE = re.compile(r"^(?P<job>jobs/[a-z0-9-]{3,32}/[A-Za-z0-9_-]{6,64})/manifest\.json$")
MAX_MANIFEST_BYTES = 64 * 1024


class Ignore(Exception):
    """Event is not a job trigger, or is invalid in a way retrying cannot fix. Acknowledge it."""


class Retry(Exception):
    """Transient condition (for example the payload is still uploading). Let Pub/Sub redeliver."""


@dataclass(frozen=True)
class Settings:
    project_id: str
    zone: str
    scan_template: str
    ingest_bucket: str
    results_bucket: str
    workload_identity_provider: str
    sign_key_version: str
    model: str
    max_bundle_bytes: int
    max_scan_seconds: int
    vendors: dict

    @classmethod
    def from_env(cls, env: dict) -> Settings:
        return cls(
            project_id=env["PROJECT_ID"],
            zone=env["ZONE"],
            scan_template=env["SCAN_TEMPLATE"],
            ingest_bucket=env["INGEST_BUCKET"],
            results_bucket=env["RESULTS_BUCKET"],
            workload_identity_provider=env["WORKLOAD_IDENTITY_PROVIDER"],
            sign_key_version=env["SIGN_KEY_VERSION"],
            model=env["MODEL"],
            max_bundle_bytes=int(env["MAX_BUNDLE_BYTES"]),
            max_scan_seconds=int(env["MAX_SCAN_SECONDS"]),
            vendors=json.loads(env.get("VENDORS_JSON", "{}")),
        )


@dataclass(frozen=True)
class Job:
    job_id: str      # jobs/<vendor_id>/<upload_id>
    vendor_id: str
    upload_id: str


def parse_push(envelope: dict, settings: Settings) -> Job:
    """Validate a Pub/Sub push envelope carrying a Cloud Storage notification."""
    msg = envelope.get("message") or {}
    attrs = msg.get("attributes") or {}
    if attrs.get("eventType") != "OBJECT_FINALIZE":
        raise Ignore("not a finalize event")
    if attrs.get("bucketId") != settings.ingest_bucket:
        raise Ignore("event from an unexpected bucket")
    m = MANIFEST_RE.match(attrs.get("objectId", ""))
    if not m:
        raise Ignore("not a manifest object")  # payload.bin and anything else never start a job
    job = job_from_id(m.group("job"))
    if job.vendor_id not in settings.vendors:
        raise Ignore("vendor not registered")

    # Object metadata arrives in the message body (JSON_API_V1); enforce the manifest size limit early.
    if msg.get("data"):
        meta = json.loads(base64.b64decode(msg["data"]))
        if int(meta.get("size", 0)) > MAX_MANIFEST_BYTES:
            raise Ignore("manifest too large")
    return job


def job_from_id(job_id: str) -> Job:
    m = JOB_PREFIX_RE.match(job_id)
    if not m:
        raise Ignore("malformed job id")
    return Job(job_id=job_id, vendor_id=m.group("vendor"), upload_id=m.group("upload"))


def check_payload(size: int | None, settings: Settings) -> None:
    """size is None when payload.bin does not exist yet."""
    if size is None:
        raise Retry("payload not uploaded yet")
    if size <= 0 or size > settings.max_bundle_bytes:
        raise Ignore("payload size outside allowed range")


def instance_name(job: Job) -> str:
    """Deterministic, so a redelivered event cannot start a second VM for the same job."""
    return "caf-job-" + hashlib.sha256(job.job_id.encode()).hexdigest()[:24]


def deployment_config(job: Job, settings: Settings) -> dict:
    """Becomes CAF_DEPLOYMENT. Its value is visible in the attestation token, so relying parties can see it."""
    return {
        "project_id": settings.project_id,
        "workload_identity_provider": settings.workload_identity_provider,
        "ingest_bucket": settings.ingest_bucket,
        "results_bucket": settings.results_bucket,
        "sign_key_version": settings.sign_key_version,
        "model": settings.model,
        "vendor_id": job.vendor_id,
        "vendor_display_name": settings.vendors[job.vendor_id]["display_name"],
    }


def instance_metadata(template_items: list[tuple[str, str]], job: Job, settings: Settings) -> list[tuple[str, str]]:
    """Template metadata plus exactly the two per-job variables the attestation policy allows.

    Instance metadata in an insert request replaces the template's, so the template items are copied in.
    Any tee-env-* already on the template is dropped: per-job values come only from here.
    """
    items = [(k, v) for k, v in template_items if not k.startswith("tee-env-")]
    items += [
        ("tee-env-CAF_JOB_ID", job.job_id),
        ("tee-env-CAF_DEPLOYMENT", json.dumps(deployment_config(job, settings), sort_keys=True, separators=(",", ":"))),
    ]
    return items


def instance_labels(job: Job) -> dict:
    return {"caf-role": "scan", "caf-vendor": job.vendor_id}


def should_sweep(status: str, created: str, now: datetime, max_scan_seconds: int) -> bool:
    """Delete scan VMs that have stopped, or have run past the time limit plus a grace period."""
    if status in {"TERMINATED", "STOPPED", "SUSPENDED"}:
        return True
    started = datetime.fromisoformat(created)
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    return now - started > timedelta(seconds=max_scan_seconds + 900)
