"""Job entrypoint. One VM, one job, then exit (restart_policy=Never; the VM is torn down by the control plane)."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from google.cloud import storage

from . import analyze, attest, keys, report, scanners, seal
from .events import ErrorCode, Stage, emit

LOCKFILE = Path("/opt/caf/config/components.lock.json")


def run() -> int:
    cfg = attest.config_from_env()
    job_id = cfg["job_id"]
    work = Path(os.environ.get("CAF_WORKDIR", "/dev/shm/caf")) / job_id
    t0 = time.monotonic()
    dek = bytearray()
    emit(job_id, Stage.START)
    try:
        creds = attest.credentials(cfg["workload_identity_provider"])
        token = attest.attestation_token()
        image_digest = attest.claims(token)["submods"]["container"]["image_digest"]
        emit(job_id, Stage.ATTESTED)

        gcs = storage.Client(credentials=creds, project=cfg["project_id"])
        ingest = gcs.bucket(cfg["ingest_bucket"])
        manifest = keys.Manifest.from_json(json.loads(ingest.blob(f"{job_id}/manifest.json").download_as_bytes()))
        payload = ingest.blob(f"{job_id}/payload.bin").download_as_bytes()

        dek = keys.unwrap_dek(manifest, creds)
        emit(job_id, Stage.KEY_RELEASED)

        src = work / "src"
        size = keys.decrypt_bundle(manifest, payload, dek, src, cfg["vendor_id"])
        keys.zeroize(dek)
        emit(job_id, Stage.DECRYPTED, bundle_bytes=size)

        findings, versions = scanners.run_all(src, work)
        emit(job_id, Stage.SCANNED, findings_total=len(findings))

        analysis = analyze.triage(findings, source_context={}, model=cfg["model"])
        emit(job_id, Stage.ANALYZED)

        meta = {"scan_id": job_id, "scanned_at": int(time.time()), "vendor_display_name": cfg["vendor_display_name"],
                "scope_summary": cfg.get("scope_summary", ""), "tool_versions": versions}
        detailed = report.detailed_report(findings, analysis, meta)
        sealed = seal.hpke_seal(manifest.vendor_hpke_public_key, detailed, aad=job_id.encode())
        shareable = report.shareable_report(report.aggregate(findings, analysis), meta)
        sbom, aibom = report.service_boms(LOCKFILE)
        emit(job_id, Stage.SEALED)

        outputs = {"sbom.cdx.json": sbom, "aibom.cdx.json": aibom,
                   "detailed-report.hpke": sealed, "shareable-report.json": shareable}
        prov = seal.provenance(
            outputs,
            inputs={
                "vendor_id": cfg["vendor_id"],
                "ciphertext_sha256": manifest.ciphertext_sha256,
                # Verified after decryption: identifies exactly which code was assessed.
                "plaintext_sha256": manifest.plaintext_sha256,
                "vendor_hpke_public_key_sha256": seal.sha256(manifest.vendor_hpke_public_key),
            },
            workload={"image_digest": image_digest, "lockfile_sha256": seal.sha256(LOCKFILE.read_bytes())},
            attestation_token=token,
        )
        outputs["provenance.intoto.json"] = prov
        signatures = {f"{n}.sig": seal.kms_sign(creds, cfg["sign_key_version"], b) for n, b in outputs.items()}
        emit(job_id, Stage.SIGNED)

        results = gcs.bucket(cfg["results_bucket"])
        for name, blob in {**outputs, **signatures}.items():
            results.blob(f"{job_id}/{name}").upload_from_string(blob)
        # TODO: submit signatures to Rekor via the allow-listed transparency endpoint, store inclusion proofs.
        emit(job_id, Stage.PUBLISHED, duration_ms=int((time.monotonic() - t0) * 1000))
        return 0
    except Exception as exc:  # noqa: BLE001 - any failure must zeroize; never log the exception text: it may contain payload-derived content
        emit(job_id, Stage.FAILED, error=_classify(exc))
        return 1
    finally:
        keys.zeroize(dek)
        shutil.rmtree(work, ignore_errors=True)
        emit(job_id, Stage.ZEROIZED)


def _classify(exc: Exception) -> ErrorCode:
    name = type(exc).__name__.lower()
    if "permission" in name or "forbidden" in name:
        return ErrorCode.KEY_RELEASE
    if isinstance(exc, ValueError):
        return ErrorCode.INTEGRITY
    return ErrorCode.INTERNAL


if __name__ == "__main__":
    sys.exit(run())
