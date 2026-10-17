# Control plane

Operator-side services that move ciphertext and start scans. Nothing here sees plaintext or holds KMS rights, so
none of it is part of the measured trust boundary.

## Launcher (`launcher/`)

A Cloud Run service with two endpoints, both callable only by the `caf-invoker` service account:

| Endpoint | Caller | Does |
|---|---|---|
| `POST /events` | Pub/Sub push from the ingest bucket notification | Validates the upload, then creates one Confidential Space VM from the `caf-scan-*` template |
| `POST /sweep` | Cloud Scheduler, every 10 minutes | Deletes scan VMs that have stopped or run past the time limit |

### Upload protocol

```
jobs/<vendor_id>/<upload_id>/payload.bin     write first
jobs/<vendor_id>/<upload_id>/manifest.json   write last: this upload starts the job
```

`caf upload` follows this order. Each vendor's principals can only create objects under their own
`jobs/<vendor_id>/` prefix and cannot overwrite them.

### What the launcher checks

- The event is an `OBJECT_FINALIZE` on the ingest bucket for a `manifest.json` with a well-formed path.
- The vendor ID is registered in Terraform (`var.vendors`).
- `payload.bin` exists and is within `max_bundle_bytes`. If it is still uploading, the launcher returns 503 and
  Pub/Sub redelivers; after 10 attempts the event goes to the dead-letter topic.
- The VM name is derived from the job ID, so a redelivered event cannot start a second VM.

The launcher passes exactly two per-job values to the VM, `CAF_JOB_ID` and `CAF_DEPLOYMENT`. They are the only
launch variables the attestation policy accepts, and both appear in the attestation token.

### Build

```bash
docker build -f control-plane/launcher/Dockerfile -t <region>-docker.pkg.dev/<project>/caf/launcher:<version> .
```
