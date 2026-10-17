"""Upload-triggered workflow: CLI upload order, launcher validation, idempotency, and workload job-ID checks."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from caf import attest
from caf_cli import transfer
from caf_launcher import logic

SETTINGS = logic.Settings(
    project_id="p", zone="us-central1-a", scan_template="caf-scan-1", ingest_bucket="p-caf-ingest",
    results_bucket="p-caf-results", workload_identity_provider="//iam.googleapis.com/x", sign_key_version="k/1",
    model="m", max_bundle_bytes=1000, max_scan_seconds=7200, vendors={"acme-saas": {"display_name": "Acme SaaS"}},
)


def envelope(object_id: str, *, event="OBJECT_FINALIZE", bucket="p-caf-ingest", size=500) -> dict:
    data = base64.b64encode(json.dumps({"name": object_id, "size": str(size)}).encode()).decode()
    return {"message": {"attributes": {"eventType": event, "bucketId": bucket, "objectId": object_id}, "data": data}}


# --- CLI upload -----------------------------------------------------------------------------------------------

class FakeBlob:
    def __init__(self, log, name):
        self.log, self.name = log, name

    def upload_from_filename(self, path, if_generation_match=None):
        self.log.append(("upload", self.name, if_generation_match))


class FakeBucket:
    def __init__(self):
        self.log = []

    def blob(self, name):
        return FakeBlob(self.log, name)


def test_upload_writes_payload_before_manifest_and_never_overwrites(tmp_path):
    (tmp_path / "payload.bin").write_bytes(b"ciphertext")
    (tmp_path / "manifest.json").write_text(json.dumps({"vendor_id": "acme-saas"}))
    bucket = FakeBucket()
    jid = transfer.upload(tmp_path, bucket, "acme-saas", "20261017T120000Z-ab12cd34")
    assert jid == "jobs/acme-saas/20261017T120000Z-ab12cd34"
    assert bucket.log == [("upload", f"{jid}/payload.bin", 0), ("upload", f"{jid}/manifest.json", 0)]


def test_upload_refuses_bundle_built_for_another_vendor(tmp_path):
    (tmp_path / "payload.bin").write_bytes(b"ciphertext")
    (tmp_path / "manifest.json").write_text(json.dumps({"vendor_id": "other-co"}))
    bucket = FakeBucket()
    with pytest.raises(ValueError, match="built for vendor"):
        transfer.upload(tmp_path, bucket, "acme-saas", "20261017T120000Z-ab12cd34")
    assert bucket.log == []


def test_upload_rejects_bad_vendor_id(tmp_path):
    with pytest.raises(ValueError):
        transfer.job_id("Acme/../x", "20261017T120000Z")


def test_generated_job_ids_are_accepted_by_launcher_and_workload():
    jid = transfer.job_id("acme-saas", transfer.new_upload_id())
    assert logic.job_from_id(jid).vendor_id == "acme-saas"
    assert attest.JOB_ID_RE.match(jid)


# --- launcher: which events start a job ------------------------------------------------------------------------

def test_manifest_finalize_starts_job():
    job = logic.parse_push(envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json"), SETTINGS)
    assert (job.vendor_id, job.upload_id) == ("acme-saas", "20261017T120000Z-ab12")


@pytest.mark.parametrize("env", [
    envelope("jobs/acme-saas/20261017T120000Z-ab12/payload.bin"),             # payload never triggers
    envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json", event="OBJECT_DELETE"),
    envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json", bucket="other-bucket"),
    envelope("jobs/unknown-co/20261017T120000Z-ab12/manifest.json"),          # vendor not registered
    envelope("jobs/acme-saas/../x/manifest.json"),                            # path tricks
    envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json", size=10**6),  # oversized manifest
    {},
])
def test_non_trigger_events_are_ignored(env):
    with pytest.raises(logic.Ignore):
        logic.parse_push(env, SETTINGS)


def test_missing_payload_is_retried_and_oversized_payload_ignored():
    with pytest.raises(logic.Retry):
        logic.check_payload(None, SETTINGS)
    with pytest.raises(logic.Ignore):
        logic.check_payload(SETTINGS.max_bundle_bytes + 1, SETTINGS)
    logic.check_payload(500, SETTINGS)


# --- launcher: the VM it requests ------------------------------------------------------------------------------

def test_instance_name_is_deterministic_and_valid():
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    name = logic.instance_name(job)
    assert name == logic.instance_name(job)
    assert name != logic.instance_name(logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab13"))
    assert len(name) <= 63 and name[0].isalpha() and name == name.lower()


def test_metadata_keeps_template_and_adds_only_the_two_allowed_variables():
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    template = [("tee-image-reference", "img@sha256:abc"), ("tee-restart-policy", "Never"),
                ("tee-env-SNEAKY", "from-template")]
    items = dict(logic.instance_metadata(template, job, SETTINGS))
    assert items["tee-image-reference"] == "img@sha256:abc"
    assert {k for k in items if k.startswith("tee-env-")} == {"tee-env-CAF_JOB_ID", "tee-env-CAF_DEPLOYMENT"}
    deployment = json.loads(items["tee-env-CAF_DEPLOYMENT"])
    assert deployment["vendor_id"] == "acme-saas" and deployment["vendor_display_name"] == "Acme SaaS"


def test_workload_accepts_launcher_config(monkeypatch):
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    items = dict(logic.instance_metadata([], job, SETTINGS))
    monkeypatch.setenv("CAF_JOB_ID", items["tee-env-CAF_JOB_ID"])
    monkeypatch.setenv("CAF_DEPLOYMENT", items["tee-env-CAF_DEPLOYMENT"])
    assert attest.config_from_env()["job_id"] == job.job_id


def test_workload_rejects_vendor_mismatch(monkeypatch):
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    deployment = json.loads(dict(logic.instance_metadata([], job, SETTINGS))["tee-env-CAF_DEPLOYMENT"])
    deployment["vendor_id"] = "other-co"
    monkeypatch.setenv("CAF_JOB_ID", job.job_id)
    monkeypatch.setenv("CAF_DEPLOYMENT", json.dumps(deployment))
    with pytest.raises(ValueError, match="vendor"):
        attest.config_from_env()


# --- sweeper -----------------------------------------------------------------------------------------------------

def test_sweep_deletes_stopped_and_overdue_vms_only():
    now = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
    fresh = (now - timedelta(minutes=10)).isoformat()
    overdue = (now - timedelta(seconds=SETTINGS.max_scan_seconds + 901)).isoformat()
    assert logic.should_sweep("TERMINATED", fresh, now, SETTINGS.max_scan_seconds)
    assert logic.should_sweep("RUNNING", overdue, now, SETTINGS.max_scan_seconds)
    assert not logic.should_sweep("RUNNING", fresh, now, SETTINGS.max_scan_seconds)


# --- web layer: status codes Pub/Sub depends on -------------------------------------------------------------------

class FakeLauncher:
    def __init__(self, outcome):
        self.s, self.outcome, self.launched = SETTINGS, outcome, []

    def launch(self, job):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        self.launched.append(job.job_id)
        return "caf-job-x"


@pytest.mark.parametrize("body, outcome, status, launched", [
    (envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json"), None, 204, 1),
    (envelope("jobs/acme-saas/20261017T120000Z-ab12/payload.bin"), None, 204, 0),
    (envelope("jobs/acme-saas/20261017T120000Z-ab12/manifest.json"), logic.Retry("payload not uploaded yet"), 503, 0),
])
def test_events_endpoint_status_codes(monkeypatch, body, outcome, status, launched):
    from caf_launcher import app as app_module
    fake = FakeLauncher(outcome)
    monkeypatch.setattr(app_module, "_launcher", fake)
    resp = app_module.app.test_client().post("/events", json=body)
    assert resp.status_code == status
    assert len(fake.launched) == launched


# --- GCP adapter against auto-specced clients (catches wrong client call signatures) -------------------------------

def _real_clients():
    from google.cloud import compute_v1, storage
    # Captured once at import: tests below monkeypatch these module attributes.
    return {"instances": compute_v1.InstancesClient, "templates": compute_v1.InstanceTemplatesClient,
            "storage": storage.Client}


REAL_CLIENTS = _real_clients()

def make_launcher(monkeypatch, payload_size=500, insert_error=None, instances=()):
    from unittest import mock

    from caf_launcher import gcp
    from google.cloud import compute_v1

    inst_client = mock.create_autospec(REAL_CLIENTS["instances"], instance=True)
    tpl_client = mock.create_autospec(REAL_CLIENTS["templates"], instance=True)
    gcs_client = mock.create_autospec(REAL_CLIENTS["storage"], instance=True)
    tpl_client.get.return_value = compute_v1.InstanceTemplate(properties=compute_v1.InstanceProperties(
        metadata=compute_v1.Metadata(items=[compute_v1.Items(key="tee-image-reference", value="img@sha256:abc")])))
    blob = None if payload_size is None else mock.Mock(size=payload_size)
    gcs_client.bucket.return_value.get_blob.return_value = blob
    if insert_error:
        inst_client.insert.side_effect = insert_error
    inst_client.list.return_value = list(instances)
    monkeypatch.setattr(gcp.compute_v1, "InstancesClient", lambda: inst_client)
    monkeypatch.setattr(gcp.compute_v1, "InstanceTemplatesClient", lambda: tpl_client)
    monkeypatch.setattr(gcp.storage, "Client", lambda project: gcs_client)
    return gcp.Launcher(SETTINGS), inst_client


def test_launch_builds_a_valid_insert_request(monkeypatch):
    launcher, inst_client = make_launcher(monkeypatch)
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    assert launcher.launch(job) == logic.instance_name(job)
    req = inst_client.insert.call_args.kwargs["request"]
    assert req.source_instance_template.endswith("/instanceTemplates/caf-scan-1")
    keys = {i.key for i in req.instance_resource.metadata.items}
    assert {"tee-image-reference", "tee-env-CAF_JOB_ID", "tee-env-CAF_DEPLOYMENT"} <= keys
    assert req.instance_resource.labels["caf-role"] == "scan"


def test_launch_treats_existing_vm_as_success_and_quota_errors_as_retry(monkeypatch):
    from google.api_core import exceptions as gexc
    job = logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12")
    launcher, _ = make_launcher(monkeypatch, insert_error=gexc.Conflict("exists"))
    assert launcher.launch(job) == logic.instance_name(job)
    launcher, _ = make_launcher(monkeypatch, insert_error=gexc.TooManyRequests("quota"))
    with pytest.raises(logic.Retry):
        launcher.launch(job)


def test_launch_waits_for_payload(monkeypatch):
    launcher, inst_client = make_launcher(monkeypatch, payload_size=None)
    with pytest.raises(logic.Retry):
        launcher.launch(logic.job_from_id("jobs/acme-saas/20261017T120000Z-ab12"))
    inst_client.insert.assert_not_called()


def test_sweep_lists_with_label_filter_and_deletes_finished(monkeypatch):
    from google.cloud import compute_v1
    done = compute_v1.Instance(name="caf-job-done", status="TERMINATED",
                               creation_timestamp=datetime.now(UTC).isoformat())
    running = compute_v1.Instance(name="caf-job-run", status="RUNNING",
                                  creation_timestamp=datetime.now(UTC).isoformat())
    launcher, inst_client = make_launcher(monkeypatch, instances=[done, running])
    assert launcher.sweep() == ["caf-job-done"]
    assert inst_client.list.call_args.kwargs["request"].filter == "labels.caf-role = scan"
