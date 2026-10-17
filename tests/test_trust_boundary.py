"""Tests for the properties the trust argument depends on. No TEE or cloud access needed."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import jsonschema
import pyhpke
import pytest
from caf import events, keys, report, seal
from caf.scanners import Finding
from caf_cli import bundle, verify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def repo_paths(monkeypatch):
    monkeypatch.setattr(report, "SCHEMAS", ROOT / "schemas")
    monkeypatch.setattr(report, "TEMPLATES", ROOT / "templates")


def _findings() -> list[Finding]:
    return [
        Finding(id="f1", tool="opengrep", rule_id="caf.python.sqli.string-built-query", kind="sast",
                severity="high", cwe=["CWE-89"], location={"path": "app/secret_billing.py", "start_line": 42},
                evidence={"snippet": "cur.execute(f'SELECT * FROM t WHERE id={uid}')"}),
        Finding(id="f2", tool="grype", rule_id="CVE-2024-12345", kind="cve", severity="critical",
                cve="CVE-2024-12345", evidence={"package": "libfoo", "version": "1.0"}),
    ]


def _analysis() -> dict:
    return {"triage": {}, "model_observations": [],
            "mappings": {"f1": {"owasp": ["A05:2025"], "attack": ["T1190"]}, "f2": {"owasp": ["A03:2025"], "attack": []}}}


# --- logging ------------------------------------------------------------------------------------------------

def test_events_reject_fields_outside_schema():
    with pytest.raises(ValueError):
        events.emit("job", events.Stage.SCANNED, file_path=1)


def test_events_reject_non_integer_values():
    with pytest.raises(TypeError):
        events.emit("job", events.Stage.SCANNED, findings_total="app/secret_billing.py")


# --- bundle round trip --------------------------------------------------------------------------------------

def test_bundle_encrypt_then_workload_decrypt(tmp_path):
    src = tmp_path / "repo"
    (src / "app").mkdir(parents=True)
    (src / "app" / "main.py").write_text("print('hello')\n")
    (src / "main.tf").write_text('resource "x" "y" {}\n')

    operator_sk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = tmp_path / "unwrap.pem"
    pem.write_bytes(operator_sk.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
    bundle.generate_vendor_keypair(tmp_path)
    out = bundle.create(src, tmp_path / "upload", tmp_path / "vendor-hpke.pub", vendor_id="acme-saas",
                        operator_pubkey_pem=pem,
                        kms_key="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")

    raw_manifest = json.loads((out / "manifest.json").read_text())
    jsonschema.validate(raw_manifest, json.loads((ROOT / "schemas/bundle-manifest.schema.json").read_text()))
    manifest = keys.Manifest.from_json(raw_manifest)

    # Stand-in for KMS asymmetric_decrypt inside the TEE.
    dek = bytearray(operator_sk.decrypt(manifest.wrapped_dek, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
    dest = tmp_path / "shm"
    keys.decrypt_bundle(manifest, (out / "payload.bin").read_bytes(), dek, dest, "acme-saas")
    assert (dest / "app" / "main.py").read_text() == "print('hello')\n"

    keys.zeroize(dek)
    assert dek == bytearray(32)


def test_tampered_ciphertext_is_rejected(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "k.pem"
    pem.write_bytes(sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    bundle.generate_vendor_keypair(tmp_path)
    out = bundle.create(src, tmp_path / "u", tmp_path / "vendor-hpke.pub", vendor_id="acme-saas",
                        operator_pubkey_pem=pem, kms_key="projects/p/locations/l/keyRings/r/cryptoKeys/k")
    m = keys.Manifest.from_json(json.loads((out / "manifest.json").read_text()))
    payload = bytearray((out / "payload.bin").read_bytes())
    payload[0] ^= 1
    with pytest.raises(ValueError, match="digest"):
        keys.decrypt_bundle(m, bytes(payload), bytearray(32), tmp_path / "d", "acme-saas")


# --- manifest tampering: the bundle must refuse to decrypt -----------------------------------------------------------
# The manifest sits in the operator's bucket, so every field the operator could change to redirect or misattribute
# results is bound into the payload's associated data.

KMS_KEY = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"


def _bundle(tmp_path, vendor_id="acme-saas"):
    src = tmp_path / "repo"
    src.mkdir(exist_ok=True)
    (src / "main.py").write_text("print('hello')\n")
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "unwrap.pem"
    pem.write_bytes(sk.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    bundle.generate_vendor_keypair(tmp_path)
    out = bundle.create(src, tmp_path / "upload", tmp_path / "vendor-hpke.pub", vendor_id=vendor_id,
                        operator_pubkey_pem=pem, kms_key=KMS_KEY)
    raw = json.loads((out / "manifest.json").read_text())
    dek = bytearray(sk.decrypt(base64.b64decode(raw["wrapped_dek"]), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
    return raw, (out / "payload.bin").read_bytes(), dek


def _open(tmp_path, raw, payload, dek, job_vendor="acme-saas"):
    return keys.decrypt_bundle(keys.Manifest.from_json(raw), payload, dek, tmp_path / "shm", job_vendor)


def test_untampered_bundle_decrypts(tmp_path):
    raw, payload, dek = _bundle(tmp_path)
    assert _open(tmp_path, raw, payload, dek) > 0


def test_swapped_report_key_fails_to_decrypt(tmp_path):
    """Attack 1: operator replaces the vendor's public key to receive the detailed report."""
    raw, payload, dek = _bundle(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    bundle.generate_vendor_keypair(attacker)
    raw["vendor_hpke_public_key"] = base64.b64encode((attacker / "vendor-hpke.pub").read_bytes()).decode()
    with pytest.raises(ValueError, match="does not authenticate"):
        _open(tmp_path, raw, payload, dek)


def test_bundle_moved_to_another_vendor_fails(tmp_path):
    """Attack 2: operator copies vendor A's bundle into vendor B's prefix to misattribute the scan."""
    raw, payload, dek = _bundle(tmp_path, vendor_id="acme-saas")
    with pytest.raises(ValueError, match="does not match the job path"):
        _open(tmp_path, raw, payload, dek, job_vendor="other-co")   # manifest left as-is
    raw["vendor_id"] = "other-co"                                    # manifest edited to match the new prefix
    with pytest.raises(ValueError, match="does not authenticate"):
        _open(tmp_path, raw, payload, dek, job_vendor="other-co")


@pytest.mark.parametrize("field, value", [
    ("kms_key", "projects/p/locations/l/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1"),
    ("key_mode", "vendor"),
])
def test_changed_key_fields_fail(tmp_path, field, value):
    raw, payload, dek = _bundle(tmp_path)
    raw[field] = value
    with pytest.raises(ValueError, match="does not authenticate"):
        _open(tmp_path, raw, payload, dek)


def test_plaintext_hash_is_verified(tmp_path):
    raw, payload, dek = _bundle(tmp_path)
    raw["plaintext_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="plaintext digest"):
        _open(tmp_path, raw, payload, dek)
    assert not (tmp_path / "shm").exists()  # nothing unpacked


def test_v1_bundles_are_rejected(tmp_path):
    raw, _, _ = _bundle(tmp_path)
    raw["format"] = "caf-bundle/v1"
    with pytest.raises(ValueError, match="unsupported bundle format"):
        keys.Manifest.from_json(raw)


def test_cli_and_workload_compute_identical_associated_data():
    args = {"key_mode": "operator", "kms_key": KMS_KEY, "vendor_id": "acme-saas", "vendor_hpke_public_key": b"k" * 32}
    assert bundle.bundle_aad(**args) == keys.bundle_aad(**args)
    assert bundle.BUNDLE_FORMAT == keys.BUNDLE_FORMAT


# --- sealing the detailed report ----------------------------------------------------------------------------

def test_detailed_report_only_opens_with_vendor_key(tmp_path):
    bundle.generate_vendor_keypair(tmp_path)
    detailed = report.detailed_report(_findings(), _analysis(), {"scan_id": "job-1"})
    sealed = seal.hpke_seal((tmp_path / "vendor-hpke.pub").read_bytes(), detailed, aad=b"job-1")
    results = tmp_path / "results"
    results.mkdir()
    (results / "detailed-report.hpke").write_bytes(sealed)

    assert verify.decrypt_detailed(results, tmp_path / "vendor-hpke.key", "job-1") == detailed
    with pytest.raises(verify.VerificationError):
        verify.decrypt_detailed(results, tmp_path / "vendor-hpke.key", "job-2")

    other = tmp_path / "other"
    other.mkdir()
    bundle.generate_vendor_keypair(other)
    with pytest.raises(pyhpke.OpenError):
        verify.decrypt_detailed(results, other / "vendor-hpke.key", "job-1")


# --- shareable tier cannot leak -----------------------------------------------------------------------------

def test_shareable_report_contains_no_paths_code_or_rule_text():
    meta = {"scan_id": "job-1", "scanned_at": 0, "vendor_display_name": "Acme", "scope_summary": "2 repos",
            "tool_versions": {"grype": "x"}}
    blob = report.shareable_report(report.aggregate(_findings(), _analysis()), meta).decode()
    for secret in ("secret_billing", "SELECT", "libfoo", "CVE-2024-12345", "sqli", "tool_versions"):
        assert secret not in blob
    assert "T1190" in blob and "A05:2025" in blob


def test_shareable_schema_rejects_extra_fields():
    schema = json.loads((ROOT / "schemas/shareable-report.schema.json").read_text())
    doc = {"format": "caf-shareable/v1",
           "meta": {"scan_id": "j", "scanned_at": 0, "vendor_display_name": "A", "scope_summary": "s"},
           "summary": {"severity_counts": {}, "owasp_categories": {}, "attack_techniques": {}, "kinds": {}, "total": 0,
                       "examples": ["app/secret_billing.py"]}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema)


# --- relying-party verification -----------------------------------------------------------------------------

DIGEST = "sha256:" + "a" * 64
GOOD_CLAIMS = {"swname": "CONFIDENTIAL_SPACE", "dbgstat": "disabled-since-boot", "hwmodel": "INTEL_TDX",
               "submods": {"container": {"image_digest": DIGEST}, "nvidia_gpu": {"cc_mode": "ON"}}}


def _signed_results(tmp_path, claims):
    sk = ec.generate_private_key(ec.SECP384R1())
    pub = tmp_path / "sign.pem"
    pub.write_bytes(sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    outputs = {n: f"content of {n}".encode() for n in verify.ARTIFACTS if n != "provenance.intoto.json"}
    token = "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"
    outputs["provenance.intoto.json"] = seal.provenance(outputs, {}, {"image_digest": DIGEST}, token)
    res = tmp_path / "results"
    res.mkdir()
    for n, b in outputs.items():
        (res / n).write_bytes(b)
        (res / f"{n}.sig").write_bytes(sk.sign(b, ec.ECDSA(hashes.SHA384())))
    return res, pub


@pytest.fixture
def offline_attestation(monkeypatch):
    from caf import attest
    monkeypatch.setattr(verify, "_verify_attestation", attest.claims)  # skip JWKS fetch; policy logic still runs


def test_verify_accepts_valid_results(tmp_path, offline_attestation):
    res, pub = _signed_results(tmp_path, GOOD_CLAIMS)
    assert verify.verify(res, pub, {DIGEST})["image_digest"] == DIGEST


def test_verify_rejects_tampered_artifact(tmp_path, offline_attestation):
    res, pub = _signed_results(tmp_path, GOOD_CLAIMS)
    (res / "shareable-report.json").write_bytes(b"0 findings, trust me")
    with pytest.raises(verify.VerificationError, match="signature"):
        verify.verify(res, pub, {DIGEST})


@pytest.mark.parametrize("patch", [
    {"dbgstat": "enable"},
    {"hwmodel": "GCP_AMD_SEV"},
    {"submods": {"container": {"image_digest": "sha256:" + "b" * 64}, "nvidia_gpu": {"cc_mode": "ON"}}},
    {"submods": {"container": {"image_digest": DIGEST}, "nvidia_gpu": {"cc_mode": "DEVTOOLS"}}},
])
def test_verify_rejects_policy_violations(tmp_path, offline_attestation, patch):
    res, pub = _signed_results(tmp_path, {**GOOD_CLAIMS, **patch})
    with pytest.raises(verify.VerificationError, match="attestation policy"):
        verify.verify(res, pub, {DIGEST})


def test_provenance_binds_every_output():
    outputs = {"a": b"1", "b": b"2"}
    st = json.loads(seal.provenance(outputs, {}, {}, "t"))
    assert {s["name"]: s["digest"]["sha256"] for s in st["subject"]} == {
        n: hashlib.sha256(b).hexdigest() for n, b in outputs.items()}
