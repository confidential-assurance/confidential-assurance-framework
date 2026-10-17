"""Bundle unwrapping and decryption.

Bundle format v2 (see schemas/bundle-manifest.schema.json):
  manifest.json  vendor ID, key mode, KMS key, wrapped DEK, nonce, ciphertext and plaintext digests,
                 vendor HPKE public key
  payload.bin    AES-256-GCM(tar.gz of the vendor's code and IaC), with bundle_aad(...) as associated data

The manifest lives in the operator's bucket, so it is untrusted until decryption succeeds. The associated data is
recomputed here, never read from the manifest, and its vendor ID comes from the job path the launcher passed in.
Changing the vendor key, key mode, KMS key, or moving a bundle to another vendor's prefix makes decryption fail.

Key modes:
  operator  DEK wrapped (RSA-OAEP-4096-SHA256) to the operator's HSM key `bundle-unwrap`
  vendor    DEK encrypted with the vendor's own Cloud KMS key; the vendor granted decrypt to our attested
            principalSet, so the vendor, not the operator, controls the key-release policy
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.cloud import kms

BUNDLE_FORMAT = "caf-bundle/v2"


def bundle_aad(*, key_mode: str, kms_key: str, vendor_id: str, vendor_hpke_public_key: bytes) -> bytes:
    """Must stay byte-for-byte identical to caf_cli.bundle.bundle_aad (a test enforces this)."""
    return json.dumps({
        "format": BUNDLE_FORMAT,
        "key_mode": key_mode,
        "kms_key": kms_key,
        "vendor_id": vendor_id,
        "vendor_hpke_public_key": base64.b64encode(vendor_hpke_public_key).decode(),
    }, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Manifest:
    format: str
    vendor_id: str
    key_mode: str
    kms_key: str
    wrapped_dek: bytes
    nonce: bytes
    ciphertext_sha256: str
    plaintext_sha256: str
    vendor_hpke_public_key: bytes

    @classmethod
    def from_json(cls, d: dict) -> Manifest:
        if d.get("format") != BUNDLE_FORMAT:
            raise ValueError("unsupported bundle format")
        if d["key_mode"] not in ("operator", "vendor"):
            raise ValueError("unknown key_mode")
        b64 = base64.b64decode
        return cls(
            format=d["format"],
            vendor_id=d["vendor_id"],
            key_mode=d["key_mode"],
            kms_key=d["kms_key"],
            wrapped_dek=b64(d["wrapped_dek"]),
            nonce=b64(d["nonce"]),
            ciphertext_sha256=d["ciphertext_sha256"],
            plaintext_sha256=d["plaintext_sha256"],
            vendor_hpke_public_key=b64(d["vendor_hpke_public_key"]),
        )


def unwrap_dek(manifest: Manifest, creds) -> bytearray:
    """Ask KMS to unwrap the DEK. Succeeds only if attestation satisfied the IAM conditions."""
    client = kms.KeyManagementServiceClient(credentials=creds)
    if manifest.key_mode == "operator":
        # kms_key names a key version for asymmetric decrypt.
        resp = client.asymmetric_decrypt(request={"name": manifest.kms_key, "ciphertext": manifest.wrapped_dek})
    else:
        resp = client.decrypt(request={"name": manifest.kms_key, "ciphertext": manifest.wrapped_dek})
    dek = bytearray(resp.plaintext)
    if len(dek) != 32:
        raise ValueError("DEK must be 256 bits")
    return dek


def decrypt_bundle(manifest: Manifest, payload: bytes, dek: bytearray, dest: Path, job_vendor_id: str) -> int:
    """Verify, decrypt and extract to RAM-backed storage. Returns plaintext size in bytes.

    job_vendor_id comes from the job path (jobs/<vendor_id>/...), whose prefix only that vendor can write to.
    """
    if manifest.vendor_id != job_vendor_id:
        raise ValueError("manifest vendor does not match the job path")
    if hashlib.sha256(payload).hexdigest() != manifest.ciphertext_sha256:
        raise ValueError("ciphertext digest mismatch")
    aad = bundle_aad(key_mode=manifest.key_mode, kms_key=manifest.kms_key, vendor_id=job_vendor_id,
                     vendor_hpke_public_key=manifest.vendor_hpke_public_key)
    try:
        plaintext = AESGCM(bytes(dek)).decrypt(manifest.nonce, payload, aad)
    except InvalidTag as e:
        raise ValueError("bundle does not authenticate: manifest fields were changed or the bundle was moved") from e
    if hashlib.sha256(plaintext).hexdigest() != manifest.plaintext_sha256:
        raise ValueError("plaintext digest mismatch")
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as tar:
        # 'data' filter rejects absolute paths, links outside dest, device files, setuid bits.
        tar.extractall(dest, filter="data")
    return len(plaintext)


def zeroize(buf: bytearray) -> None:
    """Best-effort overwrite. Python cannot guarantee no copies exist; the real guarantee is that all memory is
    TEE-encrypted and the VM is destroyed at job end."""
    for i in range(len(buf)):
        buf[i] = 0
