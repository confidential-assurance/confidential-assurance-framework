"""Bundle unwrapping and decryption.

Bundle format v1 (see schemas/bundle-manifest.schema.json):
  manifest.json  key mode, wrapped DEK, nonce, AAD, ciphertext digest, vendor HPKE public key
  payload.bin    AES-256-GCM(tar.gz of the vendor's code and IaC)

Key modes:
  operator  DEK wrapped (RSA-OAEP-4096-SHA256) to the operator's HSM key `bundle-unwrap`
  vendor    DEK encrypted with the vendor's own Cloud KMS key; the vendor granted decrypt to our attested
            principalSet, so the vendor, not the operator, controls the key-release policy
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.cloud import kms


@dataclass
class Manifest:
    format: str
    key_mode: str
    kms_key: str
    wrapped_dek: bytes
    nonce: bytes
    aad: bytes
    ciphertext_sha256: str
    vendor_hpke_public_key: bytes

    @classmethod
    def from_json(cls, d: dict) -> Manifest:
        if d.get("format") != "caf-bundle/v1":
            raise ValueError("unsupported bundle format")
        if d["key_mode"] not in ("operator", "vendor"):
            raise ValueError("unknown key_mode")
        b64 = base64.b64decode
        return cls(
            format=d["format"],
            key_mode=d["key_mode"],
            kms_key=d["kms_key"],
            wrapped_dek=b64(d["wrapped_dek"]),
            nonce=b64(d["nonce"]),
            aad=b64(d["aad"]),
            ciphertext_sha256=d["ciphertext_sha256"],
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


def decrypt_bundle(manifest: Manifest, payload: bytes, dek: bytearray, dest: Path) -> int:
    """Verify, decrypt and extract to RAM-backed storage. Returns plaintext size in bytes."""
    if hashlib.sha256(payload).hexdigest() != manifest.ciphertext_sha256:
        raise ValueError("ciphertext digest mismatch")
    plaintext = AESGCM(bytes(dek)).decrypt(manifest.nonce, payload, manifest.aad)
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
