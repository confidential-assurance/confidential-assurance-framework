"""Create an encrypted bundle (format caf-bundle/v2). Runs on the vendor's machine; plaintext never leaves it.

The manifest fields that decide where results go and who they are attributed to are bound into the payload
encryption as AES-GCM associated data (see bundle_aad). The manifest is stored in the operator's bucket, so
anyone who changes one of those fields there makes the payload fail to decrypt inside the enclave.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .transfer import VENDOR_RE

BUNDLE_FORMAT = "caf-bundle/v2"


def bundle_aad(*, key_mode: str, kms_key: str, vendor_id: str, vendor_hpke_public_key: bytes) -> bytes:
    """Associated data that binds the manifest to the payload.

    Must stay byte-for-byte identical to caf.keys.bundle_aad in the workload (a test enforces this).
    The workload recomputes it from the job path and manifest; it is never read from the manifest.
    """
    return json.dumps({
        "format": BUNDLE_FORMAT,
        "key_mode": key_mode,
        "kms_key": kms_key,
        "vendor_id": vendor_id,
        "vendor_hpke_public_key": base64.b64encode(vendor_hpke_public_key).decode(),
    }, sort_keys=True, separators=(",", ":")).encode()


def generate_vendor_keypair(out_dir: Path) -> None:
    """X25519 key pair for receiving the HPKE-encrypted detailed report. Keep the private key offline."""
    sk = x25519.X25519PrivateKey.generate()
    (out_dir / "vendor-hpke.key").write_bytes(sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    (out_dir / "vendor-hpke.pub").write_bytes(sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    os.chmod(out_dir / "vendor-hpke.key", 0o600)


def _tar_gz(src: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(src, arcname=".", filter=lambda ti: _strip(ti))
    return buf.getvalue()


def _strip(ti: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if ti.issym() or ti.islnk() or ti.isdev():
        return None
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mtime = 0
    return ti


def create(src: Path, out_dir: Path, vendor_pub: Path, *, vendor_id: str, kms_key: str,
           operator_pubkey_pem: Path | None = None, vendor_kms_encrypt=None) -> Path:
    """Encrypt `src` into out_dir/{manifest.json,payload.bin}.

    vendor_id:     your registered vendor ID; the bundle only decrypts when uploaded under jobs/<vendor_id>/.
    operator mode: pass operator_pubkey_pem (the published `bundle-unwrap` public key) and its key version name.
    vendor mode:   pass vendor_kms_encrypt, a callable that encrypts the DEK with the vendor's own KMS key.
    """
    if operator_pubkey_pem is not None:
        mode = "operator"
    elif vendor_kms_encrypt is not None:
        mode = "vendor"
    else:
        raise ValueError("choose operator or vendor key mode")
    if not VENDOR_RE.match(vendor_id):
        raise ValueError("vendor ID must be 3-32 lowercase letters, digits or hyphens")
    vendor_pub_raw = vendor_pub.read_bytes()
    if len(vendor_pub_raw) != 32:
        raise ValueError("vendor public key must be a raw 32-byte X25519 key (from caf keygen)")

    out_dir.mkdir(parents=True, exist_ok=True)
    plaintext = _tar_gz(src)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = bundle_aad(key_mode=mode, kms_key=kms_key, vendor_id=vendor_id, vendor_hpke_public_key=vendor_pub_raw)
    payload = AESGCM(dek).encrypt(nonce, plaintext, aad)

    if mode == "operator":
        pub = serialization.load_pem_public_key(operator_pubkey_pem.read_bytes())
        wrapped = pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    else:
        wrapped = vendor_kms_encrypt(dek)

    b64 = lambda b: base64.b64encode(b).decode()
    manifest = {
        "format": BUNDLE_FORMAT,
        "vendor_id": vendor_id,
        "key_mode": mode,
        "kms_key": kms_key,
        "wrapped_dek": b64(wrapped),
        "nonce": b64(nonce),
        "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "vendor_hpke_public_key": b64(vendor_pub_raw),
    }
    (out_dir / "payload.bin").write_bytes(payload)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return out_dir
