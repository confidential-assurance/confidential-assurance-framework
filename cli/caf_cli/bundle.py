"""Create an encrypted bundle (format caf-bundle/v1). Runs on the vendor's machine; plaintext never leaves it."""

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


def create(src: Path, out_dir: Path, vendor_pub: Path, *, operator_pubkey_pem: Path | None = None,
           kms_key: str, vendor_kms_encrypt=None) -> Path:
    """Encrypt `src` into out_dir/{manifest.json,payload.bin}.

    operator mode: pass operator_pubkey_pem (the published `bundle-unwrap` public key) and its key version name.
    vendor mode:   pass vendor_kms_encrypt, a callable that encrypts the DEK with the vendor's own KMS key.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    plaintext = _tar_gz(src)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = b"caf-bundle/v1"
    payload = AESGCM(dek).encrypt(nonce, plaintext, aad)

    if operator_pubkey_pem is not None:
        pub = serialization.load_pem_public_key(operator_pubkey_pem.read_bytes())
        wrapped = pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        mode = "operator"
    elif vendor_kms_encrypt is not None:
        wrapped = vendor_kms_encrypt(dek)
        mode = "vendor"
    else:
        raise ValueError("choose operator or vendor key mode")

    b64 = lambda b: base64.b64encode(b).decode()
    manifest = {
        "format": "caf-bundle/v1",
        "key_mode": mode,
        "kms_key": kms_key,
        "wrapped_dek": b64(wrapped),
        "nonce": b64(nonce),
        "aad": b64(aad),
        "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "vendor_hpke_public_key": b64(vendor_pub.read_bytes()),
    }
    (out_dir / "payload.bin").write_bytes(payload)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return out_dir
