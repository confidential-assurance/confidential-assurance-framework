"""Seal and sign outputs.

- Detailed report: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM,
  to the vendor public key from the bundle manifest. The operator stores the result but cannot open it.
- Signatures: Cloud KMS asymmetric sign (EC P-384 / SHA-384, HSM) with a key only attested workloads can use.
- Provenance: in-toto Statement v1 binding inputs, workload digest, model hashes and outputs.
"""

from __future__ import annotations

import base64
import hashlib
import json

from google.cloud import kms
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
HPKE_INFO = b"caf/detailed-report/v1"


def hpke_seal(vendor_public_key_raw: bytes, plaintext: bytes, aad: bytes) -> bytes:
    pk = KEMKey.from_pyca_cryptography_key(_x25519_public(vendor_public_key_raw))
    enc, ctx = SUITE.create_sender_context(pk, info=HPKE_INFO)
    ct = ctx.seal(plaintext, aad=aad)
    return json.dumps({"enc": base64.b64encode(enc).decode(), "aad": base64.b64encode(aad).decode(),
                       "ct": base64.b64encode(ct).decode(), "suite": "X25519-HKDF-SHA256/AES-256-GCM"}).encode()


def _x25519_public(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(raw)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kms_sign(creds, key_version: str, data: bytes) -> bytes:
    client = kms.KeyManagementServiceClient(credentials=creds)
    digest = hashlib.sha384(data).digest()
    return client.asymmetric_sign(request={"name": key_version, "digest": {"sha384": digest}}).signature


def provenance(outputs: dict[str, bytes], inputs: dict[str, str], workload: dict, attestation_token: str) -> bytes:
    """in-toto Statement v1 with a CAF assessment predicate."""
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": sha256(blob)}} for name, blob in sorted(outputs.items())],
        "predicateType": "urn:caf:predicate:assessment:v1",
        "predicate": {
            "inputs": inputs,            # bundle ciphertext + plaintext digests
            "workload": workload,        # image digest, component lock digest, model weight hashes, rule pack hash
            "attestation": {"format": "eat+jwt", "token": attestation_token},
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
