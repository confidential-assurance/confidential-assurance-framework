"""Relying-party verification. Needs no access to, or trust in, the CAF operator.

Checks, in order:
  1. every artifact's signature against the published signing public key
  2. provenance subjects match the artifact bytes
  3. the embedded attestation token is signed by Google Cloud Attestation (OIDC JWKS) and its claims match the
     policy you expect: image digest, production image, hardware model, GPU CC mode ON
  4. (TODO) Rekor inclusion proofs for each signature
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ATTESTATION_ISSUER = "https://confidentialcomputing.googleapis.com"
DISCOVERY_URL = ATTESTATION_ISSUER + "/.well-known/openid-configuration"

ARTIFACTS = ["sbom.cdx.json", "aibom.cdx.json", "detailed-report.hpke", "shareable-report.json",
             "provenance.intoto.json"]


class VerificationError(Exception):
    pass


def verify(results: Path, signing_pubkey_pem: Path, expected_digests: set[str],
           expected_hwmodel: str = "INTEL_TDX", require_gpu_cc: bool = True) -> dict:
    pub = serialization.load_pem_public_key(signing_pubkey_pem.read_bytes())
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise VerificationError("signing key must be EC P-384")

    blobs = {}
    for name in ARTIFACTS:
        data = (results / name).read_bytes()
        sig = (results / f"{name}.sig").read_bytes()
        try:
            pub.verify(sig, data, ec.ECDSA(hashes.SHA384()))
        except InvalidSignature as e:
            raise VerificationError(f"bad signature on {name}") from e
        blobs[name] = data

    statement = json.loads(blobs["provenance.intoto.json"])
    for subj in statement["subject"]:
        if hashlib.sha256(blobs[subj["name"]]).hexdigest() != subj["digest"]["sha256"]:
            raise VerificationError(f"provenance digest mismatch for {subj['name']}")

    token = statement["predicate"]["attestation"]["token"]
    claims = _verify_attestation(token)
    _check_policy(claims, expected_digests, expected_hwmodel, require_gpu_cc)
    return {"image_digest": claims["submods"]["container"]["image_digest"], "hwmodel": claims["hwmodel"],
            "artifacts": sorted(blobs)}


def _verify_attestation(token: str) -> dict:
    import httpx

    # Keys come from the issuer's OIDC discovery document, never from the artifact being verified.
    # TODO: allow pinning an offline JWKS snapshot for air-gapped verification.
    jwks_uri = httpx.get(DISCOVERY_URL, timeout=30).raise_for_status().json()["jwks_uri"]
    jwks = jwt.PyJWKClient(jwks_uri)
    key = jwks.get_signing_key_from_jwt(token)
    return jwt.decode(token, key.key, algorithms=["RS256"], issuer=ATTESTATION_ISSUER,
                      options={"verify_aud": False, "verify_exp": False})  # historical tokens are expected to be expired


def _check_policy(c: dict, digests: set[str], hwmodel: str, require_gpu_cc: bool) -> None:
    def need(cond: bool, what: str) -> None:
        if not cond:
            raise VerificationError(f"attestation policy failed: {what}")

    need(c.get("swname") == "CONFIDENTIAL_SPACE", "not Confidential Space")
    need(c.get("dbgstat") == "disabled-since-boot", "debug image")
    need(c.get("hwmodel") == hwmodel, f"hardware model is not {hwmodel}")
    need(c["submods"]["container"]["image_digest"] in digests, "image digest not in expected set")
    if require_gpu_cc:
        need(c["submods"].get("nvidia_gpu", {}).get("cc_mode") == "ON", "GPU confidential computing mode not ON")


def decrypt_detailed(results: Path, vendor_key: Path, job_id: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

    env = json.loads((results / "detailed-report.hpke").read_text())
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    sk = KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(vendor_key.read_bytes()))
    ctx = suite.create_recipient_context(base64.b64decode(env["enc"]), sk, info=b"caf/detailed-report/v1")
    aad = base64.b64decode(env["aad"])
    if aad != job_id.encode():
        raise VerificationError("report was sealed for a different job")
    return ctx.open(base64.b64decode(env["ct"]), aad=aad)
