"""caf CLI: keygen | bundle | verify | decrypt"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import bundle, verify


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="caf")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create the X25519 key pair that receives your detailed report")
    k.add_argument("--out", type=Path, default=Path("."))

    b = sub.add_parser("bundle", help="encrypt a source tree for upload")
    b.add_argument("src", type=Path)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--vendor-pub", type=Path, required=True)
    b.add_argument("--operator-pubkey", type=Path, help="published bundle-unwrap public key (operator-key mode)")
    b.add_argument("--kms-key", required=True, help="KMS key version (operator mode) or your own KMS key (vendor mode)")
    b.add_argument("--vendor-kms", action="store_true", help="wrap the DEK with your own Cloud KMS key")

    v = sub.add_parser("verify", help="verify signatures, provenance and attestation of a result set")
    v.add_argument("--results", type=Path, required=True)
    v.add_argument("--signing-pubkey", type=Path, required=True)
    v.add_argument("--expected-digest", action="append", required=True)
    v.add_argument("--hwmodel", default="INTEL_TDX")
    v.add_argument("--no-gpu", action="store_true")

    d = sub.add_parser("decrypt", help="open your detailed report")
    d.add_argument("--results", type=Path, required=True)
    d.add_argument("--key", type=Path, required=True)
    d.add_argument("--job-id", required=True)

    a = p.parse_args(argv)
    if a.cmd == "keygen":
        bundle.generate_vendor_keypair(a.out)
    elif a.cmd == "bundle":
        encrypt_fn = None
        if a.vendor_kms:
            from google.cloud import kms
            client = kms.KeyManagementServiceClient()
            encrypt_fn = lambda dek: client.encrypt(request={"name": a.kms_key, "plaintext": dek}).ciphertext
        bundle.create(a.src, a.out, a.vendor_pub, operator_pubkey_pem=a.operator_pubkey,
                      kms_key=a.kms_key, vendor_kms_encrypt=encrypt_fn)
    elif a.cmd == "verify":
        try:
            info = verify.verify(a.results, a.signing_pubkey, set(a.expected_digest), a.hwmodel, not a.no_gpu)
        except verify.VerificationError as e:
            print(f"FAILED: {e}", file=sys.stderr)
            return 2
        print(json.dumps({"verified": True, **info}, indent=2))
    elif a.cmd == "decrypt":
        sys.stdout.buffer.write(verify.decrypt_detailed(a.results, a.key, a.job_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
