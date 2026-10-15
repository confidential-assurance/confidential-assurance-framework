# Contributing to the Confidential Assurance Framework

Thanks for helping. CAF's value depends on people being able to audit exactly what runs inside the
enclave, so contributions are held to a few rules that keep the workload small, reproducible and reviewable.

## Sign-off

All commits must carry a Developer Certificate of Origin sign-off (<https://developercertificate.org/>):

```
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s`. CI rejects unsigned commits. We do not require a CLA.

## Rules for code in `workload/`

Code in `workload/` becomes part of the measured image, so every line is part of the trust argument.

1. **No network egress** beyond Cloud KMS, Cloud Storage, STS and the attestation endpoints.
2. **No logging of payload-derived content.** Log events use the fixed schema in `workload/caf/events.py`.
   Adding a field needs a maintainer review labelled `trust-boundary`.
3. **No new dependency without a pinned digest and an allowed license**
   (see [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)).
4. **Build stays reproducible.** `make reproduce` must produce an identical digest on a clean machine.
5. **Two maintainer approvals** for any change under `workload/` or `infra/terraform/wip.tf`.

## Rules for `rules/`

Rules must be original work or come from a source whose license is on the allow list. Do not copy rules from the
Semgrep Registry. Each rule needs a positive and negative test case under `rules/tests/`.

## Development

```bash
make lint        # ruff, terraform fmt, schema validation
make test        # unit tests (no TEE needed; attestation is mocked)
make reproduce   # rebuild the workload image and print its digest
```

## Reporting security issues

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
