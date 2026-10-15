# Threat model (summary)

The full model is in `docs/architecture.html` sections 01 and 09.

## Assets

Vendor source and IaC (plaintext); per-bundle data-encryption keys; the artifact-signing key; the integrity of
published artifacts.

## Adversaries and what stops them

| Adversary | Capability | Control |
|---|---|---|
| Operator staff | Full control of the GCP project and control plane | No SSH or console in Confidential Space; keys bound to attested image digest; open, reproducible image |
| Malicious operator release | Ships a modified image | New digest fails the KMS condition; vendor-key mode lets vendors refuse new digests; releases are public and reviewed |
| Cloud provider insider | Hypervisor and host access | TDX / SEV-SNP memory encryption; GPU CC mode; optional independent verification via Intel Trust Authority |
| Malicious vendor input | Prompt injection, zip slip, decompression bombs | Tar `data` filter; size limits; model output constrained to schema; shareable tier rendered from aggregates only |
| Relying-party deception | Forged or altered reports | Attestation-gated signing key; provenance statement; transparency log |
| Open-source supply chain | Compromised dependency or rule | Digest-pinned components; license and checksum gate; two-reviewer rule for `workload/` |

## Explicitly out of scope

Hardware and microcode vulnerabilities in CPU/GPU TEEs (mitigated operationally by minimum-TCB conditions),
side channels, and denial of service by the operator.

## What open-sourcing changes

It strengthens confidentiality claims (anyone can audit and reproduce the image) and does not weaken them: there
are no secrets in the repository. Keys live in HSMs and are released only to attested workloads. Attackers
gain the ability to study the scanner's rules, which matters for evasion; that risk is accepted because the
service attests to what was found, not to what an adversarial vendor could hide.
