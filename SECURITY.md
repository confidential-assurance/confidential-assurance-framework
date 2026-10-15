# Security policy

The Confidential Assurance Framework (CAF) is security infrastructure: a flaw here can expose vendors' source code. Please report problems
privately and give us time to fix them.

## How to report

- Use GitHub's **private vulnerability reporting** on this repository (Security tab → Report a vulnerability), or
- Email **sec-caf@outlook.com**. Email is not end-to-end encrypted, so for sensitive details prefer private
  vulnerability reporting, or email first and ask for a secure channel.

Please include affected component and version or image digest, reproduction steps, and impact.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | 2 business days |
| Triage and severity (CVSS v4) | 7 days |
| Fix or mitigation for critical/high | 30 days |
| Coordinated disclosure | 90 days maximum, or on fix release if sooner |

We publish a GitHub Security Advisory and CVE for confirmed issues and credit reporters who want credit.

## In scope

- Anything that could expose vendor plaintext, data-encryption keys or the signing key outside the TEE
- Attestation-policy bypasses (keys released to an image or platform that should be rejected)
- Leakage of detailed findings into the shareable report
- Signature or provenance forgery, and verifier bugs that accept invalid artifacts
- Reproducible-build breaks that let a published digest diverge from source

## Out of scope

- Vulnerabilities in CPU or GPU TEE hardware and firmware: report to AMD, Intel or NVIDIA. We will still update
  minimum TCB versions in response.
- Findings produced by a scan (those belong to the scanned vendor)

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and does not touch other users' data is
authorized, and we will not pursue legal action over it.
