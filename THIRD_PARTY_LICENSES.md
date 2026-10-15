# Third-party components and licenses

CAF does not vendor these components. They are fetched by pinned digest at build time
(`workload/config/components.lock.json`) and recorded in the published SBOM/AIBOM.

Licenses below were checked in October 2026. Re-verify on every version bump; the release workflow fails if a
component's SPDX identifier is not on the allow list.

## Scanners and serving

| Component | Role | License | Notes |
|---|---|---|---|
| Syft | Dependency inventory (SBOM) | Apache-2.0 | |
| Grype | CVE matching | Apache-2.0 | Vulnerability data sources carry their own terms (e.g. GHSA is CC-BY-4.0); attribute in reports |
| Trivy | IaC misconfiguration (Terraform, CloudFormation), secondary CVE matching | Apache-2.0 | Replaces tfsec, which is deprecated and merged into Trivy |
| Checkov | IaC policy checks | Apache-2.0 | |
| cfn-nag | CloudFormation checks | MIT | |
| Opengrep | SAST engine | LGPL-2.1 | Community fork of the Semgrep CE engine. Used as an unmodified separate executable |
| vLLM | Model serving | Apache-2.0 | |
| Sigstore cosign / Rekor | Signing transparency | Apache-2.0 | |

## Rules

| Rule source | Status | Reason |
|---|---|---|
| `rules/` in this repository | **Allowed** | Apache-2.0, project-maintained |
| Semgrep-maintained rules (Semgrep Registry) | **Not allowed** | Semgrep Rules License v1.0 restricts use to internal business purposes and prohibits use in competing products or SaaS offerings |
| Third-party rule repositories | Case by case | Each follows its source repository's license; add to the allow list only after review |

## Models

Model weights are never committed. They are pulled by hash into the measured image or verified at load time,
and the hash is recorded in the AIBOM.

| Model | Role | License | Origin |
|---|---|---|---|
| NVIDIA Nemotron 3 Ultra | Primary analyst (target) | OpenMDW-1.1 | US |
| Cisco Foundation-sec-8B | ATT&CK mapping sidecar | Apache-2.0 | US |
| Xiaomi MiMo-V2.6-Pro | Evaluation challenger | MIT | China |
| DeepSeek-V4.1-Flash | Evaluation candidate | MIT | China |
| Qwen3.8-27B class | Phase 1 single-GPU analyst | Verify per checkpoint | China |

## License allow list (SPDX)

`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `LGPL-2.1-only` (separate executables only),
`MPL-2.0` (unmodified), `OpenMDW-1.1` (model weights only), `CC-BY-4.0` (data only).
