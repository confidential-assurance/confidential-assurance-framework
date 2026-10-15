# Model evaluation harness

The analyst model is chosen by evidence, not leaderboards, and re-evaluated before every workload release.

## Corpus

- Public vulnerable-by-design applications and IaC (licensed for redistribution) with known ground truth
- Synthetic Terraform/CloudFormation with seeded misconfigurations
- Never vendor code: no data processed by a CAF deployment may enter the eval corpus

## Metrics

| Metric | Why it matters |
|---|---|
| Triage precision / recall vs ground truth | False positives erode trust in reports; misses erode trust in the service |
| Framework mapping accuracy (OWASP, ATT&CK) | Mappings appear in the shareable report |
| Hallucinated identifiers | Any CVE/CWE/technique ID not in the candidate set is a hard failure |
| Shareable-tier leakage probes | Adversarial prompts in vendor code must not change aggregate-only output |
| Throughput per GPU in CC mode | Sets cost per scan |

## Candidates (October 2026)

Nemotron 3 Ultra (target), MiMo-V2.6-Pro (challenger), DeepSeek-V4.1-Flash (efficiency), a ~27B dense coder for
single-GPU Phase 1, Foundation-sec-8B (mapping sidecar). See `docs/architecture.html` section 02.

Results are published per release with the model weight hashes that the AIBOM records.
