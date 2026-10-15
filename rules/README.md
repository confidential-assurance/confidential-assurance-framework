# CAF rules

Project-maintained detection rules, licensed Apache-2.0 with the rest of the repository.

| Directory | Engine | Scope |
|---|---|---|
| `code/` | Opengrep | Injection, deserialization, crypto misuse, auth flaws in common languages |
| `iac/` | Trivy custom checks (Rego) / Checkov custom policies | Terraform and CloudFormation misconfigurations not covered upstream |
| `tests/` | — | One positive and one negative fixture per rule |

## Licensing rule for contributions

Rules must be your original work or come from a source on the allow list in
[`../THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md). **Do not copy, translate or adapt rules from the Semgrep
Registry**: the Semgrep Rules License v1.0 prohibits use in SaaS offerings, and derived rules would contaminate the
rule pack for every operator.

## Metadata every rule needs

```yaml
metadata:
  cwe: ["CWE-89"]
  owasp: ["A05:2025"]        # candidate only; final mapping is validated in the analysis stage
  confidence: high|medium|low
  references: ["https://cwe.mitre.org/data/definitions/89.html"]
```
