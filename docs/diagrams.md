# Diagrams

Mermaid sources render directly on GitHub. The full specification, with detailed figures, is
[`architecture.html`](architecture.html).

## 1. System architecture

Who holds what. Vendor plaintext exists only inside the dashed Confidential Space box. The control plane moves
ciphertext and never holds decrypt or signing rights. KMS releases the data key only when the attestation token
matches the policy in `infra/terraform/wip.tf`.

```mermaid
flowchart TB
    subgraph VENDOR["Vendor"]
        CLI["caf bundle<br/>encrypt code + IaC on vendor machine"]
    end

    subgraph CP["Operator control plane: sees ciphertext only"]
        INGEST[("Ingest bucket<br/>ciphertext")]
        LAUNCH["Job launcher<br/>one VM per scan"]
    end

    subgraph TEE["Confidential Space VM: TDX + GPU CC, no operator access"]
        ATTEST["Attest<br/>image digest, debug off, GPU CC on"]
        DECRYPT["Decrypt in RAM"]
        SCAN["Scanners<br/>Syft/Grype, Opengrep,<br/>Trivy, Checkov, cfn-nag"]
        LLM["Open-weight LLM<br/>triage, OWASP + ATT&CK"]
        SEAL["Build, seal, sign<br/>SBOM/AIBOM, reports, provenance"]
    end

    subgraph TRUST["Trust services"]
        WIF["Workload Identity<br/>policy in wip.tf"]
        KMS["Cloud KMS (HSM)"]
        REKOR["Rekor<br/>transparency log"]
    end

    subgraph OUT["Recipients"]
        RESULTS[("Results bucket")]
        VENDOROUT["Vendor<br/>caf verify + decrypt<br/>detailed report"]
        RP["Relying party<br/>caf verify<br/>shareable summary"]
    end

    CLI -->|"ciphertext + wrapped key"| INGEST
    LAUNCH -->|"pinned image"| ATTEST
    INGEST --> DECRYPT
    ATTEST -->|"signed token"| WIF
    WIF -->|"only if policy matches"| KMS
    KMS -->|"data key"| DECRYPT
    ATTEST --> DECRYPT --> SCAN --> LLM --> SEAL
    SEAL --> RESULTS
    SEAL -->|"signatures"| REKOR
    RESULTS --> VENDOROUT
    RESULTS --> RP
    RP -.->|"checks"| REKOR

    style TEE stroke-dasharray: 6 4,stroke-width:2px
```

## 2. One scan, end to end

The blue section is attestation-gated key release: the only way a decryption key can reach the workload.

```mermaid
sequenceDiagram
    autonumber
    actor V as Vendor
    participant CP as Control plane
    participant W as Confidential workload (TEE)
    participant A as Google Cloud Attestation
    participant K as Cloud KMS (via Workload Identity)
    participant R as Relying party

    V->>V: caf bundle: encrypt with fresh DEK, wrap DEK
    V->>CP: Upload ciphertext + manifest
    CP->>W: Launch single-use VM from pinned image digest
    rect rgba(27, 79, 216, 0.10)
        W->>A: Hardware evidence (TDX, container digest, GPU)
        A-->>W: Signed attestation token (EAT)
        W->>K: Token: request DEK unwrap
        K-->>W: DEK, only if digest + policy match
    end
    W->>W: Decrypt to RAM, run scanners + LLM triage
    W->>W: HPKE-seal detailed report to vendor key
    W->>K: Sign SBOM/AIBOM, reports, provenance
    W->>CP: Write signed artifacts, log to Rekor
    W->>W: Zeroize, VM terminates
    CP-->>V: Results ready
    V->>V: caf verify, then caf decrypt
    V->>R: Share signed summary + SBOM/AIBOM
    R->>R: caf verify: signatures, provenance, attestation claims
```

## 3. Why open source matters: the reproducible-build trust loop

Anyone can rebuild the workload from source and confirm it is the only image that can obtain keys.

```mermaid
flowchart LR
    REPO["Public repo<br/>workload/ · wip.tf · rules/ · lockfile"] --> CI["Release CI<br/>build twice, digests must match"]
    CI --> DIGEST["Image digest D<br/>cosign-signed · SLSA provenance"]
    DIGEST --> POLICY["KMS key-release policy<br/>image_digest = D"]
    POLICY --> RUN["Confidential Space<br/>attests D, then gets keys"]

    VERIFIER["Independent verifier<br/>vendor · customer · auditor"]
    VERIFIER -. "make reproduce → D′ = D?" .-> REPO
    VERIFIER -. "policy pins D?" .-> POLICY
    VERIFIER -. "attestation shows D?" .-> RUN
```
