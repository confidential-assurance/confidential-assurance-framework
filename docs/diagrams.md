# Diagrams

Mermaid sources render directly on GitHub. The full specification, with detailed figures, is
[`architecture.html`](architecture.html).

## 1. System architecture

The flow starts when a SaaS vendor uploads an encrypted bundle to the ingest bucket. Writing `manifest.json` fires a
Cloud Storage event that starts one scan VM for that upload. Vendor plaintext exists only inside the dashed
Confidential Space box. The control plane moves ciphertext and never holds decrypt or signing rights. KMS releases
the data key only when the attestation token matches the policy in `infra/terraform/wip.tf`.

```mermaid
flowchart TB
    subgraph VENDOR["SaaS vendor"]
        CLI["caf bundle + caf upload<br/>encrypt code + IaC, then upload"]
    end

    subgraph CP["CAF control plane: sees ciphertext only"]
        INGEST[("Ingest bucket<br/>jobs/vendor/upload/")]
        PUBSUB["Pub/Sub<br/>upload event"]
        LAUNCH["Launcher on Cloud Run<br/>validates upload, starts VM"]
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
        RESULTS[("Results bucket<br/>jobs/vendor/upload/")]
        VENDOROUT["SaaS vendor<br/>caf download, verify, decrypt"]
        RP["Customer<br/>caf verify<br/>shareable summary"]
    end

    CLI -->|"payload.bin, then manifest.json"| INGEST
    INGEST -->|"manifest.json finalized"| PUBSUB
    PUBSUB -->|"push"| LAUNCH
    LAUNCH -->|"one VM per upload"| ATTEST
    INGEST -->|"ciphertext"| DECRYPT
    ATTEST -->|"signed token"| WIF
    WIF -->|"only if policy matches"| KMS
    KMS -->|"data key"| DECRYPT
    ATTEST --> DECRYPT --> SCAN --> LLM --> SEAL
    SEAL --> RESULTS
    SEAL -->|"signatures"| REKOR
    RESULTS --> VENDOROUT
    VENDOROUT -->|"shares summary"| RP
    RP -.->|"checks"| REKOR

    style TEE stroke-dasharray: 6 4,stroke-width:2px
```

## 2. One scan, end to end

The blue section is attestation-gated key release: the only way a decryption key can reach the workload.

```mermaid
sequenceDiagram
    autonumber
    actor V as SaaS vendor
    participant B as Ingest bucket
    participant L as Pub/Sub + launcher
    participant W as Confidential workload (TEE)
    participant A as Google Cloud Attestation
    participant K as Cloud KMS (via Workload Identity)
    actor C as Customer

    V->>V: caf bundle: encrypt with fresh DEK, wrap DEK
    V->>B: caf upload: payload.bin, then manifest.json
    B->>L: OBJECT_FINALIZE on manifest.json
    L->>L: Check vendor, path, payload size
    L->>W: Create single-use VM from pinned template
    rect rgba(27, 79, 216, 0.10)
        W->>A: Hardware evidence (TDX, container digest, GPU)
        A-->>W: Signed attestation token (EAT)
        W->>K: Token: request DEK unwrap
        K-->>W: DEK, only if digest + policy match
    end
    W->>B: Read ciphertext
    W->>W: Decrypt to RAM, run scanners + LLM triage
    W->>W: HPKE-seal detailed report to vendor key
    W->>K: Sign SBOM/AIBOM, reports, provenance
    W->>W: Write signed artifacts to results bucket, log to Rekor
    W->>W: Zeroize and exit, VM later deleted by time limit or sweeper
    V->>V: caf download, caf verify, caf decrypt
    V->>C: Share signed summary + SBOM/AIBOM
    C->>C: caf verify: signatures, provenance, attestation claims
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
