# Verifying CAF assessments

Everything below can be done without contacting, or trusting, the operator that ran the scan.

## 1. Reproduce the workload image digest (once per release)

```bash
git clone https://github.com/confidential-assurance/confidential-assurance-framework && cd confidential-assurance-framework
git checkout v<release> && git verify-tag v<release>
make reproduce            # prints sha256:...
```

The digest must equal the one in the signed release notes. This is the step that makes "the operator cannot see
your code" checkable: the image you just built from audited source is the only image the attestation policy
releases keys to.

## 2. Check the attestation policy in force

The operator publishes the `attestation_condition` Terraform output with each deployment. Compare it with
`infra/terraform/wip.tf` at the release tag. It must require the production Confidential Space image, your
expected hardware model, GPU confidential computing mode ON, and only the published digests.

## 3. Verify a result set

```bash
caf verify --results results/ --signing-pubkey artifact-sign.pem \
                  --expected-digest sha256:<digest from step 1>
```

This checks every signature, that the provenance statement covers exactly these bytes, and that the embedded
attestation token was signed by Google Cloud Attestation with claims that satisfy the policy.

## 4. For vendors: hold your own key (recommended)

Instead of wrapping your bundle key to the operator's KMS key, create a Cloud KMS key in your own project and grant
`roles/cloudkms.cryptoKeyDecrypter` to the operator's `workload_principal_sets` output (one principalSet per
allowed image digest). You then control the key-release policy directly: revoke the grant and no further scan can
decrypt your bundles, whatever the operator does.

```bash
caf keygen --out ~/.caf
caf bundle ./my-repo --out ./upload --vendor-pub ~/.caf/vendor-hpke.pub \
  --vendor-kms --kms-key projects/<you>/locations/<region>/keyRings/<ring>/cryptoKeys/<key>
```

## 5. Decrypt your detailed report

```bash
caf decrypt --results results/ --key ~/.caf/vendor-hpke.key --job-id <job id> > report.json
```
