# Workload Identity Federation for Confidential Space.
#
# This file IS the attestation policy. A workload can only exchange its attestation token for credentials
# (and therefore only reach KMS) if every condition below holds. Changes require two trust-boundary reviewers.
#
# Claim names follow the Confidential Space attestation assertions reference:
# https://cloud.google.com/confidential-computing/confidential-space/docs/reference/attestation-assertions

locals {
  digest_list = join(", ", [for d in var.allowed_image_digests : "'${d}'"])

  attestation_conditions = compact([
    # Production Confidential Space image, not the debug image.
    "assertion.swname == 'CONFIDENTIAL_SPACE'",
    "assertion.dbgstat == 'disabled-since-boot'",
    "'STABLE' in assertion.submods.confidential_space.support_attributes",

    # Required CPU TEE.
    "assertion.hwmodel == '${var.hardware_model}'",

    # Exactly the published, reproducible workload image, run exactly as built.
    "assertion.submods.container.image_digest in [${local.digest_list}]",
    "size(assertion.submods.container.cmd_override) == 0",
    # Only the two documented launch variables may be overridden (values are visible in the token).
    "assertion.submods.container.env_override.all(k, k in ['CAF_JOB_ID', 'CAF_DEPLOYMENT'])",
    "assertion.submods.container.restart_policy == 'Never'",

    # GPU must be in confidential computing mode (not OFF, not DEVTOOLS).
    var.require_gpu_cc ? "assertion.submods.nvidia_gpu.cc_mode == 'ON'" : "",

    # Only VMs in this project.
    "assertion.submods.gce.project_id == '${var.project_id}'",
  ])
}

resource "google_iam_workload_identity_pool" "scan" {
  workload_identity_pool_id = "caf-attested"
  display_name              = "CAF attested workloads"
  description               = "Confidential Space workloads whose attestation matches the published image."
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "attestation" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.scan.workload_identity_pool_id
  workload_identity_pool_provider_id = "confidential-space"
  display_name                       = "Confidential Space attestation"

  attribute_mapping = {
    "google.subject"         = "\"gcpcs::\" + assertion.submods.container.image_digest + \"::\" + assertion.submods.gce.instance_id"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }

  attribute_condition = join(" && ", local.attestation_conditions)

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }
}

locals {
  # One principalSet per allowed digest. KMS bindings use these, never a service account.
  workload_principals = [
    for d in var.allowed_image_digests :
    "principalSet://iam.googleapis.com/projects/${local.project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.scan.workload_identity_pool_id}/attribute.image_digest/${d}"
  ]
}
