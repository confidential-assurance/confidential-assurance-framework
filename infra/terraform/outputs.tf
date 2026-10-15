output "workload_identity_provider" {
  description = "Audience for the workload's STS exchange."
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool_provider.attestation.name}"
}

output "workload_principal_sets" {
  description = "Principals vendors grant decrypt on their own KMS keys (vendor-key mode)."
  value       = local.workload_principals
}

output "attestation_condition" {
  description = "The exact attestation policy in force. Publish this with each release."
  value       = google_iam_workload_identity_pool_provider.attestation.attribute_condition
}

output "bundle_unwrap_key" {
  value = google_kms_crypto_key.bundle_unwrap.id
}

output "artifact_sign_key" {
  value = google_kms_crypto_key.artifact_sign.id
}

output "ingest_bucket" {
  value = google_storage_bucket.ingest.name
}

output "results_bucket" {
  value = google_storage_bucket.results.name
}
