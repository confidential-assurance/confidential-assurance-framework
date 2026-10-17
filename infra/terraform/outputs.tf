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

output "launcher_url" {
  description = "Cloud Run launcher (authenticated callers only)."
  value       = google_cloud_run_v2_service.launcher.uri
}

output "ingest_events_topic" {
  value = google_pubsub_topic.ingest_events.id
}

output "dead_letter_subscription" {
  description = "Uploads the launcher could not start a scan for after repeated attempts."
  value       = google_pubsub_subscription.dead_letter_hold.id
}

output "artifact_registry_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.caf.repository_id}"
}

output "signing_public_key_hint" {
  description = "Publish this key's PEM with each release so relying parties need no Google account."
  value       = "gcloud kms keys versions get-public-key 1 --key=artifact-sign --keyring=caf --location=${var.region}"
}
