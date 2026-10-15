resource "google_storage_bucket" "ingest" {
  name                        = "${var.project_id}-caf-ingest"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition {
      age = var.ingest_retention_days
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket" "results" {
  name                        = "${var.project_id}-caf-results"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.apis]
}

# The attested workload reads ciphertext and writes artifacts. The control plane gets no object read on ingest
# beyond what signed URLs require, and never holds decrypt rights anywhere.
resource "google_storage_bucket_iam_member" "ingest_read_attested" {
  for_each = toset(local.workload_principals)
  bucket   = google_storage_bucket.ingest.name
  role     = "roles/storage.objectViewer"
  member   = each.value
}

resource "google_storage_bucket_iam_member" "results_write_attested" {
  for_each = toset(local.workload_principals)
  bucket   = google_storage_bucket.results.name
  role     = "roles/storage.objectCreator"
  member   = each.value
}
