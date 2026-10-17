# Per-vendor access. Each vendor's principals can create objects only under jobs/<vendor_id>/ in the ingest bucket
# and read objects only under jobs/<vendor_id>/ in the results bucket. objectCreator cannot overwrite or delete, so a
# submitted bundle cannot be swapped after upload.

locals {
  vendor_grants = flatten([
    for vendor_id, v in var.vendors : [
      for principal in v.uploaders : {
        key       = "${vendor_id}/${principal}"
        vendor_id = vendor_id
        principal = principal
      }
    ]
  ])
}

resource "google_storage_bucket_iam_member" "vendor_upload" {
  for_each = { for g in local.vendor_grants : g.key => g }
  bucket   = google_storage_bucket.ingest.name
  role     = "roles/storage.objectCreator"
  member   = each.value.principal

  condition {
    title      = "caf-upload-${each.value.vendor_id}"
    expression = "resource.name.startsWith(\"projects/_/buckets/${google_storage_bucket.ingest.name}/objects/jobs/${each.value.vendor_id}/\")"
  }
}

resource "google_storage_bucket_iam_member" "vendor_results" {
  for_each = { for g in local.vendor_grants : g.key => g }
  bucket   = google_storage_bucket.results.name
  role     = "roles/storage.objectViewer"
  member   = each.value.principal

  condition {
    title      = "caf-results-${each.value.vendor_id}"
    expression = "resource.name.startsWith(\"projects/_/buckets/${google_storage_bucket.results.name}/objects/jobs/${each.value.vendor_id}/\")"
  }
}
