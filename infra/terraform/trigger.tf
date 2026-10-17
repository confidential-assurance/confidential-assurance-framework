# Upload-triggered workflow:
#   vendor writes jobs/<vendor_id>/<upload_id>/manifest.json (last, after payload.bin)
#   -> Cloud Storage notification (OBJECT_FINALIZE) -> Pub/Sub topic
#   -> push subscription -> Cloud Run launcher -> one Confidential Space VM per job
#
# The launcher is control plane: it sees object names and sizes, never plaintext, and holds no KMS rights.

# ---- service accounts -------------------------------------------------------------------------------------

resource "google_service_account" "launcher" {
  account_id   = "caf-launcher"
  display_name = "CAF launcher (control plane)"
}

resource "google_service_account" "invoker" {
  account_id   = "caf-invoker"
  display_name = "CAF Pub/Sub and Scheduler invoker"
}

# Launcher: create and delete scan VMs, read the template, start VMs as the workload SA, and read ingest object
# metadata (ciphertext only). TODO: replace compute.instanceAdmin.v1 with a custom role scoped to these actions.
resource "google_project_iam_member" "launcher_compute" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.launcher.email}"
}

resource "google_service_account_iam_member" "launcher_can_use_workload_sa" {
  service_account_id = google_service_account.workload_vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.launcher.email}"
}

resource "google_storage_bucket_iam_member" "launcher_ingest_read" {
  bucket = google_storage_bucket.ingest.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.launcher.email}"
}

resource "google_project_iam_member" "launcher_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.launcher.email}"
}

# ---- storage -> pub/sub -----------------------------------------------------------------------------------

resource "google_pubsub_topic" "ingest_events" {
  name       = "caf-ingest-events"
  depends_on = [google_project_service.apis]
}

resource "google_pubsub_topic" "ingest_dead_letter" {
  name       = "caf-ingest-dead-letter"
  depends_on = [google_project_service.apis]
}

data "google_storage_project_service_account" "gcs" {}

resource "google_pubsub_topic_iam_member" "gcs_can_publish" {
  topic  = google_pubsub_topic.ingest_events.id
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_storage_notification" "ingest_finalize" {
  bucket             = google_storage_bucket.ingest.name
  topic              = google_pubsub_topic.ingest_events.id
  payload_format     = "JSON_API_V1"
  event_types        = ["OBJECT_FINALIZE"]
  object_name_prefix = "jobs/"
  depends_on         = [google_pubsub_topic_iam_member.gcs_can_publish]
}

# ---- launcher service -------------------------------------------------------------------------------------

locals {
  scan_template = google_compute_instance_template.scan.name

  launcher_env = {
    PROJECT_ID                 = var.project_id
    ZONE                       = var.zone
    SCAN_TEMPLATE              = local.scan_template
    INGEST_BUCKET              = google_storage_bucket.ingest.name
    RESULTS_BUCKET             = google_storage_bucket.results.name
    WORKLOAD_IDENTITY_PROVIDER = "//iam.googleapis.com/${google_iam_workload_identity_pool_provider.attestation.name}"
    SIGN_KEY_VERSION           = "${google_kms_crypto_key.artifact_sign.id}/cryptoKeyVersions/1"
    MODEL                      = var.model
    MAX_BUNDLE_BYTES           = tostring(var.max_bundle_bytes)
    MAX_SCAN_SECONDS           = tostring(var.max_scan_seconds)
    VENDORS_JSON               = jsonencode({ for k, v in var.vendors : k => { display_name = v.display_name } })
  }
}

resource "google_cloud_run_v2_service" "launcher" {
  name     = "caf-launcher"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # authenticated callers only: no allUsers invoker binding exists

  template {
    service_account                  = google_service_account.launcher.email
    max_instance_request_concurrency = 10

    scaling {
      max_instance_count = 5
    }

    containers {
      image = var.launcher_image

      dynamic "env" {
        for_each = local.launcher_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  name     = google_cloud_run_v2_service.launcher.name
  location = google_cloud_run_v2_service.launcher.location
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker.email}"
}

# ---- pub/sub push to launcher -----------------------------------------------------------------------------

locals {
  pubsub_agent = "serviceAccount:service-${local.project_number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_service_account_iam_member" "pubsub_mints_invoker_tokens" {
  service_account_id = google_service_account.invoker.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.pubsub_agent
}

resource "google_pubsub_subscription" "launcher_push" {
  name                 = "caf-launcher-push"
  topic                = google_pubsub_topic.ingest_events.id
  ack_deadline_seconds = 60

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.launcher.uri}/events"
    oidc_token {
      service_account_email = google_service_account.invoker.email
      audience              = google_cloud_run_v2_service.launcher.uri
    }
  }

  # A manifest that arrives before its payload is retried until the payload lands.
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.ingest_dead_letter.id
    max_delivery_attempts = 10
  }
}

resource "google_pubsub_topic_iam_member" "dead_letter_publish" {
  topic  = google_pubsub_topic.ingest_dead_letter.id
  role   = "roles/pubsub.publisher"
  member = local.pubsub_agent
}

resource "google_pubsub_subscription_iam_member" "dead_letter_ack" {
  subscription = google_pubsub_subscription.launcher_push.id
  role         = "roles/pubsub.subscriber"
  member       = local.pubsub_agent
}

resource "google_pubsub_subscription" "dead_letter_hold" {
  name                       = "caf-ingest-dead-letter-hold"
  topic                      = google_pubsub_topic.ingest_dead_letter.id
  message_retention_duration = "604800s"
}

# ---- sweeper: delete finished or overdue scan VMs ----------------------------------------------------------

resource "google_cloud_scheduler_job" "sweep" {
  name     = "caf-sweep-scan-vms"
  region   = var.region
  schedule = "*/10 * * * *"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.launcher.uri}/sweep"
    oidc_token {
      service_account_email = google_service_account.invoker.email
      audience              = google_cloud_run_v2_service.launcher.uri
    }
  }

  depends_on = [google_project_service.apis]
}
