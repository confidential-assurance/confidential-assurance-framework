terraform {
  required_version = ">= 1.7"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  project_number = data.google_project.this.number

  required_apis = [
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "storage.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.required_apis)
  service            = each.value
  disable_on_destroy = false
}

# Service account attached to Confidential Space VMs. It only needs to generate attestation tokens and write
# structured status logs. It holds NO KMS or bucket permissions: those go to attested principals in wip.tf.
resource "google_service_account" "workload_vm" {
  account_id   = "caf-workload-vm"
  display_name = "CAF Confidential Space VM"
}

resource "google_project_iam_member" "workload_vm_attest" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.workload_vm.email}"
}

resource "google_project_iam_member" "workload_vm_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workload_vm.email}"
}

# The control-plane launcher may start VMs as the workload SA, and nothing more.
resource "google_service_account_iam_member" "launcher_can_use_workload_sa" {
  service_account_id = google_service_account.workload_vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.launcher_service_account_email}"
}
