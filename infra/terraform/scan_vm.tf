# Template for single-use scan VMs. The launcher creates one VM per uploaded bundle from this template and adds
# only two per-job values (tee-env-CAF_JOB_ID, tee-env-CAF_DEPLOYMENT), which the attestation policy allows and
# which appear in the attestation token.

resource "google_compute_instance_template" "scan" {
  name_prefix  = "caf-scan-"
  machine_type = "a3-highgpu-1g" # 1x NVIDIA H100; Confidential Space supports GPU CC on H100 only

  confidential_instance_config {
    confidential_instance_type = "TDX"
  }

  scheduling {
    on_host_maintenance         = "TERMINATE"
    automatic_restart           = false
    provisioning_model          = var.provisioning_model
    preemptible                 = var.provisioning_model == "SPOT"
    instance_termination_action = "DELETE"

    # Backstop: Compute Engine deletes the VM after this long even if the workload hangs.
    max_run_duration {
      seconds = var.max_scan_seconds
    }
  }

  shielded_instance_config {
    enable_secure_boot = true
  }

  disk {
    source_image = "projects/confidential-space-images/global/images/family/confidential-space"
    disk_size_gb = var.boot_disk_gb
    boot         = true
    auto_delete  = true
  }

  network_interface {
    subnetwork = google_compute_subnetwork.workload.id
    # No access_config block: no external IP.
  }

  service_account {
    email  = google_service_account.workload_vm.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    "tee-image-reference"        = "${var.workload_image}@${var.workload_image_digest}"
    "tee-install-gpu-driver"     = "true"
    "tee-restart-policy"         = "Never"
    "tee-container-log-redirect" = "false"
    "tee-dev-shm-size-kb"        = tostring(var.shm_size_kb)
  }

  labels = {
    caf-role = "scan"
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = contains(var.allowed_image_digests, var.workload_image_digest)
      error_message = "workload_image_digest must be one of allowed_image_digests, or scan VMs could never obtain keys."
    }
  }
}
