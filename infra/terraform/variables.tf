variable "project_id" {
  description = "GCP project that hosts the data plane (KMS, buckets, Confidential Space VMs)."
  type        = string
}

variable "region" {
  description = "Region for buckets, KMS and VMs. Must offer confidential GPU shapes."
  type        = string
  default     = "us-central1"
}

variable "allowed_image_digests" {
  description = <<-EOT
    Workload image digests allowed to obtain keys (sha256:...). Normally one; two during a release rollover window.
    Each must match a digest published in a signed release and reproducible from source.
  EOT
  type        = list(string)

  validation {
    condition     = alltrue([for d in var.allowed_image_digests : can(regex("^sha256:[0-9a-f]{64}$", d))])
    error_message = "Each digest must look like sha256:<64 hex chars>."
  }
}

variable "hardware_model" {
  description = "Required CPU TEE (Confidential Space hwmodel claim): INTEL_TDX or GCP_AMD_SEV."
  type        = string
  default     = "INTEL_TDX"

  validation {
    condition     = contains(["INTEL_TDX", "GCP_AMD_SEV"], var.hardware_model)
    error_message = "hardware_model must be INTEL_TDX or GCP_AMD_SEV."
  }
}

variable "require_gpu_cc" {
  description = "Require an NVIDIA GPU with confidential computing mode ON in the attestation claims."
  type        = bool
  default     = true
}

variable "zone" {
  description = "Zone for scan VMs. Must offer a3-highgpu-1g with NVIDIA Confidential Computing."
  type        = string
  default     = "us-central1-a"
}

variable "vendors" {
  description = <<-EOT
    Registered SaaS vendors. The map key is the vendor ID used in object paths (jobs/<vendor_id>/...).
    uploaders: IAM principals allowed to upload to, and read results from, that vendor's prefix only,
    for example "serviceAccount:ci@vendor-project.iam.gserviceaccount.com" or "group:secops@vendor.example".
  EOT
  type = map(object({
    display_name = string
    uploaders    = list(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for k in keys(var.vendors) : can(regex("^[a-z0-9-]{3,32}$", k))])
    error_message = "Vendor IDs must be 3-32 characters of lowercase letters, digits and hyphens."
  }
}

variable "workload_image" {
  description = "Artifact Registry path of the workload image, without tag or digest (REGION-docker.pkg.dev/PROJECT/caf/workload)."
  type        = string
}

variable "workload_image_digest" {
  description = "Digest the scan VMs launch. Must be one of allowed_image_digests."
  type        = string
}

variable "launcher_image" {
  description = "Container image for the control-plane launcher (Cloud Run). Not part of the trust boundary."
  type        = string
}

variable "model" {
  description = "Analyst model identifier passed to the workload; must match an entry in the workload's lockfile."
  type        = string
  default     = "phase1-27b-coder"
}

variable "provisioning_model" {
  description = "STANDARD or SPOT for scan VMs."
  type        = string
  default     = "STANDARD"

  validation {
    condition     = contains(["STANDARD", "SPOT"], var.provisioning_model)
    error_message = "provisioning_model must be STANDARD or SPOT."
  }
}

variable "max_scan_seconds" {
  description = "Hard limit on a scan VM's lifetime. Compute Engine deletes the VM when it is reached."
  type        = number
  default     = 7200
}

variable "max_bundle_bytes" {
  description = "Largest ciphertext bundle the launcher accepts."
  type        = number
  default     = 2147483648
}

variable "boot_disk_gb" {
  description = "Boot disk size for scan VMs; must hold the workload image including model weights."
  type        = number
  default     = 200
}

variable "shm_size_kb" {
  description = "RAM-backed /dev/shm size where plaintext is unpacked. Must exceed the largest unpacked bundle."
  type        = number
  default     = 33554432
}

variable "ingest_retention_days" {
  description = "Days before ciphertext bundles are deleted from the ingest bucket."
  type        = number
  default     = 7
}

variable "vpc_sc_perimeter_enabled" {
  description = "Create a VPC Service Controls perimeter around the data project (needs an access policy)."
  type        = bool
  default     = false
}

variable "access_policy_id" {
  description = "Access Context Manager policy ID, required when vpc_sc_perimeter_enabled is true."
  type        = string
  default     = ""
}
