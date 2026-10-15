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

variable "launcher_service_account_email" {
  description = "Control-plane service account that may create Confidential Space VMs. Gets no KMS rights."
  type        = string
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
