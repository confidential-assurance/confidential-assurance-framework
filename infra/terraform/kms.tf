# Two HSM-backed keys, both releasable only to attested workloads:
#   bundle-unwrap   asymmetric decrypt; vendors wrap their per-bundle DEK to its public key (operator-key mode)
#   artifact-sign   asymmetric signing for SBOM/AIBOM, reports and provenance
#
# Vendors who prefer to hold their own key (vendor-key mode) create a key in their own project and grant
# roles/cloudkms.cryptoKeyDecrypter to the principalSet output by this module. See docs/verification.md.

resource "google_kms_key_ring" "caf" {
  name       = "caf"
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "bundle_unwrap" {
  name     = "bundle-unwrap"
  key_ring = google_kms_key_ring.caf.id
  purpose  = "ASYMMETRIC_DECRYPT"

  version_template {
    algorithm        = "RSA_DECRYPT_OAEP_4096_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "artifact_sign" {
  name     = "artifact-sign"
  key_ring = google_kms_key_ring.caf.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Decrypt and sign are granted ONLY to attested workload principals.
resource "google_kms_crypto_key_iam_member" "unwrap_attested" {
  for_each      = toset(local.workload_principals)
  crypto_key_id = google_kms_crypto_key.bundle_unwrap.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = each.value
}

resource "google_kms_crypto_key_iam_member" "sign_attested" {
  for_each      = toset(local.workload_principals)
  crypto_key_id = google_kms_crypto_key.artifact_sign.id
  role          = "roles/cloudkms.signerVerifier"
  member        = each.value
}

# Public keys are public: vendors need the unwrap public key, relying parties need the signing public key.
resource "google_kms_crypto_key_iam_member" "unwrap_public" {
  crypto_key_id = google_kms_crypto_key.bundle_unwrap.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "allAuthenticatedUsers"
}

resource "google_kms_crypto_key_iam_member" "sign_public" {
  crypto_key_id = google_kms_crypto_key.artifact_sign.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "allAuthenticatedUsers"
}
