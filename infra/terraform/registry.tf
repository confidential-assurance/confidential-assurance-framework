# Scan VMs have no internet route, so the workload image must come from Artifact Registry (reachable through
# Private Google Access). Release images are published to GitHub Container Registry and copied here by digest;
# a registry copy preserves the manifest digest, so the attestation policy is unaffected:
#
#   crane copy ghcr.io/confidential-assurance/confidential-assurance-framework/workload@sha256:<D> \
#              <region>-docker.pkg.dev/<project>/caf/workload@sha256:<D>

resource "google_artifact_registry_repository" "caf" {
  repository_id = "caf"
  location      = var.region
  format        = "DOCKER"
  description   = "Measured CAF workload images, copied from signed releases by digest"

  docker_config {
    immutable_tags = true
  }

  depends_on = [google_project_service.apis]
}
