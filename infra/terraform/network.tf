# Workload network: no external IPs, no Cloud NAT, Private Google Access only.
# Egress is therefore limited to Google APIs; VPC Service Controls narrows that to the APIs the workload needs.

resource "google_compute_network" "workload" {
  name                    = "caf-workload"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "workload" {
  name                     = "caf-workload-${var.region}"
  network                  = google_compute_network.workload.id
  region                   = var.region
  ip_cidr_range            = "10.42.0.0/24"
  private_ip_google_access = true
}

resource "google_compute_firewall" "deny_all_ingress" {
  name      = "caf-deny-all-ingress"
  network   = google_compute_network.workload.name
  direction = "INGRESS"
  priority  = 0

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "deny_internet_egress" {
  name               = "caf-deny-internet-egress"
  network            = google_compute_network.workload.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

# Private Google Access range (private.googleapis.com) is allowed explicitly at higher priority.
resource "google_compute_firewall" "allow_google_apis_egress" {
  name               = "caf-allow-google-apis"
  network            = google_compute_network.workload.name
  direction          = "EGRESS"
  priority           = 100
  destination_ranges = ["199.36.153.8/30"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_access_context_manager_service_perimeter" "data_plane" {
  count  = var.vpc_sc_perimeter_enabled ? 1 : 0
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/caf"
  title  = "caf"

  status {
    resources = ["projects/${local.project_number}"]
    restricted_services = [
      "cloudkms.googleapis.com",
      "storage.googleapis.com",
    ]
  }
}
