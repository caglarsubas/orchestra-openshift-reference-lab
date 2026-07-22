resource "google_dns_managed_zone" "public_base_domain" {
  provider = google.services

  name          = local.public_dns_managed_zone_name
  dns_name      = local.base_dns_name
  description   = "Public delegation and ownership proof for the Orchestra OpenShift reference lab"
  visibility    = "public"
  force_destroy = false
}

# OpenShift owns the target VPC's private cluster zone and records. This
# consumer zone lets services-plane workloads resolve that namespace without
# granting them authority to mutate it.
resource "google_dns_managed_zone" "services_to_openshift_private" {
  provider = google.services

  name          = local.services_dns_peering_zone_name
  dns_name      = local.cluster_dns_name
  description   = "Services-plane resolution of the installer-owned private OpenShift cluster namespace"
  visibility    = "private"
  force_destroy = false

  private_visibility_config {
    networks {
      network_url = google_compute_network.services.id
    }
  }

  peering_config {
    target_network {
      network_url = google_compute_network.target.id
    }
  }
}
