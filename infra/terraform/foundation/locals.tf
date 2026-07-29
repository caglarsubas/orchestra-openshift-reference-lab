locals {
  region = "europe-west1"
  zones = [
    "europe-west1-b",
    "europe-west1-c",
    "europe-west1-d",
  ]

  base_dns_name                  = "ocp-lab.planeon.ai."
  cluster_dns_name               = "orchestra.${local.base_dns_name}"
  public_dns_managed_zone_name   = "orchestra-ocp-lab-public"
  services_dns_peering_zone_name = "orchestra-services-to-ocp-private"

  target_subnets = {
    control = "10.40.0.0/24"
    compute = "10.40.16.0/20"
  }
  target_machine_cidr = "10.40.0.0/19"
  services_subnet     = "10.60.0.0/20"
  gke_pods_cidr       = "10.64.0.0/14"
  gke_services_cidr   = "10.68.0.0/20"
  gke_master_cidr     = "10.69.0.0/28"

  platform_labels = {
    environment = "reference-lab"
    profile     = "orchestra-ocp-4-20-amd64-v1"
    managed_by  = "terraform"
  }

  system_egress_cidrs = toset([
    "169.254.169.254/32",
    "199.36.153.4/30",
  ])
  effective_egress_cidrs = setunion(var.approved_egress_cidrs, local.system_egress_cidrs)

  probe_instances = {
    probe-b = "europe-west1-b"
    probe-c = "europe-west1-c"
  }
}
