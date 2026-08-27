resource "google_compute_network" "target" {
  provider = google.target

  name                            = "orchestra-ocp-network"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = false
}

resource "google_compute_subnetwork" "target_control" {
  provider = google.target

  name                     = "orchestra-ocp-control"
  region                   = local.region
  network                  = google_compute_network.target.id
  ip_cidr_range            = local.target_subnets.control
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "target_compute" {
  provider = google.target

  name                     = "orchestra-ocp-compute"
  region                   = local.region
  network                  = google_compute_network.target.id
  ip_cidr_range            = local.target_subnets.compute
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_network" "services" {
  provider = google.services

  name                            = "orchestra-services-network"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = false
}

resource "google_compute_subnetwork" "services" {
  provider = google.services

  name                     = "orchestra-services"
  region                   = local.region
  network                  = google_compute_network.services.id
  ip_cidr_range            = local.services_subnet
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"

  secondary_ip_range {
    range_name    = "orchestra-gke-pods"
    ip_cidr_range = local.gke_pods_cidr
  }

  secondary_ip_range {
    range_name    = "orchestra-gke-services"
    ip_cidr_range = local.gke_services_cidr
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_network_peering" "target_to_services" {
  provider = google.target

  name                 = "orchestra-target-to-services"
  network              = google_compute_network.target.self_link
  peer_network         = google_compute_network.services.self_link
  export_custom_routes = false
  import_custom_routes = false
}

resource "google_compute_network_peering" "services_to_target" {
  provider = google.services

  name                 = "orchestra-services-to-target"
  network              = google_compute_network.services.self_link
  peer_network         = google_compute_network.target.self_link
  export_custom_routes = false
  import_custom_routes = false
}

resource "google_compute_router" "target" {
  provider = google.target

  name    = "orchestra-target-router"
  region  = local.region
  network = google_compute_network.target.id
}

resource "google_compute_router_nat" "target" {
  provider = google.target

  name                               = "orchestra-target-nat"
  router                             = google_compute_router.target.name
  region                             = local.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ALL"
  }
}

resource "google_compute_router" "services" {
  provider = google.services

  name    = "orchestra-services-router"
  region  = local.region
  network = google_compute_network.services.id
}

resource "google_compute_router_nat" "services" {
  provider = google.services

  name                               = "orchestra-services-nat"
  router                             = google_compute_router.services.name
  region                             = local.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ALL"
  }
}

resource "google_compute_firewall" "target_egress_allow" {
  provider = google.target

  name               = "orchestra-target-egress-allowlisted"
  network            = google_compute_network.target.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = sort(tolist(local.effective_egress_cidrs))

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "target_egress_services" {
  provider = google.target

  name               = "orchestra-target-egress-services"
  network            = google_compute_network.target.name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [local.services_subnet, local.gke_pods_cidr, local.gke_services_cidr]

  allow {
    protocol = "tcp"
    ports    = ["443", "4222", "5432", "6379", "8123", "8200", "9000", "9443"]
  }
  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "target_egress_internal" {
  provider = google.target

  name               = "orchestra-target-egress-internal"
  network            = google_compute_network.target.name
  direction          = "EGRESS"
  priority           = 850
  destination_ranges = values(local.target_subnets)

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "target_egress_deny" {
  provider = google.target

  name               = "orchestra-target-egress-deny"
  network            = google_compute_network.target.name
  direction          = "EGRESS"
  priority           = 65534
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "services_egress_allow" {
  provider = google.services

  name               = "orchestra-services-egress-allowlisted"
  network            = google_compute_network.services.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = sort(tolist(local.effective_egress_cidrs))

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "services_egress_target" {
  provider = google.services

  name               = "orchestra-services-egress-target"
  network            = google_compute_network.services.name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = values(local.target_subnets)

  allow {
    protocol = "tcp"
    ports    = ["22", "443", "6443"]
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "services_egress_internal" {
  provider = google.services

  name      = "orchestra-services-egress-internal"
  network   = google_compute_network.services.name
  direction = "EGRESS"
  priority  = 850
  destination_ranges = [
    local.services_subnet,
    local.gke_pods_cidr,
    local.gke_services_cidr,
    local.gke_master_cidr,
  ]

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "services_egress_deny" {
  provider = google.services

  name               = "orchestra-services-egress-deny"
  network            = google_compute_network.services.name
  direction          = "EGRESS"
  priority           = 65534
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "services_ingress_target" {
  provider = google.services

  name          = "orchestra-services-ingress-target"
  network       = google_compute_network.services.name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = values(local.target_subnets)

  allow {
    protocol = "tcp"
    ports    = ["443", "4222", "5432", "6379", "8123", "8200", "9000", "9443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "target_ingress_services" {
  provider = google.target

  name          = "orchestra-target-ingress-services"
  network       = google_compute_network.target.name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = [local.services_subnet, local.gke_pods_cidr]

  allow {
    protocol = "tcp"
    ports    = ["443", "6443"]
  }
  allow {
    protocol = "icmp"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "iap_ssh" {
  provider = google.services

  name          = "orchestra-iap-ssh"
  network       = google_compute_network.services.name
  direction     = "INGRESS"
  priority      = 800
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["orchestra-iap-bastion"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_service_account" "gke_nodes" {
  provider = google.services

  project      = var.services_project_id
  account_id   = "orchestra-gke-nodes"
  display_name = "Orchestra dependency-plane GKE nodes"
}

resource "google_project_iam_member" "gke_nodes" {
  provider = google.services
  for_each = toset([
    "roles/artifactregistry.reader",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
  ])

  project = var.services_project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_container_cluster" "dependencies" {
  provider = google.services

  name                        = "orchestra-dependencies"
  location                    = local.region
  network                     = google_compute_network.services.id
  subnetwork                  = google_compute_subnetwork.services.id
  remove_default_node_pool    = true
  initial_node_count          = 1
  deletion_protection         = true
  networking_mode             = "VPC_NATIVE"
  enable_intranode_visibility = true
  enable_shielded_nodes       = true
  resource_labels             = local.platform_labels

  release_channel {
    channel = var.gke_release_channel
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "orchestra-gke-pods"
    services_secondary_range_name = "orchestra-gke-services"
  }

  private_cluster_config {
    enable_private_endpoint = true
    enable_private_nodes    = true
    master_ipv4_cidr_block  = local.gke_master_cidr

    master_global_access_config {
      enabled = false
    }
  }

  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled      = false
    private_endpoint_enforcement_enabled = true

    cidr_blocks {
      cidr_block   = local.target_subnets.control
      display_name = "ocp-control"
    }
  }

  workload_identity_config {
    workload_pool = "${var.services_project_id}.svc.id.goog"
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  logging_config {
    enable_components = var.reference_lab_active ? ["SYSTEM_COMPONENTS", "WORKLOADS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"] : ["NONE"]
  }

  monitoring_config {
    enable_components = var.reference_lab_active ? ["SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER", "STORAGE", "POD", "DEPLOYMENT", "STATEFULSET", "DAEMONSET", "HPA", "CADVISOR", "KUBELET"] : ["NONE"]

    managed_prometheus {
      enabled = var.reference_lab_active
    }
  }

  maintenance_policy {
    recurring_window {
      start_time = "2026-01-03T00:00:00Z"
      end_time   = "2026-01-03T08:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA"
    }
  }

  lifecycle {
    precondition {
      condition     = var.target_project_id != var.services_project_id
      error_message = "Target and services/evidence projects must be distinct."
    }

    precondition {
      condition     = !var.certification_mode || var.reference_lab_active
      error_message = "Certification mode requires an active reference-lab runtime."
    }
  }
}

resource "google_container_node_pool" "dependencies" {
  provider = google.services

  name           = "orchestra-dependencies"
  location       = local.region
  cluster        = google_container_cluster.dependencies.name
  node_locations = local.zones
  node_count     = var.reference_lab_active ? 1 : 0

  node_config {
    machine_type    = "n2-standard-8"
    disk_type       = "pd-ssd"
    disk_size_gb    = 100 # Fits default regional SSD_TOTAL_GB=500 quota.
    image_type      = "COS_CONTAINERD"
    preemptible     = false
    spot            = false
    service_account = google_service_account.gke_nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    resource_labels = local.platform_labels

    metadata = {
      disable-legacy-endpoints = "true"
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_integrity_monitoring = true
      enable_secure_boot          = true
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = false
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }

  depends_on = [google_project_iam_member.gke_nodes]
}

# Harbor cannot mirror the charts and images needed to install Harbor itself.
# This immutable Artifact Registry repository is the bounded bootstrap source;
# the campaign records promotion into Harbor as a separate supply-chain edge.
resource "google_artifact_registry_repository" "bootstrap" {
  provider = google.services

  project       = var.services_project_id
  location      = local.region
  repository_id = "orchestra-bootstrap"
  description   = "Immutable pre-Harbor OCI seed for the Orchestra reference lab"
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"

  docker_config {
    immutable_tags = true
  }

  cleanup_policy_dry_run = true
  labels                 = local.platform_labels
}

resource "google_service_account" "artifact_mirror" {
  provider = google.services

  project      = var.services_project_id
  account_id   = "orchestra-artifact-mirror"
  display_name = "Orchestra bootstrap artifact mirror"
  description  = "Supply-chain intake identity; receives short-lived credentials only."
}

resource "google_artifact_registry_repository_iam_member" "artifact_mirror_writer" {
  provider = google.services

  project    = var.services_project_id
  location   = google_artifact_registry_repository.bootstrap.location
  repository = google_artifact_registry_repository.bootstrap.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.artifact_mirror.email}"
}

resource "google_artifact_registry_repository_iam_member" "gitops_bootstrap_reader" {
  provider = google.services

  project    = var.services_project_id
  location   = google_artifact_registry_repository.bootstrap.location
  repository = google_artifact_registry_repository.bootstrap.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.separated_operator["gitops-executor"].email}"
}

resource "google_kms_key_ring" "evidence" {
  provider = google.services

  project  = var.services_project_id
  name     = "orchestra-reference-evidence"
  location = local.region
}

resource "google_kms_crypto_key" "evidence" {
  provider = google.services

  name            = "evidence-custody"
  key_ring        = google_kms_key_ring.evidence.id
  rotation_period = "7776000s"
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "dependency_risk_signing" {
  provider = google.services

  name     = "dependency-risk-collection-signing"
  key_ring = google_kms_key_ring.evidence.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "dependency_risk_signer" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.dependency_risk_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:orchestra-dependency-risk@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "dependency_risk_collector_signer" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.dependency_risk_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:orchestra-risk-collector@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key" "dependency_risk_custody_verification_signing" {
  provider = google.services

  name     = "dependency-risk-custody-verification-signing"
  key_ring = google_kms_key_ring.evidence.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "dependency_risk_custody_collection_public_key" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.dependency_risk_signing.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:orchestra-custody-verifier@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "dependency_risk_custody_verifier_signer" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.dependency_risk_custody_verification_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:orchestra-custody-verifier@${var.services_project_id}.iam.gserviceaccount.com"
}

data "google_storage_project_service_account" "services" {
  provider = google.services
  project  = var.services_project_id
}

resource "google_kms_crypto_key_iam_member" "storage_agent" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.evidence.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.services.email_address}"
}

resource "google_storage_bucket" "signed_evidence" {
  provider = google.services

  project                     = var.services_project_id
  name                        = var.signed_evidence_bucket_name
  location                    = local.region
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  enable_object_retention     = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.evidence.id
  }

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 400 * 24 * 60 * 60
    is_locked        = var.lock_signed_evidence_bucket
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = !var.certification_mode || var.lock_signed_evidence_bucket
      error_message = "Certification mode requires the signed evidence retention lock."
    }

    precondition {
      condition     = !var.lock_signed_evidence_bucket || var.retention_lock_acknowledgement == "LOCK-400-DAY-EVIDENCE-RETENTION-IRREVERSIBLY"
      error_message = "Set the exact retention lock acknowledgement after two-person review."
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.storage_agent]
}

resource "google_storage_bucket" "raw_evidence" {
  provider = google.services

  project                     = var.services_project_id
  name                        = var.raw_evidence_bucket_name
  location                    = local.region
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  enable_object_retention     = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.evidence.id
  }

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 90 * 24 * 60 * 60
    is_locked        = false
  }

  lifecycle_rule {
    condition {
      age = 91
    }
    action {
      type = "Delete"
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_kms_crypto_key_iam_member.storage_agent]
}

resource "google_storage_managed_folder" "dependency_risk_raw" {
  provider = google.services

  bucket          = google_storage_bucket.raw_evidence.name
  name            = "dependency-risk/"
  deletion_policy = "PREVENT"
}

resource "google_storage_managed_folder" "dependency_risk_signed" {
  provider = google.services

  bucket          = google_storage_bucket.signed_evidence.name
  name            = "dependency-risk-custody/"
  deletion_policy = "PREVENT"
}

resource "google_service_account" "evidence_writer" {
  provider = google.services

  project      = var.services_project_id
  account_id   = "orchestra-evidence-writer"
  display_name = "Orchestra payload-free evidence writer"
}

resource "google_storage_bucket_iam_member" "signed_evidence_writer" {
  provider = google.services

  bucket = google_storage_bucket.signed_evidence.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.evidence_writer.email}"
}

resource "google_storage_bucket_iam_member" "raw_evidence_writer" {
  provider = google.services

  bucket = google_storage_bucket.raw_evidence.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.evidence_writer.email}"
}

resource "google_storage_bucket_iam_member" "dependency_risk_collector_writer" {
  provider = google.services

  bucket = google_storage_bucket.raw_evidence.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:orchestra-risk-collector@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_storage_managed_folder_iam_member" "dependency_risk_custody_raw_reader" {
  provider = google.services

  bucket         = google_storage_managed_folder.dependency_risk_raw.bucket
  managed_folder = google_storage_managed_folder.dependency_risk_raw.name
  role           = "roles/storage.objectViewer"
  member         = "serviceAccount:orchestra-custody-verifier@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_storage_managed_folder_iam_member" "dependency_risk_custody_report_writer" {
  provider = google.services

  bucket         = google_storage_managed_folder.dependency_risk_signed.bucket
  managed_folder = google_storage_managed_folder.dependency_risk_signed.name
  role           = "roles/storage.objectCreator"
  member         = "serviceAccount:orchestra-custody-verifier@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_service_account" "bastion" {
  provider = google.services

  project      = var.services_project_id
  account_id   = "orchestra-iap-bastion"
  display_name = "Orchestra IAP bastion"
}

resource "google_project_iam_member" "bastion_logging" {
  provider = google.services
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])

  project = var.services_project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.bastion.email}"
}

resource "google_project_iam_member" "iap_operator" {
  provider = google.services
  for_each = var.iap_operator_members

  project = var.services_project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = each.value
}

resource "google_project_iam_member" "os_login_operator" {
  provider = google.services
  for_each = var.iap_operator_members

  project = var.services_project_id
  role    = "roles/compute.osLogin"
  member  = each.value
}

resource "google_project_iam_member" "bastion_viewer" {
  provider = google.services
  for_each = var.iap_operator_members

  project = var.services_project_id
  role    = "roles/compute.viewer"
  member  = each.value
}

resource "google_compute_instance" "bastion" {
  provider = google.services

  name                      = "orchestra-iap-bastion"
  zone                      = "europe-west1-b"
  machine_type              = "e2-standard-2"
  can_ip_forward            = false
  deletion_protection       = true
  allow_stopping_for_update = true
  desired_status            = var.reference_lab_active ? "RUNNING" : "TERMINATED"
  tags                      = ["orchestra-iap-bastion"]
  labels                    = local.platform_labels

  boot_disk {
    auto_delete = false
    initialize_params {
      image = var.bastion_source_image
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.services.id
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "TRUE"
    serial-port-enable     = "false"
  }

  service_account {
    email  = google_service_account.bastion.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  depends_on = [google_project_iam_member.bastion_logging]
}

resource "google_service_account" "probe" {
  provider = google.services
  for_each = local.probe_instances

  project      = var.services_project_id
  account_id   = "orchestra-${each.key}"
  display_name = "Orchestra external ${each.key}"
}

resource "google_project_iam_member" "probe_monitoring" {
  provider = google.services
  for_each = local.probe_instances

  project = var.services_project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.probe[each.key].email}"
}

resource "google_compute_instance" "probe" {
  provider = google.services
  for_each = local.probe_instances

  name                      = "orchestra-${each.key}"
  zone                      = each.value
  machine_type              = "e2-standard-2"
  can_ip_forward            = false
  deletion_protection       = true
  allow_stopping_for_update = true
  desired_status            = var.reference_lab_active ? "RUNNING" : "TERMINATED"
  labels                    = merge(local.platform_labels, { probe = each.key })

  boot_disk {
    auto_delete = false
    initialize_params {
      image = var.probe_source_image
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.services.id
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "TRUE"
    serial-port-enable     = "false"
    probe-container-image  = var.probe_container_image
    probe-identity         = each.key
  }

  service_account {
    email  = google_service_account.probe[each.key].email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  lifecycle {
    precondition {
      condition     = length(local.probe_instances) == 2 && length(toset(values(local.probe_instances))) == 2
      error_message = "Exactly two probe runners in distinct zones are required."
    }
  }

  depends_on = [google_project_iam_member.probe_monitoring]
}

resource "google_service_account" "separated_operator" {
  provider = google.services
  for_each = toset([
    "datastore-operator",
    "fault-controller",
    "gitops-executor",
    "readonly-observer",
    "secret-operator",
  ])

  project      = var.services_project_id
  account_id   = "orchestra-${each.value}"
  display_name = "Orchestra ${each.value}"
  description  = "Identity boundary only; campaign-specific grants are applied separately."
}
