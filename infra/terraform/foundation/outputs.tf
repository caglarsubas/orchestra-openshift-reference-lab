output "topology" {
  value = {
    region                   = local.region
    zones                    = local.zones
    target_project_id        = var.target_project_id
    services_project_id      = var.services_project_id
    target_network           = google_compute_network.target.name
    target_control_subnet    = google_compute_subnetwork.target_control.name
    target_compute_subnet    = google_compute_subnetwork.target_compute.name
    target_machine_cidr      = local.target_machine_cidr
    services_network         = google_compute_network.services.name
    dependency_cluster       = google_container_cluster.dependencies.name
    bootstrap_oci_repository = google_artifact_registry_repository.bootstrap.name
    signed_evidence_bucket   = google_storage_bucket.signed_evidence.name
    raw_evidence_bucket      = google_storage_bucket.raw_evidence.name
    evidence_kms_key         = google_kms_crypto_key.evidence.id
    signed_retention_locked  = var.lock_signed_evidence_bucket
    certification_mode       = var.certification_mode
    external_probe_instances = sort(keys(google_compute_instance.probe))
  }
}

output "openshift_install_values" {
  value = {
    OCP_MACHINE_CIDR         = local.target_machine_cidr
    OCP_COMPUTE_SUBNET       = google_compute_subnetwork.target_compute.name
    OCP_CONTROL_PLANE_SUBNET = google_compute_subnetwork.target_control.name
    OCP_NETWORK_NAME         = google_compute_network.target.name
    TARGET_PROJECT_ID        = var.target_project_id
  }
}

output "operator_service_accounts" {
  value = {
    for name, account in google_service_account.separated_operator : name => account.email
  }
}

output "probe_service_accounts" {
  value = {
    for name, account in google_service_account.probe : name => account.email
  }
}

output "evidence_writer_service_account" {
  value = google_service_account.evidence_writer.email
}

output "artifact_mirror_service_account" {
  value = google_service_account.artifact_mirror.email
}
