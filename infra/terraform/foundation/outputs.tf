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
    public_dns_zone          = google_dns_managed_zone.public_base_domain.name
    services_dns_peering     = google_dns_managed_zone.services_to_openshift_private.name
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

output "dns_contract" {
  description = "Non-secret inputs for registrar delegation and post-install private resolution checks."
  value = {
    public_managed_zone = {
      project      = var.services_project_id
      name         = google_dns_managed_zone.public_base_domain.name
      dns_name     = google_dns_managed_zone.public_base_domain.dns_name
      name_servers = sort(google_dns_managed_zone.public_base_domain.name_servers)
    }
    registrar_delegation = {
      required            = true
      performed_by        = "external-dns-operator"
      inferred_from_apply = false
      independent_gate    = "dnsDelegation"
    }
    private_cluster_namespace = {
      dns_name             = local.cluster_dns_name
      authority            = "openshift-installer"
      producer_project     = var.target_project_id
      producer_network     = google_compute_network.target.name
      consumer_project     = var.services_project_id
      consumer_network     = google_compute_network.services.name
      peering_zone         = google_dns_managed_zone.services_to_openshift_private.name
      records_created_here = false
    }
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

output "dependency_risk_signing_contract" {
  value = {
    crypto_key                           = google_kms_crypto_key.dependency_risk_signing.id
    purpose                              = "ASYMMETRIC_SIGN"
    algorithm                            = "EC_SIGN_P256_SHA256"
    protection_level                     = "SOFTWARE"
    exact_key_version_required           = true
    signer_service_account               = "orchestra-dependency-risk@${var.services_project_id}.iam.gserviceaccount.com"
    signer_role                          = "roles/cloudkms.signerVerifier"
    declared_evidence_bucket_write_grant = false
    declared_artifact_mirror_write_grant = false
  }
}
