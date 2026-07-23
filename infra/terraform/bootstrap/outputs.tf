output "target_project_id" {
  value = google_project.target.project_id
}

output "services_project_id" {
  value = google_project.services.project_id
}

output "state_bucket" {
  value = google_storage_bucket.state.name
}

output "state_kms_key" {
  value = google_kms_crypto_key.state.id
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}

output "foundation_apply_workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.foundation_apply.name
}

output "foundation_observation_workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.foundation_observation.name
}

output "dependency_risk_workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.dependency_risk.name
}

output "dependency_risk_collection_workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.dependency_risk_collection.name
}

output "dependency_risk_custody_verification_workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.dependency_risk_custody_verification.name
}

output "foundation_service_account" {
  value = google_service_account.foundation_executor.email
}

output "foundation_plan_service_account" {
  value = google_service_account.foundation_planner.email
}

output "foundation_plan_packager_service_account" {
  value = google_service_account.foundation_plan_packager.email
}

output "foundation_observation_service_account" {
  value = google_service_account.foundation_observer.email
}

output "dependency_risk_service_account" {
  value = google_service_account.dependency_risk.email
}

output "dependency_risk_collection_service_account" {
  value = google_service_account.dependency_risk_collector.email
}

output "dependency_risk_custody_verification_service_account" {
  value = google_service_account.dependency_risk_custody_verifier.email
}

output "foundation_identity_contract" {
  value = {
    planner_service_account       = google_service_account.foundation_planner.email
    planner_environment           = local.foundation_plan_environment
    planner_workflow_ref          = local.foundation_plan_workflow_ref
    planner_federated_subject     = local.foundation_plan_subject
    planner_state_access          = "read-only-without-lock"
    plan_packager_service_account = google_service_account.foundation_plan_packager.email
    plan_packager_state_access    = "none"
    executor_service_account      = google_service_account.foundation_executor.email
    executor_environment          = local.foundation_apply_environment
    executor_workflow_ref         = local.foundation_apply_workflow_ref
    executor_federated_subject    = local.foundation_apply_subject
    executor_federated            = true
    observer_service_account      = google_service_account.foundation_observer.email
    observer_environment          = local.foundation_observation_environment
    observer_workflow_ref         = local.foundation_observation_workflow_ref
    observer_federated_subject    = local.foundation_observation_subject
    observer_state_access         = "read-only-without-lock"
  }
}

output "foundation_apply_execution_contract" {
  value = {
    plan_managed_folder                    = google_storage_managed_folder.foundation_plans.name
    apply_report_managed_folder            = google_storage_managed_folder.foundation_apply_reports.name
    plan_packager_project_roles            = []
    plan_packager_object_create_only       = true
    plan_packager_state_access             = false
    plan_reviewer_members                  = sort(tolist(var.foundation_plan_reviewer_members))
    plan_reviewer_package_read_only        = true
    plan_reviewer_state_access             = false
    executor_has_foundation_project_roles  = true
    executor_has_artifact_mirror_authority = true
    workflow_permits_artifact_mirroring    = false
    plan_signing_key                       = google_kms_crypto_key.foundation_plan_signing.id
    apply_receipt_signing_key              = google_kms_crypto_key.foundation_apply_receipt_signing.id
    campaign_authority                     = false
  }
}

output "foundation_observation_contract" {
  value = {
    service_account                     = google_service_account.foundation_observer.email
    workload_identity_provider          = google_iam_workload_identity_pool_provider.foundation_observation.name
    environment                         = local.foundation_observation_environment
    workflow_ref                        = local.foundation_observation_workflow_ref
    federated_subject                   = local.foundation_observation_subject
    declared_project_roles              = sort(flatten([tolist(local.foundation_planner_roles.target), tolist(local.foundation_planner_roles.services)]))
    declared_custom_project_roles       = [google_project_iam_custom_role.foundation_storage_metadata_observer.name]
    state_managed_folder                = google_storage_managed_folder.foundation_state.name
    plan_managed_folder                 = google_storage_managed_folder.foundation_plans.name
    apply_report_managed_folder         = google_storage_managed_folder.foundation_apply_reports.name
    observation_report_managed_folder   = google_storage_managed_folder.foundation_observations.name
    declared_source_object_role         = "roles/storage.objectViewer"
    declared_report_object_role         = "roles/storage.objectCreator"
    declared_source_object_write_grant  = false
    declared_source_object_delete_grant = false
    declared_report_object_read_grant   = false
    declared_report_object_delete_grant = false
    observation_signing_key             = google_kms_crypto_key.foundation_observation_signing.id
    infrastructure_mutation_granted     = false
    campaign_authority                  = false
  }
}

output "dependency_risk_identity_contract" {
  value = {
    service_account                      = google_service_account.dependency_risk.email
    workload_identity_provider           = google_iam_workload_identity_pool_provider.dependency_risk.name
    environment                          = local.dependency_risk_preflight_environment
    workflow_ref                         = local.dependency_risk_preflight_workflow_ref
    federated_subject                    = local.dependency_risk_preflight_subject
    declared_project_roles               = []
    declared_evidence_bucket_write_grant = false
    declared_artifact_mirror_write_grant = false
    user_managed_key_resource_declared   = false
  }
}

output "dependency_risk_collection_identity_contract" {
  value = {
    service_account                      = google_service_account.dependency_risk_collector.email
    workload_identity_provider           = google_iam_workload_identity_pool_provider.dependency_risk_collection.name
    environment                          = local.dependency_risk_collection_environment
    workflow_ref                         = local.dependency_risk_collection_workflow_ref
    federated_subject                    = local.dependency_risk_collection_subject
    declared_project_roles               = []
    declared_raw_evidence_create_grant   = true
    declared_raw_evidence_read_grant     = false
    declared_raw_evidence_delete_grant   = false
    declared_signed_evidence_write_grant = false
    declared_artifact_mirror_write_grant = false
    user_managed_key_resource_declared   = false
  }
}

output "dependency_risk_custody_verification_identity_contract" {
  value = {
    service_account                       = google_service_account.dependency_risk_custody_verifier.email
    workload_identity_provider            = google_iam_workload_identity_pool_provider.dependency_risk_custody_verification.name
    environment                           = local.dependency_risk_custody_verification_environment
    workflow_ref                          = local.dependency_risk_custody_verification_workflow_ref
    federated_subject                     = local.dependency_risk_custody_verification_subject
    declared_project_roles                = []
    declared_raw_object_read_grant        = true
    declared_raw_object_write_grant       = false
    declared_raw_object_delete_grant      = false
    declared_signed_evidence_create_grant = true
    declared_signed_evidence_read_grant   = false
    declared_signed_evidence_delete_grant = false
    declared_artifact_mirror_write_grant  = false
    user_managed_key_resource_declared    = false
  }
}
