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
    planner_service_account   = google_service_account.foundation_planner.email
    planner_environment       = local.foundation_plan_environment
    planner_workflow_ref      = local.foundation_plan_workflow_ref
    planner_federated_subject = local.foundation_plan_subject
    planner_state_access      = "read-only-without-lock"
    executor_service_account  = google_service_account.foundation_executor.email
    executor_federated        = false
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
