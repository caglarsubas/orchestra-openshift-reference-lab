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

output "foundation_service_account" {
  value = google_service_account.foundation_executor.email
}

output "foundation_plan_service_account" {
  value = google_service_account.foundation_planner.email
}

output "foundation_identity_contract" {
  value = {
    planner_service_account  = google_service_account.foundation_planner.email
    planner_environment      = local.foundation_plan_environment
    planner_workflow_ref     = local.foundation_plan_workflow_ref
    planner_state_access     = "read-only-without-lock"
    executor_service_account = google_service_account.foundation_executor.email
    executor_federated       = false
  }
}
