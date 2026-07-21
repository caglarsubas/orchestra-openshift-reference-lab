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
