output "production_model_custody_identity_contract" {
  value = {
    uploader = {
      service_account            = google_service_account.production_model_custody_writer.email
      workload_identity_provider = google_iam_workload_identity_pool_provider.production_model_custody_upload.name
      environment                = local.production_model_custody_upload_environment
      workflow_ref               = local.production_model_custody_upload_workflow_ref
      federated_subject          = local.production_model_custody_upload_subject
      declared_project_roles     = []
      user_managed_key_declared  = false
    }
    verifier = {
      service_account            = google_service_account.production_model_custody_verifier.email
      workload_identity_provider = google_iam_workload_identity_pool_provider.production_model_custody_verify.name
      environment                = local.production_model_custody_verify_environment
      workflow_ref               = local.production_model_custody_verify_workflow_ref
      federated_subject          = local.production_model_custody_verify_subject
      declared_project_roles     = []
      user_managed_key_declared  = false
    }
    workflow_declared  = true
    campaign_authority = false
  }
}
