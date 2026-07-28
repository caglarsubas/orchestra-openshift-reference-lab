output "production_model_artifact_custody_contract" {
  value = {
    bucket                             = google_storage_bucket.production_model_artifacts.name
    encryption_key                     = google_kms_crypto_key.production_model_artifact_custody.id
    verification_signing_key           = google_kms_crypto_key.production_model_artifact_custody_verification_signing.id
    artifact_managed_folder            = google_storage_managed_folder.production_model_artifacts.name
    signed_record_managed_folder       = google_storage_managed_folder.production_model_custody_records.name
    uploader_service_account           = "orchestra-model-custody-writer@${var.services_project_id}.iam.gserviceaccount.com"
    uploader_role                      = "roles/storage.objectCreator"
    uploader_read_granted              = false
    uploader_delete_granted            = false
    verifier_service_account           = "orchestra-model-custody-verify@${var.services_project_id}.iam.gserviceaccount.com"
    verifier_artifact_role             = "roles/storage.objectViewer"
    verifier_signed_record_role        = "roles/storage.objectCreator"
    verifier_artifact_write_granted    = false
    verifier_delete_granted            = false
    verifier_signing_role              = "roles/cloudkms.signerVerifier"
    artifact_mirror_write_granted      = false
    source_admission_authority_granted = false
    deployment_authority_granted       = false
    campaign_authority_granted         = false
    retention_days                     = 400
    retention_locked                   = false
  }
}
