locals {
  production_model_artifact_bucket_name = (
    var.production_model_artifact_bucket_name != ""
    ? var.production_model_artifact_bucket_name
    : "${var.services_project_id}-production-model-artifacts"
  )
}

resource "google_kms_crypto_key" "production_model_artifact_custody" {
  provider = google.services

  name            = "production-model-artifact-custody"
  key_ring        = google_kms_key_ring.evidence.id
  rotation_period = "7776000s"
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "production_model_artifact_custody_verification_signing" {
  provider = google.services

  name     = "production-model-artifact-custody-verification-signing"
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

resource "google_kms_crypto_key_iam_member" "production_model_artifact_storage_agent" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.production_model_artifact_custody.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.services.email_address}"
}

resource "google_kms_crypto_key_iam_member" "production_model_custody_verifier_signer" {
  provider = google.services

  crypto_key_id = google_kms_crypto_key.production_model_artifact_custody_verification_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:orchestra-model-custody-verify@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_storage_bucket" "production_model_artifacts" {
  provider = google.services

  project                     = var.services_project_id
  name                        = local.production_model_artifact_bucket_name
  location                    = local.region
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
  enable_object_retention     = true
  default_event_based_hold    = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.production_model_artifact_custody.id
  }

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 400 * 24 * 60 * 60
    is_locked        = false
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        local.production_model_artifact_bucket_name != var.signed_evidence_bucket_name
        && local.production_model_artifact_bucket_name != var.raw_evidence_bucket_name
      )
      error_message = "Production model bytes require a dedicated bucket distinct from signed and raw evidence."
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.production_model_artifact_storage_agent]
}

resource "google_storage_managed_folder" "production_model_artifacts" {
  provider = google.services

  bucket          = google_storage_bucket.production_model_artifacts.name
  name            = "production-model-artifacts/"
  deletion_policy = "PREVENT"
}

resource "google_storage_managed_folder" "production_model_custody_records" {
  provider = google.services

  bucket          = google_storage_bucket.production_model_artifacts.name
  name            = "production-model-custody/"
  deletion_policy = "PREVENT"
}

resource "google_storage_managed_folder_iam_member" "production_model_custody_writer" {
  provider = google.services

  bucket         = google_storage_managed_folder.production_model_artifacts.bucket
  managed_folder = google_storage_managed_folder.production_model_artifacts.name
  role           = "roles/storage.objectCreator"
  member         = "serviceAccount:orchestra-model-custody-writer@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_storage_managed_folder_iam_member" "production_model_custody_artifact_reader" {
  provider = google.services

  bucket         = google_storage_managed_folder.production_model_artifacts.bucket
  managed_folder = google_storage_managed_folder.production_model_artifacts.name
  role           = "roles/storage.objectViewer"
  member         = "serviceAccount:orchestra-model-custody-verify@${var.services_project_id}.iam.gserviceaccount.com"
}

resource "google_storage_managed_folder_iam_member" "production_model_custody_record_writer" {
  provider = google.services

  bucket         = google_storage_managed_folder.production_model_custody_records.bucket
  managed_folder = google_storage_managed_folder.production_model_custody_records.name
  role           = "roles/storage.objectCreator"
  member         = "serviceAccount:orchestra-model-custody-verify@${var.services_project_id}.iam.gserviceaccount.com"
}
