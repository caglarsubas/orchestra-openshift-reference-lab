locals {
  production_model_custody_upload_environment  = "reference-lab-production-model-custody-upload"
  production_model_custody_upload_workflow_ref = "${var.github_repository}/.github/workflows/production-model-artifact-custody.yml@refs/heads/main"
  production_model_custody_upload_subject      = "model-custody-upload:${var.github_repository_id}:${local.production_model_custody_upload_environment}"
  production_model_custody_upload_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.production_model_custody_upload_workflow_ref}'",
    "assertion.environment == '${local.production_model_custody_upload_environment}'",
  ])
  production_model_custody_verify_environment  = "reference-lab-production-model-custody-verification"
  production_model_custody_verify_workflow_ref = "${var.github_repository}/.github/workflows/production-model-artifact-custody.yml@refs/heads/main"
  production_model_custody_verify_subject      = "model-custody-verify:${var.github_repository_id}:${local.production_model_custody_verify_environment}"
  production_model_custody_verify_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.production_model_custody_verify_workflow_ref}'",
    "assertion.environment == '${local.production_model_custody_verify_environment}'",
  ])
}

resource "google_iam_workload_identity_pool_provider" "production_model_custody_upload" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "production-model-custody-upload"
  display_name                       = "Production model custody upload"
  description                        = "Reserved exact-main create-only model custody identity; no workflow or live transfer is declared."

  attribute_mapping = {
    "google.subject"                  = "'model-custody-upload:' + assertion.repository_id + ':' + assertion.environment"
    "attribute.actor_id"              = "assertion.actor_id"
    "attribute.environment"           = "assertion.environment"
    "attribute.event_name"            = "assertion.event_name"
    "attribute.ref"                   = "assertion.ref"
    "attribute.repository"            = "assertion.repository"
    "attribute.repository_id"         = "assertion.repository_id"
    "attribute.repository_owner_id"   = "assertion.repository_owner_id"
    "attribute.repository_visibility" = "assertion.repository_visibility"
    "attribute.workflow_ref"          = "assertion.workflow_ref"
  }
  attribute_condition = local.production_model_custody_upload_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "production_model_custody_verify" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "production-model-custody-verify"
  display_name                       = "Production model custody verification"
  description                        = "Reserved exact-main generation-pinned verifier and create-only report signer; no workflow or admission authority."

  attribute_mapping = {
    "google.subject"                  = "'model-custody-verify:' + assertion.repository_id + ':' + assertion.environment"
    "attribute.actor_id"              = "assertion.actor_id"
    "attribute.environment"           = "assertion.environment"
    "attribute.event_name"            = "assertion.event_name"
    "attribute.ref"                   = "assertion.ref"
    "attribute.repository"            = "assertion.repository"
    "attribute.repository_id"         = "assertion.repository_id"
    "attribute.repository_owner_id"   = "assertion.repository_owner_id"
    "attribute.repository_visibility" = "assertion.repository_visibility"
    "attribute.workflow_ref"          = "assertion.workflow_ref"
  }
  attribute_condition = local.production_model_custody_verify_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "production_model_custody_writer" {
  project      = google_project.services.project_id
  account_id   = "orchestra-model-custody-writer"
  display_name = "Orchestra production model custody writer"
  description  = "Short-lived create-only model artifact writer. No read, delete, mirror, admission, deployment, or campaign authority."
}

resource "google_service_account" "production_model_custody_verifier" {
  project      = google_project.services.project_id
  account_id   = "orchestra-model-custody-verify"
  display_name = "Orchestra production model custody verifier"
  description  = "Short-lived model artifact reader and create-only signed custody reporter. No artifact mutation or admission authority."
}

resource "google_service_account_iam_member" "production_model_custody_upload_wif" {
  service_account_id = google_service_account.production_model_custody_writer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.production_model_custody_upload_subject}"
}

resource "google_service_account_iam_member" "production_model_custody_verify_wif" {
  service_account_id = google_service_account.production_model_custody_verifier.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.production_model_custody_verify_subject}"
}
