locals {
  project_services = {
    target = toset([
      "cloudapis.googleapis.com",
      "cloudkms.googleapis.com",
      "compute.googleapis.com",
      "dns.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "logging.googleapis.com",
      "monitoring.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ])
    services = toset([
      "artifactregistry.googleapis.com",
      "binaryauthorization.googleapis.com",
      "billingbudgets.googleapis.com",
      "cloudkms.googleapis.com",
      "compute.googleapis.com",
      "container.googleapis.com",
      "containeranalysis.googleapis.com",
      "dns.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "logging.googleapis.com",
      "monitoring.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ])
  }
  foundation_roles = {
    target = toset([
      "roles/compute.admin",
      "roles/compute.networkAdmin",
      "roles/dns.admin",
      "roles/dns.peer",
      "roles/iam.serviceAccountAdmin",
      "roles/iam.serviceAccountUser",
      "roles/resourcemanager.projectIamAdmin",
      "roles/serviceusage.serviceUsageAdmin",
      "roles/storage.admin",
    ])
    services = toset([
      "roles/artifactregistry.admin",
      "roles/cloudkms.admin",
      "roles/compute.admin",
      "roles/compute.networkAdmin",
      "roles/container.admin",
      "roles/dns.admin",
      "roles/iam.serviceAccountAdmin",
      "roles/iam.serviceAccountUser",
      "roles/resourcemanager.projectIamAdmin",
      "roles/serviceusage.serviceUsageAdmin",
      "roles/storage.admin",
    ])
  }
  foundation_planner_roles = {
    target = toset([
      "roles/browser",
      "roles/compute.viewer",
      "roles/dns.reader",
      "roles/iam.securityReviewer",
      "roles/iam.serviceAccountViewer",
      "roles/serviceusage.serviceUsageConsumer",
    ])
    services = toset([
      "roles/artifactregistry.reader",
      "roles/browser",
      "roles/cloudkms.viewer",
      "roles/compute.viewer",
      "roles/container.clusterViewer",
      "roles/dns.reader",
      "roles/iam.securityReviewer",
      "roles/iam.serviceAccountViewer",
      "roles/serviceusage.serviceUsageConsumer",
    ])
  }
  role_bindings = merge(
    {
      for role in local.foundation_roles.target : "target:${role}" => {
        project = google_project.target.project_id
        role    = role
      }
    },
    {
      for role in local.foundation_roles.services : "services:${role}" => {
        project = google_project.services.project_id
        role    = role
      }
    },
  )
  planner_role_bindings = merge(
    {
      for role in local.foundation_planner_roles.target : "target:${role}" => {
        project = google_project.target.project_id
        role    = role
      }
    },
    {
      for role in local.foundation_planner_roles.services : "services:${role}" => {
        project = google_project.services.project_id
        role    = role
      }
    },
  )
  foundation_plan_environment  = "reference-lab-foundation-plan"
  foundation_plan_workflow_ref = "${var.github_repository}/.github/workflows/foundation-plan.yml@refs/heads/main"
  foundation_plan_subject      = "github:${var.github_repository_id}:${local.foundation_plan_environment}"
  foundation_plan_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.foundation_plan_workflow_ref}'",
    "assertion.environment == '${local.foundation_plan_environment}'",
  ])
  foundation_apply_environment  = "reference-lab-foundation-apply"
  foundation_apply_workflow_ref = "${var.github_repository}/.github/workflows/foundation-apply.yml@refs/heads/main"
  foundation_apply_subject      = "foundation-apply:${var.github_repository_id}:${local.foundation_apply_environment}"
  foundation_apply_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.foundation_apply_workflow_ref}'",
    "assertion.environment == '${local.foundation_apply_environment}'",
  ])
  dependency_risk_preflight_environment  = "reference-lab-dependency-risk-preflight"
  dependency_risk_preflight_workflow_ref = "${var.github_repository}/.github/workflows/dependency-risk-preflight.yml@refs/heads/main"
  dependency_risk_preflight_subject      = "dependency-risk-preflight:${var.github_repository_id}:${local.dependency_risk_preflight_environment}"
  dependency_risk_preflight_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.dependency_risk_preflight_workflow_ref}'",
    "assertion.environment == '${local.dependency_risk_preflight_environment}'",
  ])
  dependency_risk_collection_environment  = "reference-lab-dependency-risk-collection"
  dependency_risk_collection_workflow_ref = "${var.github_repository}/.github/workflows/dependency-risk-collection.yml@refs/heads/main"
  dependency_risk_collection_subject      = "dependency-risk-collection:${var.github_repository_id}:${local.dependency_risk_collection_environment}"
  dependency_risk_collection_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.dependency_risk_collection_workflow_ref}'",
    "assertion.environment == '${local.dependency_risk_collection_environment}'",
  ])
  dependency_risk_custody_verification_environment  = "reference-lab-dependency-risk-custody-verification"
  dependency_risk_custody_verification_workflow_ref = "${var.github_repository}/.github/workflows/dependency-risk-custody-verification.yml@refs/heads/main"
  dependency_risk_custody_verification_subject      = "dependency-risk-custody:${var.github_repository_id}:${local.dependency_risk_custody_verification_environment}"
  dependency_risk_custody_verification_wif_condition = join(" && ", [
    "assertion.repository == '${var.github_repository}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.repository_owner_id == '${var.github_repository_owner_id}'",
    "assertion.repository_visibility == 'private'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.workflow_ref == '${local.dependency_risk_custody_verification_workflow_ref}'",
    "assertion.environment == '${local.dependency_risk_custody_verification_environment}'",
  ])
}

resource "google_project" "target" {
  name            = "Orchestra OpenShift Target"
  project_id      = var.target_project_id
  billing_account = var.billing_account
  org_id          = var.parent_type == "organization" ? var.parent_id : null
  folder_id       = var.parent_type == "folder" ? var.parent_id : null
  deletion_policy = "PREVENT"

  labels = {
    environment = "reference-lab"
    plane       = "target"
    managed_by  = "terraform"
  }

  lifecycle {
    precondition {
      condition     = var.target_project_id != var.services_project_id
      error_message = "Target and services/evidence projects must be distinct."
    }
  }
}

resource "google_project" "services" {
  name            = "Orchestra Lab Services"
  project_id      = var.services_project_id
  billing_account = var.billing_account
  org_id          = var.parent_type == "organization" ? var.parent_id : null
  folder_id       = var.parent_type == "folder" ? var.parent_id : null
  deletion_policy = "PREVENT"

  labels = {
    environment = "reference-lab"
    plane       = "services-evidence"
    managed_by  = "terraform"
  }
}

resource "google_project_service" "target" {
  for_each = local.project_services.target

  project            = google_project.target.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_project_service" "services" {
  for_each = local.project_services.services

  project            = google_project.services.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_kms_key_ring" "state" {
  project  = google_project.services.project_id
  name     = "orchestra-lab-terraform-state"
  location = var.region

  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key" "state" {
  name            = "terraform-state"
  key_ring        = google_kms_key_ring.state.id
  rotation_period = "7776000s"
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

data "google_storage_project_service_account" "services" {
  project = google_project.services.project_id

  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key_iam_member" "state_storage_agent" {
  crypto_key_id = google_kms_crypto_key.state.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.services.email_address}"
}

resource "google_storage_bucket" "state" {
  project                     = google_project.services.project_id
  name                        = var.state_bucket_name
  location                    = var.region
  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.state.id
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 30
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_kms_crypto_key_iam_member.state_storage_agent]
}

resource "google_kms_key_ring" "foundation_execution" {
  project  = google_project.services.project_id
  name     = "orchestra-lab-foundation-execution"
  location = var.region

  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key" "foundation_plan_signing" {
  name     = "foundation-plan-signing"
  key_ring = google_kms_key_ring.foundation_execution.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "foundation_apply_receipt_signing" {
  name     = "foundation-apply-receipt-signing"
  key_ring = google_kms_key_ring.foundation_execution.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_managed_folder" "foundation_plans" {
  bucket        = google_storage_bucket.state.name
  name          = "foundation-plans/"
  force_destroy = false
}

resource "google_storage_managed_folder" "foundation_apply_reports" {
  bucket        = google_storage_bucket.state.name
  name          = "foundation-apply-reports/"
  force_destroy = false
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = google_project.services.project_id
  workload_identity_pool_id = "orchestra-lab-github"
  display_name              = "Orchestra lab GitHub Actions"
  description               = "Short-lived workflow identities; no service-account key exists."

  depends_on = [google_project_service.services]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"                  = "'github:' + assertion.repository_id + ':' + assertion.environment"
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
  attribute_condition = local.foundation_plan_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "foundation_apply" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "foundation-apply"
  display_name                       = "Foundation apply"
  description                        = "Exact-main, reviewed saved-plan apply identity; no campaign authority."

  attribute_mapping = {
    "google.subject"                  = "'foundation-apply:' + assertion.repository_id + ':' + assertion.environment"
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
  attribute_condition = local.foundation_apply_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "dependency_risk" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "dependency-risk-preflight"
  display_name                       = "Dependency risk preflight"
  description                        = "Exact-main preflight identity; no collection, mirror, or evidence-write authority."

  attribute_mapping = {
    "google.subject"                  = "'dependency-risk-preflight:' + assertion.repository_id + ':' + assertion.environment"
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
  attribute_condition = local.dependency_risk_preflight_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "dependency_risk_collection" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "dependency-risk-collection"
  display_name                       = "Dependency risk collection"
  description                        = "Exact-main collection identity; no mirror, activation, signed-evidence, or campaign authority."

  attribute_mapping = {
    "google.subject"                  = "'dependency-risk-collection:' + assertion.repository_id + ':' + assertion.environment"
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
  attribute_condition = local.dependency_risk_collection_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "dependency_risk_custody_verification" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "dependency-risk-custody"
  display_name                       = "Dependency risk custody verification"
  description                        = "Exact-main raw-custody verifier; no raw mutation, mirror, admission, activation, or campaign authority."

  attribute_mapping = {
    "google.subject"                  = "'dependency-risk-custody:' + assertion.repository_id + ':' + assertion.environment"
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
  attribute_condition = local.dependency_risk_custody_verification_wif_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "foundation_executor" {
  project      = google_project.services.project_id
  account_id   = "orchestra-lab-foundation"
  display_name = "Orchestra lab foundation executor"
  description  = "Short-lived Terraform executor. No key creation is permitted."
}

resource "google_service_account" "foundation_planner" {
  project      = google_project.services.project_id
  account_id   = "orchestra-lab-foundation-plan"
  display_name = "Orchestra lab foundation planner"
  description  = "Read-only Terraform planner. No key creation or apply permissions are permitted."
}

resource "google_service_account" "foundation_plan_packager" {
  project      = google_project.services.project_id
  account_id   = "orchestra-plan-packager"
  display_name = "Orchestra foundation plan packager"
  description  = "Short-lived plan signer and create-only package writer. No infrastructure or state permissions."
}

resource "google_service_account" "dependency_risk" {
  project      = google_project.services.project_id
  account_id   = "orchestra-dependency-risk"
  display_name = "Orchestra dependency risk preflight"
  description  = "Short-lived preflight signer; receives no project, bucket, mirror, or collection role."
}

resource "google_service_account" "dependency_risk_collector" {
  project      = google_project.services.project_id
  account_id   = "orchestra-risk-collector"
  display_name = "Orchestra dependency risk collector"
  description  = "Short-lived collection signer and create-only raw evidence writer."
}

resource "google_service_account" "dependency_risk_custody_verifier" {
  project      = google_project.services.project_id
  account_id   = "orchestra-custody-verifier"
  display_name = "Orchestra dependency risk custody verifier"
  description  = "Short-lived generation-pinned raw reader and create-only signed custody reporter."
}

resource "google_service_account_iam_member" "foundation_plan_wif" {
  service_account_id = google_service_account.foundation_planner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.foundation_plan_subject}"
}

resource "google_service_account_iam_member" "foundation_plan_packager_wif" {
  service_account_id = google_service_account.foundation_plan_packager.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.foundation_plan_subject}"
}

resource "google_service_account_iam_member" "foundation_apply_wif" {
  service_account_id = google_service_account.foundation_executor.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.foundation_apply_subject}"
}

resource "google_service_account_iam_member" "dependency_risk_wif" {
  service_account_id = google_service_account.dependency_risk.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_preflight_subject}"
}

resource "google_service_account_iam_member" "dependency_risk_collection_wif" {
  service_account_id = google_service_account.dependency_risk_collector.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_collection_subject}"
}

resource "google_service_account_iam_member" "dependency_risk_custody_verification_wif" {
  service_account_id = google_service_account.dependency_risk_custody_verifier.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/${local.dependency_risk_custody_verification_subject}"
}

resource "google_project_iam_member" "foundation" {
  for_each = local.role_bindings

  project = each.value.project
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.foundation_executor.email}"
}

resource "google_project_iam_member" "foundation_planner" {
  for_each = local.planner_role_bindings

  project = each.value.project
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.foundation_planner.email}"
}

resource "google_storage_bucket_iam_member" "foundation_planner_state" {
  for_each = toset([
    "roles/storage.legacyBucketReader",
    "roles/storage.objectViewer",
  ])

  bucket = google_storage_bucket.state.name
  role   = each.value
  member = "serviceAccount:${google_service_account.foundation_planner.email}"
}

resource "google_kms_crypto_key_iam_member" "foundation_plan_packager_signer" {
  crypto_key_id = google_kms_crypto_key.foundation_plan_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.foundation_plan_packager.email}"
}

resource "google_kms_crypto_key_iam_member" "foundation_executor_plan_public_key" {
  crypto_key_id = google_kms_crypto_key.foundation_plan_signing.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.foundation_executor.email}"
}

resource "google_kms_crypto_key_iam_member" "foundation_executor_receipt_signer" {
  crypto_key_id = google_kms_crypto_key.foundation_apply_receipt_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.foundation_executor.email}"
}

resource "google_storage_managed_folder_iam_member" "foundation_plan_packager_writer" {
  bucket         = google_storage_bucket.state.name
  managed_folder = google_storage_managed_folder.foundation_plans.name
  role           = "roles/storage.objectCreator"
  member         = "serviceAccount:${google_service_account.foundation_plan_packager.email}"
}

resource "google_storage_managed_folder_iam_member" "foundation_plan_reviewer" {
  for_each = var.foundation_plan_reviewer_members

  bucket         = google_storage_bucket.state.name
  managed_folder = google_storage_managed_folder.foundation_plans.name
  role           = "roles/storage.objectViewer"
  member         = each.value
}

resource "google_billing_budget" "reference_lab" {
  billing_account = var.billing_account
  display_name    = "Orchestra OpenShift reference lab"

  budget_filter {
    projects = [
      "projects/${google_project.target.number}",
      "projects/${google_project.services.number}",
    ]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.monthly_budget_usd)
    }
  }

  dynamic "threshold_rules" {
    for_each = toset([0.5, 0.8, 1.0, 1.2])
    content {
      threshold_percent = threshold_rules.value
      spend_basis       = "CURRENT_SPEND"
    }
  }

  depends_on = [google_project_service.services]
}
