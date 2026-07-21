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

resource "google_iam_workload_identity_pool" "github" {
  project                   = google_project.services.project_id
  workload_identity_pool_id = "orchestra-lab-github"
  display_name              = "Orchestra lab GitHub Actions"
  description               = "Short-lived apply identity; no service-account key exists."

  depends_on = [google_project_service.services]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = google_project.services.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.event_name"       = "assertion.event_name"
    "attribute.job_workflow_ref" = "assertion.job_workflow_ref"
    "attribute.ref"              = "assertion.ref"
    "attribute.repository"       = "assertion.repository"
  }
  attribute_condition = "assertion.repository == '${var.github_repository}' && assertion.ref == 'refs/heads/main' && assertion.event_name == 'workflow_dispatch'"

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

resource "google_service_account_iam_member" "foundation_wif" {
  service_account_id = google_service_account.foundation_executor.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

resource "google_project_iam_member" "foundation" {
  for_each = local.role_bindings

  project = each.value.project
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.foundation_executor.email}"
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
