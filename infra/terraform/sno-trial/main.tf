locals {
  profile = jsondecode(file("${path.module}/../../../config/sno-trial.lock.json"))

  profile_digest = "sha256:0e660bc8552fd9714d97e7063511751d633fb7aee0f39729733034728e8d2a4b"
  required_services = toset([
    "billingbudgets.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "storage.googleapis.com",
  ])
}

check "locked_trial_profile" {
  assert {
    condition = (
      local.profile.profileId == "orchestra-ocp-sno-trial-amd64-v1"
      && local.profile.targetClass == "engineering-trial"
      && local.profile.executionMode == "live"
      && local.profile.certificationEligible == false
      && local.profile.location.region == var.region
      && local.profile.projects.count == 1
      && local.profile.projects.mustBeEphemeral == true
      && local.profile.guardrails.budget.monthlyUsd == 75
      && local.profile.guardrails.budget.alertPercentages == [10, 25, 50, 75, 90, 100]
      && local.profile.guardrails.budget.budgetIsHardCap == false
      && local.profile.guardrails.budget.maxActiveHoursPerMonth == 48
      && local.profile.guardrails.lease.maximumHours == 12
      && local.profile.guardrails.teardown.required == true
      && local.profile.guardrails.teardown.automaticProviderTeardown == false
    )
    error_message = "The Terraform trial foundation no longer matches the locked SNO profile."
  }
}

resource "google_project" "trial" {
  name                = var.project_name
  project_id          = var.project_id
  billing_account     = var.billing_account
  auto_create_network = false
  deletion_policy     = var.allow_project_delete ? "DELETE" : "PREVENT"

  labels = {
    environment            = "engineering-trial"
    managed-by             = "terraform"
    certification-eligible = "false"
  }
}

resource "google_project_service" "serviceusage" {
  project                    = google_project.trial.project_id
  service                    = "serviceusage.googleapis.com"
  disable_dependent_services = true
  disable_on_destroy         = false
}

resource "google_project_service" "required" {
  for_each = local.required_services

  project                    = google_project.trial.project_id
  service                    = each.value
  disable_dependent_services = true
  disable_on_destroy         = false

  depends_on = [google_project_service.serviceusage]
}

resource "google_billing_budget" "trial" {
  provider = google.trial

  billing_account = var.billing_account
  display_name    = "Orchestra OpenShift SNO trial - ${google_project.trial.project_id}"

  budget_filter {
    projects               = ["projects/${google_project.trial.number}"]
    credit_types_treatment = "EXCLUDE_ALL_CREDITS"
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(local.profile.guardrails.budget.monthlyUsd)
    }
  }

  dynamic "threshold_rules" {
    for_each = toset(local.profile.guardrails.budget.alertPercentages)
    content {
      threshold_percent = threshold_rules.value / 100
      spend_basis       = "CURRENT_SPEND"
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_dns_managed_zone" "public_base_domain" {
  provider = google.trial

  project = google_project.trial.project_id

  name          = "orchestra-ocp-sno-trial-public"
  dns_name      = "${local.profile.location.dnsZone}."
  description   = "Public delegation zone for the non-certifying Orchestra OpenShift SNO trial"
  visibility    = "public"
  force_destroy = false

  depends_on = [google_project_service.required]
}
