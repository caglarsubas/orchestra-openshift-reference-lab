locals {
  profile = jsondecode(file("${path.module}/../../../config/sno-trial.lock.json"))
  billing_execution = jsondecode(
    file("${path.module}/../../../config/sno-trial-billing-execution.lock.json")
  )

  profile_digest = "sha256:9a7dbdac36417b10ce15b74de4558502fc09cf1740153c5817b89df4c0ba738a"
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

check "locked_billing_execution" {
  assert {
    condition = (
      local.billing_execution.schemaVersion == 1
      && local.billing_execution.kind == "orchestra.openshift.sno-trial-billing-execution.v1"
      && local.billing_execution.profileId == local.profile.profileId
      && local.billing_execution.profileDigest == local.profile_digest
      && local.billing_execution.monthlyUsdCeiling == local.profile.guardrails.budget.monthlyUsd
      && local.billing_execution.billingCurrencyCode == "TRY"
      && local.billing_execution.billingAmountUnits == 3500
      && local.billing_execution.conversionRateTryPerUsd == "47.2497"
      && local.billing_execution.conversionRateDate == "2026-07-24"
      && local.billing_execution.conversionRateSource == "TCMB ForexSelling"
      && local.billing_execution.equivalentUsdAtLockedRate == "74.08"
      && local.billing_execution.budgetIsHardCap == local.profile.guardrails.budget.budgetIsHardCap
    )
    error_message = "The Terraform trial budget no longer matches the reviewed billing execution lock."
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
      currency_code = local.billing_execution.billingCurrencyCode
      units         = tostring(local.billing_execution.billingAmountUnits)
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

moved {
  from = google_dns_managed_zone.public_base_domain
  to   = google_dns_managed_zone.legacy_public_base_domain[0]
}

resource "google_dns_managed_zone" "legacy_public_base_domain" {
  count    = var.retain_legacy_prometa_zone ? 1 : 0
  provider = google.trial

  project = google_project.trial.project_id

  name          = "orchestra-ocp-sno-trial-public"
  dns_name      = "ocp-lab.prometa.ai."
  description   = "Public delegation zone for the non-certifying Orchestra OpenShift SNO trial"
  visibility    = "public"
  force_destroy = false

  depends_on = [google_project_service.required]
}

resource "google_dns_managed_zone" "planeon_public_base_domain" {
  provider = google.trial

  project = google_project.trial.project_id

  name          = "orchestra-ocp-sno-trial-planeon-public"
  dns_name      = "${local.profile.location.dnsZone}."
  description   = "Planeon public delegation zone for the non-certifying Orchestra OpenShift SNO trial"
  visibility    = "public"
  force_destroy = false

  depends_on = [google_project_service.required]
}
