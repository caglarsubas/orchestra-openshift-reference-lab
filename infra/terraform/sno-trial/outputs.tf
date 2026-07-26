output "project_id" {
  value = google_project.trial.project_id
}

output "project_number" {
  value = google_project.trial.number
}

output "budget_name" {
  value = google_billing_budget.trial.name
}

output "public_dns_delegation" {
  value = {
    managed_zone = google_dns_managed_zone.public_base_domain.name
    dns_name     = google_dns_managed_zone.public_base_domain.dns_name
    name_servers = sort(google_dns_managed_zone.public_base_domain.name_servers)
  }
}

output "trial_contract" {
  value = {
    profile_id                     = local.profile.profileId
    profile_digest                 = local.profile_digest
    target_class                   = local.profile.targetClass
    certification_eligible         = local.profile.certificationEligible
    monthly_budget_usd             = local.profile.guardrails.budget.monthlyUsd
    billing_budget_currency_code   = local.billing_execution.billingCurrencyCode
    billing_budget_amount_units    = local.billing_execution.billingAmountUnits
    budget_exchange_rate_date      = local.billing_execution.conversionRateDate
    budget_is_hard_cap             = local.profile.guardrails.budget.budgetIsHardCap
    maximum_active_hours_per_month = local.profile.guardrails.budget.maxActiveHoursPerMonth
    maximum_lease_hours            = local.profile.guardrails.lease.maximumHours
    automatic_provider_teardown    = local.profile.guardrails.teardown.automaticProviderTeardown
    project_delete_authorized      = var.allow_project_delete
  }
}
