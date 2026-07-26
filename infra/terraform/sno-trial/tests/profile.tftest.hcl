mock_provider "google" {
  mock_resource "google_project" {
    defaults = {
      number = "123456789012"
    }
  }

  mock_resource "google_billing_budget" {
    defaults = {
      name = "billingAccounts/000000-000000-000000/budgets/mock"
    }
  }

  mock_resource "google_dns_managed_zone" {
    defaults = {
      name_servers = [
        "ns-cloud-a1.googledomains.com.",
        "ns-cloud-a2.googledomains.com.",
      ]
    }
  }
}

mock_provider "google" {
  alias = "trial"

  mock_resource "google_billing_budget" {
    defaults = {
      name = "billingAccounts/000000-000000-000000/budgets/mock"
    }
  }

  mock_resource "google_dns_managed_zone" {
    defaults = {
      name_servers = [
        "ns-cloud-a1.googledomains.com.",
        "ns-cloud-a2.googledomains.com.",
      ]
    }
  }
}

run "locked_cost_boundary" {
  command = plan

  variables {
    billing_account = "000000-000000-000000"
    project_id      = "prometa-orch-sno-test"
  }

  assert {
    condition     = output.trial_contract.monthly_budget_usd == 75
    error_message = "The trial budget must remain locked to 75 USD."
  }

  assert {
    condition = (
      output.trial_contract.billing_budget_currency_code == "TRY"
      && output.trial_contract.billing_budget_amount_units == 3500
      && output.trial_contract.budget_exchange_rate_date == "2026-07-24"
    )
    error_message = "The provider budget must remain locked to the reviewed TRY conversion."
  }

  assert {
    condition     = output.trial_contract.maximum_active_hours_per_month == 48
    error_message = "The active node-hour ceiling must remain locked to 48."
  }

  assert {
    condition     = output.trial_contract.maximum_lease_hours == 12
    error_message = "The maximum lease must remain locked to 12 hours."
  }

  assert {
    condition     = output.trial_contract.certification_eligible == false
    error_message = "The SNO trial must remain non-certifying."
  }

  assert {
    condition     = output.trial_contract.project_delete_authorized == false
    error_message = "Project deletion must remain disabled by default."
  }

  assert {
    condition     = output.trial_contract.legacy_prometa_zone_retained == false
    error_message = "A fresh trial must not create the legacy Prometa zone."
  }

  assert {
    condition = (
      output.public_dns_delegation.managed_zone == "orchestra-ocp-sno-trial-planeon-public"
      && output.public_dns_delegation.dns_name == "ocp-lab.planeon.ai."
    )
    error_message = "The active SNO trial delegation must remain isolated under planeon.ai."
  }
}

run "reject_region_drift" {
  command = plan

  variables {
    billing_account = "000000-000000-000000"
    project_id      = "prometa-orch-sno-test"
    region          = "us-central1"
  }

  expect_failures = [var.region]
}
