variable "parent_type" {
  description = "GCP resource parent type for both projects. Use none for unorganized no-parent projects (lab operator path when Cloud Identity org is unavailable)."
  type        = string

  validation {
    condition     = contains(["organization", "folder", "none"], var.parent_type)
    error_message = "parent_type must be organization, folder, or none."
  }
}

variable "parent_id" {
  description = "Numeric organization or folder ID. Empty when parent_type is none."
  type        = string
  default     = ""

  validation {
    condition = (
      (var.parent_type == "none" && var.parent_id == "")
      || (var.parent_type != "none" && can(regex("^[0-9]+$", var.parent_id)))
    )
    error_message = "parent_id must be numeric for organization/folder, or empty when parent_type is none."
  }
}

variable "billing_account" {
  description = "Billing account attached to both dedicated projects."
  type        = string
  sensitive   = true
}

variable "target_project_id" {
  description = "Dedicated OpenShift target project ID."
  type        = string
}

variable "services_project_id" {
  description = "Dedicated dependency and evidence project ID."
  type        = string
}

variable "state_bucket_name" {
  description = "Globally unique mutable Terraform state bucket name."
  type        = string
}

variable "github_repository" {
  description = "Exact private owner/repository allowed to request the plan identity."
  type        = string
  default     = "caglarsubas/orchestra-openshift-reference-lab"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must use owner/repository syntax."
  }
}

variable "github_repository_id" {
  description = "Immutable numeric GitHub repository ID allowed to request the plan identity."
  type        = string
  default     = "1307302690"

  validation {
    condition     = var.github_repository_id == "1307302690"
    error_message = "The reference-lab plan identity is locked to repository ID 1307302690."
  }
}

variable "github_repository_owner_id" {
  description = "Immutable numeric GitHub owner ID allowed to request the plan identity."
  type        = string
  default     = "37515097"

  validation {
    condition     = var.github_repository_owner_id == "37515097"
    error_message = "The reference-lab plan identity is locked to owner ID 37515097."
  }
}

variable "region" {
  description = "Locked lab region."
  type        = string
  default     = "europe-west1"

  validation {
    condition     = var.region == "europe-west1"
    error_message = "The reference profile is locked to europe-west1."
  }
}

variable "monthly_budget_usd" {
  description = "Reviewed monthly lab budget amount (integer) used for 50/80/100/120 percent alerts. Name retained for compatibility; currency is billing_currency_code."
  type        = number

  validation {
    condition     = var.monthly_budget_usd >= 1000 && floor(var.monthly_budget_usd) == var.monthly_budget_usd
    error_message = "monthly_budget_usd must be an integer of at least 1000."
  }
}

variable "billing_currency_code" {
  description = "ISO 4217 currency code for the billing account budget amount."
  type        = string
  default     = "USD"

  validation {
    condition     = can(regex("^[A-Z]{3}$", var.billing_currency_code))
    error_message = "billing_currency_code must be a three-letter ISO currency code."
  }
}

variable "foundation_plan_reviewer_members" {
  description = "Approved human groups allowed to read immutable foundation plan packages for review."
  type        = set(string)

  validation {
    condition = (
      length(var.foundation_plan_reviewer_members) >= 1
      && alltrue([
        for member in var.foundation_plan_reviewer_members :
        can(regex("^group:[^@]+@[^@]+$", member))
      ])
    )
    error_message = "At least one foundation plan reviewer is required, and every member must use group: IAM syntax."
  }
}
