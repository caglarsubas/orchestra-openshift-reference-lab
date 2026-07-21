variable "parent_type" {
  description = "GCP resource parent type for both projects."
  type        = string

  validation {
    condition     = contains(["organization", "folder"], var.parent_type)
    error_message = "parent_type must be organization or folder."
  }
}

variable "parent_id" {
  description = "Numeric organization or folder ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.parent_id))
    error_message = "parent_id must be numeric."
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
  description = "Exact owner/repository allowed to request apply identity."
  type        = string
  default     = "caglarsubas/orchestra-openshift-reference-lab"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must use owner/repository syntax."
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
  description = "Reviewed monthly lab budget used for 50/80/100/120 percent alerts."
  type        = number

  validation {
    condition     = var.monthly_budget_usd >= 1000 && floor(var.monthly_budget_usd) == var.monthly_budget_usd
    error_message = "monthly_budget_usd must be an integer of at least 1000."
  }
}
