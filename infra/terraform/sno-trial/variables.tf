variable "billing_account" {
  description = "Billing account for the disposable SNO trial project."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account))
    error_message = "billing_account must use the canonical six-six-six account ID format."
  }
}

variable "project_id" {
  description = "Globally unique disposable GCP project ID for the SNO trial."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid 6-30 character GCP project ID."
  }
}

variable "project_name" {
  description = "Display name for the disposable SNO trial project."
  type        = string
  default     = "Orchestra OpenShift SNO Trial"

  validation {
    condition     = length(var.project_name) >= 4 && length(var.project_name) <= 30
    error_message = "project_name must be between 4 and 30 characters."
  }
}

variable "region" {
  description = "Locked SNO trial region."
  type        = string
  default     = "europe-west1"

  validation {
    condition     = var.region == "europe-west1"
    error_message = "The SNO trial is locked to europe-west1."
  }
}

variable "allow_project_delete" {
  description = "Permit Terraform to delete the project only after OpenShift and residual-resource teardown."
  type        = bool
  default     = false
}
