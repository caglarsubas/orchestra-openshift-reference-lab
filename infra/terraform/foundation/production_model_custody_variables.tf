variable "production_model_artifact_bucket_name" {
  description = "Optional globally unique production model custody bucket override; defaults from the services project ID."
  type        = string
  default     = ""

  validation {
    condition = (
      var.production_model_artifact_bucket_name == ""
      || (
        length(var.production_model_artifact_bucket_name) >= 3
        && length(var.production_model_artifact_bucket_name) <= 63
        && can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.production_model_artifact_bucket_name))
      )
    )
    error_message = "Leave empty for the project-derived default, or use a globally unique 3-63 character lowercase GCS bucket name containing only letters, numbers, and hyphens."
  }
}
