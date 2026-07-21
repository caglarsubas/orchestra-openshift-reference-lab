variable "target_project_id" {
  description = "Dedicated OpenShift target project."
  type        = string
}

variable "services_project_id" {
  description = "Dedicated dependency and evidence project."
  type        = string
}

variable "signed_evidence_bucket_name" {
  description = "Globally unique 400-day evidence bucket name."
  type        = string
}

variable "raw_evidence_bucket_name" {
  description = "Globally unique restricted raw-artifact bucket name."
  type        = string
}

variable "certification_mode" {
  description = "True only for the frozen live campaign foundation."
  type        = bool
  default     = false
}

variable "lock_signed_evidence_bucket" {
  description = "Irreversibly lock the 400-day retention policy."
  type        = bool
  default     = false
}

variable "retention_lock_acknowledgement" {
  description = "Must equal the exact acknowledgement before irreversible locking."
  type        = string
  default     = ""
  sensitive   = true
}

variable "gke_release_channel" {
  description = "Dependency-plane GKE release channel. Actual version is frozen in campaign evidence."
  type        = string
  default     = "STABLE"

  validation {
    condition     = contains(["STABLE", "EXTENDED"], var.gke_release_channel)
    error_message = "The lab permits only STABLE or EXTENDED GKE channels."
  }
}

variable "bastion_source_image" {
  description = "Pinned, immutable GCE image self-link for the IAP bastion."
  type        = string

  validation {
    condition     = can(regex("^projects/[^/]+/global/images/[^/]+$", var.bastion_source_image))
    error_message = "Use an immutable image name, not an image family."
  }
}

variable "probe_source_image" {
  description = "Pinned, immutable GCE image self-link for external probes."
  type        = string

  validation {
    condition     = can(regex("^projects/[^/]+/global/images/[^/]+$", var.probe_source_image))
    error_message = "Use an immutable image name, not an image family."
  }
}

variable "probe_container_image" {
  description = "Immutable external-probe runner image reference."
  type        = string

  validation {
    condition     = can(regex("^[^@]+@sha256:[a-f0-9]{64}$", var.probe_container_image))
    error_message = "probe_container_image must be pinned by sha256 digest."
  }
}

variable "approved_egress_cidrs" {
  description = "Reviewed public CIDRs allowed during connected-mode installation and certification."
  type        = set(string)

  validation {
    condition = (
      length(var.approved_egress_cidrs) > 0 &&
      alltrue([
        for cidr in var.approved_egress_cidrs :
        can(cidrnetmask(cidr)) && cidr != "0.0.0.0/0" && can(regex("^[0-9.]+/[0-9]+$", cidr))
      ])
    )
    error_message = "Approved egress must contain explicit IPv4 CIDRs and cannot contain 0.0.0.0/0."
  }
}

variable "iap_operator_members" {
  description = "Human groups/users allowed to establish IAP tunnels; use groups, not individual long-lived accounts."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for member in var.iap_operator_members : can(regex("^(group|user):[^@]+@[^@]+$", member))])
    error_message = "IAP operators must be group: or user: IAM members."
  }
}
