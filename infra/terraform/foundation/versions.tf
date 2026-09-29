terraform {
  required_version = "= 1.14.6"

  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.4.0"
    }
  }
}

provider "google" {
  alias   = "target"
  project = var.target_project_id
  region  = local.region
}

provider "google" {
  alias   = "services"
  project = var.services_project_id
  region  = local.region
}
