terraform {
  required_version = "= 1.14.6"

  backend "local" {
    path = "../../../restricted/terraform/sno-trial/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.45.0"
    }
  }
}

provider "google" {
  region = var.region
}

provider "google" {
  alias = "trial"

  project               = var.project_id
  region                = var.region
  billing_project       = var.project_id
  user_project_override = true
}
