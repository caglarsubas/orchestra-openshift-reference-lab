terraform {
  required_version = "= 1.14.6"

  backend "local" {
    path = "../../../restricted/terraform/sno-trial/terraform.tfstate"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.41.0"
    }
  }
}

provider "google" {
  region = var.region
}
