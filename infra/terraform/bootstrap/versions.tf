terraform {
  required_version = "= 1.14.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.8.1"
    }
  }
}

provider "google" {}
