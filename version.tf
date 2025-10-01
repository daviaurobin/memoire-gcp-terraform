# =============================================================================
# version.tf — Contrainte versions Terraform & providers
# Repository: memoire-gcp-terraform
# Purpose   : Verrouiller des versions reproductibles et auditées.
# Author    : RD
# Date      : 2025-10-01
#
# Notes
# - Fixer les versions, reproductibilité, CI stable, alignement Checkov/CI.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}
