# =============================================================================
# backend.tf — Backend Terraform (GCS) pour le state distant
# Repository: memoire-gcp-terraform
# Purpose   : IaC pour GCP
# Author    : RD
# Date      : 2025-10-01
#
# Notes
# - Le backend GCS centralise l’état Terraform (verrouillage + historique).
# - Conformité: séparation du state → facilite l’audit, évite la perte locale.
# - Le bucket a PAP "enforced" + UBLA activés (fait en amont via gsutil).
# =============================================================================

terraform {
  backend "gcs" {
    bucket = "memoire-tfstate-direct-byte-472309-n3" # Bucket créé en amont
    prefix = "terraform/state"                       # Arborescence logique
  }
}
