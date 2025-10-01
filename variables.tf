# =============================================================================
# variables.tf — Variables d'entrée du module racine
# Repository: memoire-gcp-terraform
# Purpose   : Centraliser les paramètres (projet, régions, noms).
# Author    : RD
# Date      : 2025-10-01
#
# Notes
# - Variables: lisibilité + réutilisation + sécurité.
# - Checkov: favorise la factorisation et les valeurs explicites.
# =============================================================================

variable "project_id" {
  description = "ID du projet GCP"
  type        = string
  default     = "direct-byte-472309-n3"
}

variable "region" {
  description = "Région par défaut"
  type        = string
  default     = "europe-west1"
}

variable "zone" {
  description = "Zone par défaut"
  type        = string
  default     = "europe-west1-b"
}

variable "oslogin_user_email" {
  description = "Email de l'utilisateur humain (lecture + IAP)"
  type        = string
  default     = "daviau.robin@gmail.com"
}

variable "name_prefix" {
  description = "Préfixe des ressources"
  type        = string
  default     = "memoire"
}

