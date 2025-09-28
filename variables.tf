variable "project_id" {
  description = "ID du projet GCP"
  type        = string
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

# Utilisateur autorisé pour OS Login / IAP (et sudo si admin)
variable "oslogin_user_email" {
  description = "Email du compte utilisateur autorisé pour OS Login + IAP (+ sudo si osAdminLogin)"
  type        = string
}

# Préfixe de nommage des ressources
variable "name_prefix" {
  description = "Préfixe de nommage des ressources"
  type        = string
  default     = "memoire"
}
