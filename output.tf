# =============================================================================
# output.tf — Valeurs d'outputs pour CI et lecture rapide
# Repository: memoire-gcp-terraform
# Purpose   : Exposer les identifiants utiles (VM, VPC, Buckets) à la CI.
# Author    : RD
# Date      : 2025-10-01
#
# Notes
# - Utile pour les logs d’actions et les étapes Prowler/rapports.
# - Pas d’infos sensibles (pas de clés/secrets en outputs).
# =============================================================================

output "bucket_name" {
  description = "Bucket principal de données"
  value       = google_storage_bucket.main.name
}

output "logs_bucket_name" {
  description = "Bucket d'audit/logs"
  value       = google_logging_project_bucket_config.audit.bucket_id
}

output "vm_name" {
  description = "Nom de la VM de démonstration"
  value       = google_compute_instance.vm.name
}

output "vm_service_account_email" {
  description = "SA utilisée par la VM"
  value       = google_service_account.vm_sa.email
}

output "vpc_name" {
  description = "Nom du VPC principal"
  value       = google_compute_network.vpc.name
}
