output "bucket_name" {
  value = google_storage_bucket.main.name
}

output "logs_bucket_name" {
  value = google_logging_project_bucket_config.audit.bucket_id
}

output "vm_name" {
  value = google_compute_instance.vm.name
}

output "vm_service_account_email" {
  value = google_service_account.vm_sa.email
}

output "vpc_name" {
  value = google_compute_network.vpc.name
}
