########################################
# Provider + Locals
########################################
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  project_id = var.project_id
  region     = var.region
  zone       = var.zone

  vpc_name    = "${var.name_prefix}-vpc"
  subnet_name = "${var.name_prefix}-subnet"
  subnet_cidr = "10.10.0.0/24"

  # Buckets
  data_bucket_name      = "${var.name_prefix}-data-${local.project_id}"
  accesslog_bucket_name = "${var.name_prefix}-access-logs-${local.project_id}"

  # Cloud Logging bucket (Log Router)
  audit_log_bucket_id = "memoire-audit-logs"

  # DNS
  dns_policy_name = "${var.name_prefix}-dns-policy"

  # VM/SA
  vm_name    = "${var.name_prefix}-vm"
  vm_sa_name = "${var.name_prefix}-vm-sa"

  # IAP ranges (SSH over IAP)
  iap_ranges = ["35.235.240.0/20"]

  # IAM user
  user_member = "user:${var.oslogin_user_email}"
}

########################################
# Réseau (VPC + Subnet + Flow Logs)
########################################
resource "google_compute_network" "vpc" {
  name                    = local.vpc_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name                     = local.subnet_name
  ip_cidr_range            = local.subnet_cidr
  region                   = local.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true

  # ✅ VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "${var.name_prefix}-allow-iap-ssh"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = local.iap_ranges
  target_tags   = ["iap-ssh"]
}

########################################
# DNS Policy (logging activé)
########################################
resource "google_dns_policy" "policy" {
  name           = local.dns_policy_name
  enable_logging = true

  networks {
    network_url = google_compute_network.vpc.self_link
  }
}

########################################
# Buckets (GCS)
########################################
# Bucket récepteur des access logs
resource "google_storage_bucket" "access_logs" {
  # checkov:skip=CKV_GCP_62: "Bucket dédié à la réception des access logs; pas de cascade infinie pour ce PoC"
  name     = local.accesslog_bucket_name
  project  = local.project_id
  location = upper(local.region)

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning { enabled = true }

  # Rétention souple pour éviter les suppressions involontaires (PoC)
  soft_delete_policy {
    retention_duration_seconds = 604800 # 7 jours
  }

  labels = {
    purpose = "access-logs"
    env     = "poc"
  }
}

# Bucket applicatif (logs d'accès vers access_logs)
resource "google_storage_bucket" "main" {
  name     = local.data_bucket_name
  project  = local.project_id
  location = upper(local.region)

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning { enabled = true }

  logging {
    log_bucket        = google_storage_bucket.access_logs.name
    log_object_prefix = "gcs_access_logs/"
  }

  labels = {
    purpose = "app-data"
    env     = "poc"
  }
}

########################################
# Log Router bucket (Cloud Logging, régional)
########################################
resource "google_logging_project_bucket_config" "audit" {
  project        = local.project_id
  location       = local.region
  bucket_id      = local.audit_log_bucket_id
  retention_days = 30
}

########################################
# Service Account pour la VM + rôle log writer
########################################
resource "google_service_account" "vm_sa" {
  account_id   = local.vm_sa_name
  display_name = "SA for ${local.vm_name}"
}

resource "google_project_iam_member" "vm_sa_logwriter" {
  project = local.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm_sa.email}"
}

########################################
# OS Login global + durcissement au niveau PROJET
########################################
resource "google_compute_project_metadata_item" "enable_oslogin" {
  key   = "enable-oslogin"
  value = "TRUE"
}

resource "google_compute_project_metadata_item" "block_project_ssh_keys" {
  key   = "block-project-ssh-keys"
  value = "TRUE"
}

resource "google_compute_project_metadata_item" "serial_port_disable" {
  key   = "serial-port-enable"
  value = "false"
}

########################################
# VM (sans IP publique, Shielded, IAP)
########################################
resource "google_compute_instance" "vm" {
  # checkov:skip=CKV_GCP_38: "PoC: chiffrement par clés Google (GMEK). Pas de CMEK/CSEK pour limiter complexité/coûts."
  name         = local.vm_name
  machine_type = "e2-micro"
  zone         = local.zone
  tags         = ["iap-ssh"]

  metadata = {
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "false"
  }

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 10
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.name
    # Pas d'access_config -> pas d'IP publique
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["https://www.googleapis.com/auth/logging.write"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

########################################
# IAM lecture granulaire (utilisateur humain)
########################################
resource "google_project_iam_member" "compute_viewer" {
  project = local.project_id
  role    = "roles/compute.viewer"
  member  = local.user_member
}

resource "google_project_iam_member" "logging_viewer" {
  project = local.project_id
  role    = "roles/logging.viewer"
  member  = local.user_member
}

resource "google_project_iam_member" "monitoring_viewer" {
  project = local.project_id
  role    = "roles/monitoring.viewer"
  member  = local.user_member
}

resource "google_project_iam_member" "storage_object_viewer" {
  project = local.project_id
  role    = "roles/storage.objectViewer"
  member  = local.user_member
}

resource "google_project_iam_member" "serviceusage_consumer" {
  project = local.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = local.user_member
}

resource "google_project_iam_member" "iam_security_reviewer" {
  project = local.project_id
  role    = "roles/iam.securityReviewer"
  member  = local.user_member
}

resource "google_project_iam_member" "iap_tunnel_accessor" {
  project = local.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = local.user_member
}

########################################
# 🔶 Prowler quick wins: Audit logs, Sink, Metrics & Alertes
########################################

# (1) Activer les Audit Logs (ADMIN/DATA READ/WRITE) sur tous les services
resource "google_project_iam_audit_config" "all_services" {
  project = local.project_id
  service = "allServices"

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# (2) Log Router Sink qui exporte tout vers le bucket d'audit
resource "google_logging_project_sink" "export_all" {
  project     = local.project_id
  name        = "memoire-export-all"
  destination = "logging.googleapis.com/projects/${local.project_id}/locations/${local.region}/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter      = "" # tout exporter
  disabled    = false
}

# (3) Metrics Logging (log-based) pour activités sensibles
resource "google_logging_metric" "m_audit_config_changes" {
  name   = "audit_config_changes"
  filter = "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\" protoPayload.methodName=\"SetIamPolicy\" protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
}

resource "google_logging_metric" "m_project_ownership_changes" {
  name   = "project_ownership_changes"
  filter = "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\" protoPayload.methodName=\"SetIamPolicy\" protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\" protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\""
}

resource "google_logging_metric" "m_custom_role_changes" {
  name   = "custom_role_changes"
  filter = "protoPayload.serviceName=\"iam.googleapis.com\" (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")"
}

resource "google_logging_metric" "m_vpc_firewall_rule_changes" {
  name   = "vpc_firewall_rule_changes"
  filter = "protoPayload.serviceName=\"compute.googleapis.com\" (protoPayload.methodName:\"firewalls.insert\" OR protoPayload.methodName:\"firewalls.patch\")"
}

resource "google_logging_metric" "m_vpc_network_changes" {
  name   = "vpc_network_changes"
  filter = "protoPayload.serviceName=\"compute.googleapis.com\" (protoPayload.methodName:\"networks.insert\" OR protoPayload.methodName:\"networks.delete\" OR protoPayload.methodName:\"networks.updatePolicy\")"
}

resource "google_logging_metric" "m_vpc_route_changes" {
  name   = "vpc_route_changes"
  filter = "protoPayload.serviceName=\"compute.googleapis.com\" (protoPayload.methodName:\"routes.insert\" OR protoPayload.methodName:\"routes.delete\")"
}

resource "google_logging_metric" "m_bucket_permission_changes" {
  name   = "bucket_permission_changes"
  filter = "protoPayload.serviceName=\"storage.googleapis.com\" protoPayload.methodName=\"storage.setIamPermissions\""
}

resource "google_logging_metric" "m_sql_instance_config_changes" {
  name   = "sql_instance_config_changes"
  filter = "protoPayload.serviceName=\"cloudsql.googleapis.com\" (protoPayload.methodName:\"instances.update\" OR protoPayload.methodName:\"cloudsql.instances.update\")"
}

# (4) Alert Policies (Threshold – pas MQL), resource.type="global" pour métriques de logs
resource "google_monitoring_alert_policy" "a_audit_config_changes" {
  display_name = "Alert - Audit config changes"
  combiner     = "OR"
  conditions {
    display_name = "audit_config_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/audit_config_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_project_ownership_changes" {
  display_name = "Alert - Project ownership changes"
  combiner     = "OR"
  conditions {
    display_name = "project_ownership_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/project_ownership_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_custom_role_changes" {
  display_name = "Alert - Custom role changes"
  combiner     = "OR"
  conditions {
    display_name = "custom_role_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/custom_role_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_vpc_firewall_rule_changes" {
  display_name = "Alert - VPC firewall rule changes"
  combiner     = "OR"
  conditions {
    display_name = "vpc_firewall_rule_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc_firewall_rule_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_vpc_network_changes" {
  display_name = "Alert - VPC network changes"
  combiner     = "OR"
  conditions {
    display_name = "vpc_network_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc_network_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_vpc_route_changes" {
  display_name = "Alert - VPC route changes"
  combiner     = "OR"
  conditions {
    display_name = "vpc_route_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc_route_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_bucket_permission_changes" {
  display_name = "Alert - Bucket IAM changes"
  combiner     = "OR"
  conditions {
    display_name = "bucket_permission_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/bucket_permission_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}

resource "google_monitoring_alert_policy" "a_sql_instance_config_changes" {
  display_name = "Alert - SQL instance config changes"
  combiner     = "OR"
  conditions {
    display_name = "sql_instance_config_changes > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/sql_instance_config_changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = []
      }
      trigger { count = 1 }
    }
  }
}
