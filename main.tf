############################
# Services à activer
############################
resource "google_project_service" "services" {
  for_each = toset([
    "compute.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "cloudkms.googleapis.com",
    "iap.googleapis.com",
  ])
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

############################
# Réseau VPC + Subnet + Firewall
############################
resource "google_compute_network" "vpc" {
  name                    = "memoire-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

# ➜ Flow Logs via log_config (sans enable_flow_logs)
resource "google_compute_subnetwork" "subnet" {
  name                     = "memoire-subnet"
  ip_cidr_range            = "10.10.0.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = false
  stack_type               = "IPV4_ONLY"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ➜ Logging activé sur la règle
resource "google_compute_firewall" "allow_iap_ssh" {
  name      = "memoire-allow-iap-ssh"
  network   = google_compute_network.vpc.name
  project   = var.project_id
  direction = "INGRESS"
  priority  = 1000

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["iap-ssh"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

############################
# Durcissement par métadonnées PROJET
############################
resource "google_compute_project_metadata_item" "enable_oslogin" {
  project = var.project_id
  key     = "enable-oslogin"
  value   = "TRUE"
}

resource "google_compute_project_metadata_item" "block_project_ssh_keys" {
  project = var.project_id
  key     = "block-project-ssh-keys"
  value   = "TRUE"
}

resource "google_compute_project_metadata_item" "serial_port_enable" {
  project = var.project_id
  key     = "serial-port-enable"
  value   = "false"
}

############################
# KMS (CMEK) pour GCS
############################
resource "google_kms_key_ring" "kr" {
  name     = "memoire-kr"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "ck" {
  name            = "memoire-ck"
  key_ring        = google_kms_key_ring.kr.id
  rotation_period = "2592000s" # 30 jours
}

# Compte de service GCS du projet (pour CMEK)
data "google_storage_project_service_account" "gcs_sa" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_binding" "kms_for_gcs" {
  crypto_key_id = google_kms_crypto_key.ck.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members = [
    "serviceAccount:${data.google_storage_project_service_account.gcs_sa.email_address}",
  ]
}

############################
# Buckets GCS
############################

# Bucket de logs d’accès GCS
resource "google_storage_bucket" "access_logs" {
  name                        = "memoire-access-logs-${var.project_id}"
  project                     = var.project_id
  location                    = "EUROPE-WEST1"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  labels = {
    goog-terraform-provisioned = "true"
  }
}

# Bucket principal de données, chiffré par CMEK + logging vers access_logs
resource "google_storage_bucket" "main" {
  name                        = "memoire-data-${var.project_id}"
  project                     = var.project_id
  location                    = "EUROPE-WEST1"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  labels = {
    goog-terraform-provisioned = "true"
  }

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.ck.id
  }

  logging {
    log_bucket        = google_storage_bucket.access_logs.name
    log_object_prefix = "gcs_access"
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      num_newer_versions = 10
    }
  }
}

############################
# Logging (Audit Logs) – rétention 365j
############################
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "memoire-audit-logs"
  retention_days = 365
}

resource "google_logging_project_sink" "audit_sink" {
  name        = "memoire-audit-sink"
  project     = var.project_id
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter      = "logName:cloudaudit.googleapis.com"
}

# Activer les journaux Admin/Data pour GCS (Data Access)
resource "google_project_iam_audit_config" "gcs_data_access" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

############################
# IAM de confort pour ton user
############################
resource "google_project_iam_binding" "viewer" {
  project = var.project_id
  role    = "roles/viewer"
  members = ["user:daviau.robin@gmail.com"]
}

resource "google_project_iam_binding" "oslogin" {
  project = var.project_id
  role    = "roles/compute.osLogin"
  members = ["user:daviau.robin@gmail.com"]
}

resource "google_project_iam_binding" "oslogin_admin" {
  project = var.project_id
  role    = "roles/compute.osAdminLogin"
  members = ["user:daviau.robin@gmail.com"]
}

resource "google_project_iam_binding" "iap" {
  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  members = ["user:daviau.robin@gmail.com"]
}

############################
# VM + Service Account minimal
############################
resource "google_service_account" "vm_sa" {
  project      = var.project_id
  account_id   = "memoire-vm-sa"
  display_name = "SA minimal pour memoire-vm"
}

# Principe du moindre privilège : écriture Logging seulement
resource "google_project_iam_binding" "sa_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  members = [
    "serviceAccount:${google_service_account.vm_sa.email}",
  ]
}

resource "google_compute_instance" "vm" {
  name                      = "memoire-vm"
  project                   = var.project_id
  zone                      = var.zone
  machine_type              = "e2-micro"
  allow_stopping_for_update = true

  tags = ["iap-ssh"]

  labels = {
    goog-terraform-provisioned = "true"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
      type  = "pd-balanced"
    }
  }

  # Pas d'IP publique : accès via IAP
  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id
  }

  # Durcissement au niveau instance (en plus du niveau projet)
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "false"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["https://www.googleapis.com/auth/logging.write"]
  }
}
