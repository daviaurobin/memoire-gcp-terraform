############################################
# main.tf — déploiement minimal sécurisé GCP
############################################

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ---------------------------------------------------------
# 0) Activer les APIs nécessaires
# ---------------------------------------------------------
resource "google_project_service" "services" {
  for_each = toset([
    "compute.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "cloudkms.googleapis.com",
    "iap.googleapis.com",
  ])
  project = var.project_id
  service = each.value
}

# ---------------------------------------------------------
# 1) KMS : clé gérée par nous (CMEK) pour GCS
# ---------------------------------------------------------
resource "google_kms_key_ring" "kr" {
  name       = "${var.name_prefix}-kr"
  location   = var.region
  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key" "ck" {
  name            = "${var.name_prefix}-ck"
  key_ring        = google_kms_key_ring.kr.id
  rotation_period = "2592000s" # 30 jours (académique)
}

# Récupère / crée le service account "Storage Service Agent" du projet
data "google_storage_project_service_account" "gcs_sa" {
  project    = var.project_id
  depends_on = [google_project_service.services]
}

# Autorise GCS à chiffrer avec la clé CMEK
resource "google_kms_crypto_key_iam_binding" "kms_for_gcs" {
  crypto_key_id = google_kms_crypto_key.ck.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members       = ["serviceAccount:${data.google_storage_project_service_account.gcs_sa.email_address}"]
  depends_on    = [google_project_service.services]
}

# ---------------------------------------------------------
# 2) Buckets Cloud Storage
#    - bucket de logs d’accès
#    - bucket principal avec UBLA, PAP, versioning, CMEK, logs
# ---------------------------------------------------------
resource "google_storage_bucket" "access_logs" {
  name                        = "${var.name_prefix}-access-logs-${var.project_id}"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  depends_on                  = [google_project_service.services]
}

resource "google_storage_bucket" "main" {
  name                        = "${var.name_prefix}-data-${var.project_id}"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning { enabled = true }

  # Chiffrement par défaut avec notre clé KMS
  encryption {
    default_kms_key_name = google_kms_crypto_key.ck.id
  }

  # Logs d'accès vers le bucket dédié
  logging {
    log_bucket        = google_storage_bucket.access_logs.name
    log_object_prefix = "gcs_access"
  }

  # Exemple académique : ne garder que 10 versions
  lifecycle_rule {
    condition { num_newer_versions = 10 }
    action    { type = "Delete" }
  }

  depends_on = [
    google_kms_crypto_key_iam_binding.kms_for_gcs,
    google_project_service.services
  ]
}

# ---------------------------------------------------------
# 3) Cloud Logging : bucket dédié + sink pour Cloud Audit Logs
# ---------------------------------------------------------
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = "global"
  retention_days = 30
  bucket_id      = "${var.name_prefix}-audit-logs"
  depends_on     = [google_project_service.services]
}

# Lorsque la destination est un log bucket du même projet,
# le sink est automatiquement autorisé (pas de binding IAM à ajouter).
resource "google_logging_project_sink" "audit_sink" {
  name                   = "${var.name_prefix}-audit-sink"
  destination            = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter                 = "logName:cloudaudit.googleapis.com"
  unique_writer_identity = true
  depends_on             = [google_logging_project_bucket_config.audit]
}

# (Option) Cloud Audit Logs — Data Access pour GCS (plus verbeux)
resource "google_project_iam_audit_config" "gcs_data_access" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ"  }
  audit_log_config { log_type = "DATA_WRITE" }
}

# ---------------------------------------------------------
# 4) Réseau + firewall minimal : pas d'IP publique ; SSH via IAP
# ---------------------------------------------------------
resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.services]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.name_prefix}-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

# Autorise le range IAP vers TCP/22 uniquement
resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "${var.name_prefix}-allow-iap-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]  # plage IP d'IAP
  target_tags   = ["iap-ssh"]
}

# ---------------------------------------------------------
# 5) Service account dédié pour la VM (moindre privilège)
# ---------------------------------------------------------
resource "google_service_account" "vm_sa" {
  account_id   = "${var.name_prefix}-vm-sa"
  display_name = "SA minimal pour ${var.name_prefix}-vm"
}

# Rôle minimal pour écrire dans Cloud Logging
resource "google_project_iam_binding" "sa_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  members = ["serviceAccount:${google_service_account.vm_sa.email}"]
}

# ---------------------------------------------------------
# 6) VM sécurisée (Shielded, pas d'IP publique, OS Login)
#     → ATTENTION : changement de service account/scopes remplace la VM
# ---------------------------------------------------------
resource "google_compute_instance" "vm" {
  name         = "${var.name_prefix}-vm"
  machine_type = "e2-micro"        # éligible Free Tier
  zone         = var.zone
  tags         = ["iap-ssh"]

  allow_stopping_for_update = true  # ← permet d'arrêter/redémarrer pour appliquer les changements

  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
      size  = 10
      type  = "pd-balanced"
    }
  }

  # Pas d'IP publique (pas de bloc access_config)
  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin         = "TRUE"   # OS Login obligatoire
    block-project-ssh-keys = "TRUE"   # désactive les clés SSH metadata
  }

  # Service account dédié + scope minimal
  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["https://www.googleapis.com/auth/logging.write"]
  }

  depends_on = [
    google_compute_firewall.allow_iap_ssh,
    google_project_service.services
  ]
}

# ---------------------------------------------------------
# 7) IAM minimal pour l’accès admin via IAP/OS Login (+sudo)
# ---------------------------------------------------------
resource "google_project_iam_binding" "viewer" {
  project = var.project_id
  role    = "roles/viewer"
  members = ["user:${var.oslogin_user_email}"]
}

resource "google_project_iam_binding" "oslogin" {
  project = var.project_id
  role    = "roles/compute.osLogin"
  members = ["user:${var.oslogin_user_email}"]
}

resource "google_project_iam_binding" "oslogin_admin" {
  project = var.project_id
  role    = "roles/compute.osAdminLogin"
  members = ["user:${var.oslogin_user_email}"]
}

resource "google_project_iam_binding" "iap" {
  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  members = ["user:${var.oslogin_user_email}"]
}
