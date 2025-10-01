terraform {
  backend "gcs" {
    bucket = "memoire-tfstate-direct-byte-472309-n3"
    prefix = "terraform/state"
  }
}
