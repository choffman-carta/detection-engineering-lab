# Detection Engineering Lab - Main Terraform Configuration

locals {
  common_labels = {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  }
}

# Network Module - Docker network for inter-container communication
module "network" {
  source = "./modules/network"

  project_name = var.project_name
  subnet       = var.subnet
  labels       = local.common_labels
}

# SIEM Module - Elasticsearch + Kibana
module "siem" {
  source = "./modules/siem"

  project_name          = var.project_name
  network_name          = module.network.network_name
  elasticsearch_version = var.elasticsearch_version
  elasticsearch_memory  = var.elasticsearch_memory
  kibana_version        = var.kibana_version
  labels                = local.common_labels
}

# Storage Module - MinIO S3-compatible storage
module "storage" {
  source = "./modules/storage"

  project_name        = var.project_name
  network_name        = module.network.network_name
  minio_root_user     = var.minio_root_user
  minio_root_password = var.minio_root_password
  labels              = local.common_labels
}

# Log Shipping Module - Vector
module "log_shipping" {
  source = "./modules/log-shipping"

  project_name       = var.project_name
  network_name       = module.network.network_name
  vector_version     = var.vector_version
  elasticsearch_host = module.siem.elasticsearch_host
  elasticsearch_port = module.siem.elasticsearch_internal_port
  minio_endpoint     = module.storage.minio_internal_endpoint
  minio_access_key   = var.minio_root_user
  minio_secret_key   = var.minio_root_password
  labels             = local.common_labels

  depends_on = [module.siem, module.storage]
}

# Linux Target Module - Ubuntu with security tooling
module "linux_target" {
  source = "./modules/linux-target"

  project_name = var.project_name
  network_name = module.network.network_name
  target_image = var.linux_target_image
  vector_host  = module.log_shipping.vector_host
  labels       = local.common_labels

  depends_on = [module.log_shipping]
}

# Caldera Module - MITRE Caldera (optional)
module "caldera" {
  source = "./modules/caldera"
  count  = var.enable_caldera ? 1 : 0

  project_name    = var.project_name
  network_name    = module.network.network_name
  caldera_version = var.caldera_version
  labels          = local.common_labels
}

# Windows UTM Management (via null_resource)
resource "null_resource" "windows_utm_status" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/utm-windows.sh status || true"
    interpreter = ["/bin/bash", "-c"]
    on_failure  = continue
  }
}
