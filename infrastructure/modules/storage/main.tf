# Storage Module - MinIO S3-compatible storage

resource "docker_image" "minio" {
  name         = "minio/minio:latest"
  keep_locally = true
}

resource "docker_volume" "minio_data" {
  name = "${var.project_name}-minio-data"

  labels {
    label = "project"
    value = var.labels.project
  }
}

resource "docker_container" "minio" {
  name  = "${var.project_name}-minio"
  image = docker_image.minio.image_id

  restart = "unless-stopped"
  command = ["server", "/data", "--console-address", ":9001"]

  networks_advanced {
    name = var.network_name
  }

  ports {
    internal = 9000
    external = var.minio_api_port
  }

  ports {
    internal = 9001
    external = var.minio_console_port
  }

  env = [
    "MINIO_ROOT_USER=${var.minio_root_user}",
    "MINIO_ROOT_PASSWORD=${var.minio_root_password}"
  ]

  volumes {
    volume_name    = docker_volume.minio_data.name
    container_path = "/data"
  }

  healthcheck {
    test         = ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
    interval     = "30s"
    timeout      = "10s"
    retries      = 3
    start_period = "30s"
  }

  dynamic "labels" {
    for_each = var.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

# Create default buckets using MinIO client
resource "docker_container" "minio_setup" {
  name  = "${var.project_name}-minio-setup"
  image = "minio/mc:latest"

  restart = "no"
  rm      = true

  networks_advanced {
    name = var.network_name
  }

  entrypoint = ["/bin/sh", "-c"]
  command = [
    <<-EOT
    sleep 10
    mc alias set local http://${docker_container.minio.name}:9000 ${var.minio_root_user} ${var.minio_root_password}
    mc mb --ignore-existing local/logs
    mc mb --ignore-existing local/detections
    mc mb --ignore-existing local/samples
    mc mb --ignore-existing local/yara-rules
    echo "Buckets created successfully"
    EOT
  ]

  depends_on = [docker_container.minio]
}
