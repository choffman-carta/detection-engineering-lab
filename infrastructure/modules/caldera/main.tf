# Caldera Module - MITRE Caldera Adversary Emulation Platform
# This module is optional and disabled by default

resource "docker_image" "caldera" {
  name         = "mitre/caldera:${var.caldera_version}"
  keep_locally = true
}

resource "docker_volume" "caldera_data" {
  name = "${var.project_name}-caldera-data"

  labels {
    label = "project"
    value = var.labels.project
  }
}

resource "docker_container" "caldera" {
  name  = "${var.project_name}-caldera"
  image = docker_image.caldera.image_id

  restart = "unless-stopped"

  networks_advanced {
    name = var.network_name
  }

  # Web UI
  ports {
    internal = 8888
    external = var.caldera_port
  }

  # Agent communication
  ports {
    internal = 7010
    external = 7010
  }

  ports {
    internal = 7011
    external = 7011
  }

  ports {
    internal = 7012
    external = 7012
  }

  volumes {
    volume_name    = docker_volume.caldera_data.name
    container_path = "/usr/src/app/data"
  }

  env = [
    "CALDERA_CONFIG=default"
  ]

  healthcheck {
    test         = ["CMD", "curl", "-f", "http://localhost:8888"]
    interval     = "30s"
    timeout      = "10s"
    retries      = 5
    start_period = "60s"
  }

  dynamic "labels" {
    for_each = var.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}
