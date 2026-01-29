# Network Module - Docker network for detection lab

resource "docker_network" "lab_network" {
  name   = "${var.project_name}-network"
  driver = "bridge"

  ipam_config {
    subnet = var.subnet
  }

  labels {
    label = "project"
    value = var.labels.project
  }

  labels {
    label = "environment"
    value = var.labels.environment
  }

  labels {
    label = "managed_by"
    value = var.labels.managed_by
  }
}
