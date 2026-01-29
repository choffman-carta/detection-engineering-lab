# Log Shipping Module - Vector for log collection and routing

resource "docker_image" "vector" {
  name         = "timberio/vector:${var.vector_version}"
  keep_locally = true
}

resource "docker_volume" "vector_data" {
  name = "${var.project_name}-vector-data"

  labels {
    label = "project"
    value = var.labels.project
  }
}

# Vector configuration file
resource "local_file" "vector_config" {
  filename = "${path.module}/config/vector.toml"
  content  = <<-EOT
# Vector Configuration for Detection Lab
# Collects logs from various sources and routes to Elasticsearch and S3

[api]
enabled = true
address = "0.0.0.0:8686"

# ============================================================================
# SOURCES - Log ingestion points
# ============================================================================

# Syslog input for Linux containers
[sources.syslog_input]
type = "syslog"
address = "0.0.0.0:5514"
mode = "udp"

# HTTP input for JSON logs (Panther-style)
[sources.http_input]
type = "http_server"
address = "0.0.0.0:8080"
encoding = "json"
path_key = "path"

# File input for mounted log directories
[sources.file_input]
type = "file"
include = ["/var/log/targets/**/*.log", "/var/log/targets/**/*.json"]
read_from = "beginning"

# Docker logs from target containers
[sources.docker_logs]
type = "docker_logs"
docker_host = "unix:///var/run/docker.sock"
include_containers = ["${var.project_name}-linux-target*"]

# ============================================================================
# TRANSFORMS - Log parsing and enrichment
# ============================================================================

# Parse syslog messages
[transforms.parse_syslog]
type = "remap"
inputs = ["syslog_input"]
source = '''
.log_type = "syslog"
.timestamp = .timestamp ?? now()
.host = .hostname ?? "unknown"
'''

# Parse JSON logs and add metadata
[transforms.parse_json_logs]
type = "remap"
inputs = ["http_input"]
source = '''
.log_type = "json"
.timestamp = .timestamp ?? now()
.ingested_at = now()
'''

# Enrich with lab metadata
[transforms.enrich_logs]
type = "remap"
inputs = ["parse_syslog", "parse_json_logs", "file_input", "docker_logs"]
source = '''
.lab_environment = "detection-lab"
.lab_project = "${var.project_name}"
'''

# Detect log source type for routing
[transforms.route_by_type]
type = "route"
inputs = ["enrich_logs"]

  [transforms.route_by_type.route]
  sysmon = '.source_type == "sysmon" || contains(string!(.message), "Sysmon")'
  osquery = '.source_type == "osquery" || .name == "pack"'
  auditd = '.source_type == "auditd" || contains(string!(.message), "type=SYSCALL")'
  security = 'true'

# ============================================================================
# SINKS - Output destinations
# ============================================================================

# Elasticsearch for searchable storage
[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["enrich_logs"]
endpoints = ["http://${var.elasticsearch_host}:${var.elasticsearch_port}"]
bulk.index = "detection-lab-logs-{{ .log_type }}"
encoding.timestamp_format = "rfc3339"

# S3 (MinIO) for Panther-style ingestion testing
[sinks.s3_logs]
type = "aws_s3"
inputs = ["enrich_logs"]
bucket = "logs"
endpoint = "http://${var.minio_endpoint}"
region = "us-east-1"
compression = "gzip"
encoding.codec = "json"
key_prefix = "raw/{{ .log_type }}/year=%Y/month=%m/day=%d/"
auth.access_key_id = "${var.minio_access_key}"
auth.secret_access_key = "${var.minio_secret_key}"

# Console output for debugging
[sinks.console]
type = "console"
inputs = ["enrich_logs"]
encoding.codec = "json"
EOT
}

resource "docker_container" "vector" {
  name  = "${var.project_name}-vector"
  image = docker_image.vector.image_id

  restart = "unless-stopped"

  networks_advanced {
    name = var.network_name
  }

  # Syslog UDP input
  ports {
    internal = 5514
    external = 5514
    protocol = "udp"
  }

  # HTTP input for JSON logs
  ports {
    internal = 8080
    external = 8080
  }

  # Vector API
  ports {
    internal = 8686
    external = 8686
  }

  volumes {
    host_path      = abspath(local_file.vector_config.filename)
    container_path = "/etc/vector/vector.toml"
  }

  volumes {
    volume_name    = docker_volume.vector_data.name
    container_path = "/var/lib/vector"
  }

  # Mount Docker socket for container log collection
  volumes {
    host_path      = "/var/run/docker.sock"
    container_path = "/var/run/docker.sock"
  }

  env = [
    "VECTOR_CONFIG=/etc/vector/vector.toml",
    "VECTOR_LOG=info"
  ]

  healthcheck {
    test         = ["CMD", "curl", "-f", "http://localhost:8686/health"]
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
