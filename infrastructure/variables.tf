variable "docker_host" {
  description = "Docker daemon socket path"
  type        = string
  default     = "unix:///var/run/docker.sock"
}

variable "project_name" {
  description = "Project name prefix for resources"
  type        = string
  default     = "detection-lab"
}

variable "environment" {
  description = "Environment name (local, cloud)"
  type        = string
  default     = "local"
}

# SIEM Configuration
variable "elasticsearch_version" {
  description = "Elasticsearch version"
  type        = string
  default     = "8.11.0"
}

variable "elasticsearch_memory" {
  description = "Elasticsearch JVM heap size"
  type        = string
  default     = "4g"
}

variable "kibana_version" {
  description = "Kibana version"
  type        = string
  default     = "8.11.0"
}

# Storage Configuration
variable "minio_root_user" {
  description = "MinIO root username"
  type        = string
  default     = "minioadmin"
  sensitive   = true
}

variable "minio_root_password" {
  description = "MinIO root password"
  type        = string
  default     = "minioadmin123"
  sensitive   = true
}

# Vector Configuration
variable "vector_version" {
  description = "Vector version"
  type        = string
  default     = "0.34.1-alpine"
}

# Linux Target Configuration
variable "linux_target_image" {
  description = "Linux target container image"
  type        = string
  default     = "ubuntu:22.04"
}

# Optional Components
variable "enable_caldera" {
  description = "Enable MITRE Caldera container"
  type        = bool
  default     = false
}

variable "caldera_version" {
  description = "Caldera version"
  type        = string
  default     = "4.2.0"
}

# Network Configuration
variable "subnet" {
  description = "Docker network subnet"
  type        = string
  default     = "172.28.0.0/16"
}
