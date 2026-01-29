variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "network_name" {
  description = "Docker network name"
  type        = string
}

variable "vector_version" {
  description = "Vector version tag"
  type        = string
  default     = "0.34.1-alpine"
}

variable "elasticsearch_host" {
  description = "Elasticsearch container hostname"
  type        = string
}

variable "elasticsearch_port" {
  description = "Elasticsearch port"
  type        = number
  default     = 9200
}

variable "minio_endpoint" {
  description = "MinIO internal endpoint (host:port)"
  type        = string
}

variable "minio_access_key" {
  description = "MinIO access key"
  type        = string
  sensitive   = true
}

variable "minio_secret_key" {
  description = "MinIO secret key"
  type        = string
  sensitive   = true
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
