variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "network_name" {
  description = "Docker network name"
  type        = string
}

variable "minio_root_user" {
  description = "MinIO root username"
  type        = string
  sensitive   = true
}

variable "minio_root_password" {
  description = "MinIO root password"
  type        = string
  sensitive   = true
}

variable "minio_api_port" {
  description = "External port for MinIO API"
  type        = number
  default     = 9000
}

variable "minio_console_port" {
  description = "External port for MinIO console"
  type        = number
  default     = 9001
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
