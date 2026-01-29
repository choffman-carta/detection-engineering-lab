variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "network_name" {
  description = "Docker network name"
  type        = string
}

variable "caldera_version" {
  description = "Caldera version tag"
  type        = string
  default     = "4.2.0"
}

variable "caldera_port" {
  description = "External port for Caldera web UI"
  type        = number
  default     = 8888
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
