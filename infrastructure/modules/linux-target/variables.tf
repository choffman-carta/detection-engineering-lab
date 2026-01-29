variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "network_name" {
  description = "Docker network name"
  type        = string
}

variable "target_image" {
  description = "Base image for Linux target"
  type        = string
  default     = "ubuntu:22.04"
}

variable "vector_host" {
  description = "Vector container hostname for log forwarding"
  type        = string
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
