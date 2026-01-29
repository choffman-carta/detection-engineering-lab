variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "subnet" {
  description = "Docker network subnet CIDR"
  type        = string
  default     = "172.28.0.0/16"
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
