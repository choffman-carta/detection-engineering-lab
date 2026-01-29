variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "network_name" {
  description = "Docker network name"
  type        = string
}

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

variable "elasticsearch_port" {
  description = "External port for Elasticsearch API"
  type        = number
  default     = 9200
}

variable "elasticsearch_transport_port" {
  description = "External port for Elasticsearch transport"
  type        = number
  default     = 9300
}

variable "kibana_version" {
  description = "Kibana version"
  type        = string
  default     = "8.11.0"
}

variable "kibana_port" {
  description = "External port for Kibana"
  type        = number
  default     = 5601
}

variable "labels" {
  description = "Common labels for resources"
  type        = map(string)
  default     = {}
}
