output "elasticsearch_host" {
  description = "Elasticsearch container hostname"
  value       = docker_container.elasticsearch.name
}

output "elasticsearch_port" {
  description = "Elasticsearch external port"
  value       = var.elasticsearch_port
}

output "elasticsearch_internal_port" {
  description = "Elasticsearch internal port"
  value       = 9200
}

output "elasticsearch_url" {
  description = "Elasticsearch URL (external)"
  value       = "http://localhost:${var.elasticsearch_port}"
}

output "kibana_host" {
  description = "Kibana container hostname"
  value       = docker_container.kibana.name
}

output "kibana_port" {
  description = "Kibana external port"
  value       = var.kibana_port
}

output "kibana_url" {
  description = "Kibana URL (external)"
  value       = "http://localhost:${var.kibana_port}"
}
