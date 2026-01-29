output "elasticsearch_url" {
  description = "Elasticsearch API URL"
  value       = "http://localhost:${module.siem.elasticsearch_port}"
}

output "kibana_url" {
  description = "Kibana web UI URL"
  value       = "http://localhost:${module.siem.kibana_port}"
}

output "minio_api_url" {
  description = "MinIO S3 API URL"
  value       = "http://localhost:${module.storage.minio_api_port}"
}

output "minio_console_url" {
  description = "MinIO web console URL"
  value       = "http://localhost:${module.storage.minio_console_port}"
}

output "network_name" {
  description = "Docker network name"
  value       = module.network.network_name
}

output "linux_target_ip" {
  description = "Linux target container IP"
  value       = module.linux_target.container_ip
}

output "caldera_url" {
  description = "Caldera web UI URL (if enabled)"
  value       = var.enable_caldera ? "http://localhost:${module.caldera[0].caldera_port}" : "Caldera disabled"
}
