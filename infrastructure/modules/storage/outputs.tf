output "minio_host" {
  description = "MinIO container hostname"
  value       = docker_container.minio.name
}

output "minio_api_port" {
  description = "MinIO API external port"
  value       = var.minio_api_port
}

output "minio_console_port" {
  description = "MinIO console external port"
  value       = var.minio_console_port
}

output "minio_internal_endpoint" {
  description = "MinIO internal endpoint for other containers"
  value       = "${docker_container.minio.name}:9000"
}

output "minio_api_url" {
  description = "MinIO API URL (external)"
  value       = "http://localhost:${var.minio_api_port}"
}

output "minio_console_url" {
  description = "MinIO console URL (external)"
  value       = "http://localhost:${var.minio_console_port}"
}

output "buckets" {
  description = "Default buckets created"
  value       = ["logs", "detections", "samples", "yara-rules"]
}
