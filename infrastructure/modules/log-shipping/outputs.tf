output "vector_host" {
  description = "Vector container hostname"
  value       = docker_container.vector.name
}

output "vector_syslog_port" {
  description = "Vector syslog UDP port"
  value       = 5514
}

output "vector_http_port" {
  description = "Vector HTTP input port"
  value       = 8080
}

output "vector_api_port" {
  description = "Vector API port"
  value       = 8686
}

output "vector_syslog_endpoint" {
  description = "Vector syslog endpoint for targets"
  value       = "${docker_container.vector.name}:5514"
}

output "vector_http_endpoint" {
  description = "Vector HTTP endpoint for JSON logs"
  value       = "http://${docker_container.vector.name}:8080"
}
