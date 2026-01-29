output "caldera_host" {
  description = "Caldera container hostname"
  value       = docker_container.caldera.name
}

output "caldera_port" {
  description = "Caldera web UI port"
  value       = var.caldera_port
}

output "caldera_url" {
  description = "Caldera web UI URL"
  value       = "http://localhost:${var.caldera_port}"
}

output "agent_ports" {
  description = "Caldera agent communication ports"
  value       = [7010, 7011, 7012]
}
