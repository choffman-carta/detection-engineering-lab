output "network_name" {
  description = "Docker network name"
  value       = docker_network.lab_network.name
}

output "network_id" {
  description = "Docker network ID"
  value       = docker_network.lab_network.id
}
