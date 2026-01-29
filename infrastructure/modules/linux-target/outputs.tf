output "container_name" {
  description = "Linux target container name"
  value       = docker_container.linux_target.name
}

output "container_id" {
  description = "Linux target container ID"
  value       = docker_container.linux_target.id
}

output "container_ip" {
  description = "Linux target container IP address"
  value       = docker_container.linux_target.network_data[0].ip_address
}
