# SIEM Module - Elasticsearch + Kibana

resource "docker_image" "elasticsearch" {
  name         = "docker.elastic.co/elasticsearch/elasticsearch:${var.elasticsearch_version}"
  keep_locally = true
}

resource "docker_image" "kibana" {
  name         = "docker.elastic.co/kibana/kibana:${var.kibana_version}"
  keep_locally = true
}

resource "docker_volume" "elasticsearch_data" {
  name = "${var.project_name}-elasticsearch-data"

  labels {
    label = "project"
    value = var.labels.project
  }
}

resource "docker_container" "elasticsearch" {
  name  = "${var.project_name}-elasticsearch"
  image = docker_image.elasticsearch.image_id

  restart = "unless-stopped"

  networks_advanced {
    name = var.network_name
  }

  ports {
    internal = 9200
    external = var.elasticsearch_port
  }

  ports {
    internal = 9300
    external = var.elasticsearch_transport_port
  }

  env = [
    "discovery.type=single-node",
    "xpack.security.enabled=false",
    "xpack.security.enrollment.enabled=false",
    "ES_JAVA_OPTS=-Xms${var.elasticsearch_memory} -Xmx${var.elasticsearch_memory}",
    "cluster.name=${var.project_name}-cluster",
    "node.name=${var.project_name}-node1"
  ]

  volumes {
    volume_name    = docker_volume.elasticsearch_data.name
    container_path = "/usr/share/elasticsearch/data"
  }

  healthcheck {
    test         = ["CMD-SHELL", "curl -s http://localhost:9200/_cluster/health | grep -q '\"status\":\"green\"\\|\"status\":\"yellow\"'"]
    interval     = "30s"
    timeout      = "10s"
    retries      = 5
    start_period = "60s"
  }

  dynamic "labels" {
    for_each = var.labels
    content {
      label = labels.key
      value = labels.value
    }
  }
}

resource "docker_container" "kibana" {
  name  = "${var.project_name}-kibana"
  image = docker_image.kibana.image_id

  restart = "unless-stopped"

  networks_advanced {
    name = var.network_name
  }

  ports {
    internal = 5601
    external = var.kibana_port
  }

  env = [
    "ELASTICSEARCH_HOSTS=http://${docker_container.elasticsearch.name}:9200",
    "SERVER_NAME=${var.project_name}-kibana",
    "XPACK_SECURITY_ENABLED=false"
  ]

  healthcheck {
    test         = ["CMD-SHELL", "curl -s http://localhost:5601/api/status | grep -q '\"level\":\"available\"'"]
    interval     = "30s"
    timeout      = "10s"
    retries      = 5
    start_period = "120s"
  }

  dynamic "labels" {
    for_each = var.labels
    content {
      label = labels.key
      value = labels.value
    }
  }

  depends_on = [docker_container.elasticsearch]
}
