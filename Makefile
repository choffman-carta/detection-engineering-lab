# Detection Engineering Lab Makefile
# Common commands for managing the detection lab

.PHONY: help up down status logs test validate clean atomic setup

# Default target
help:
	@echo "Detection Engineering Lab"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Infrastructure:"
	@echo "  setup          Initial setup (install dependencies)"
	@echo "  up             Start the full lab environment"
	@echo "  down           Stop and remove all lab containers"
	@echo "  status         Show status of all components"
	@echo "  logs           Tail logs from all containers"
	@echo ""
	@echo "Detection Testing:"
	@echo "  test           Run all detection unit tests"
	@echo "  validate       Validate all detection rules"
	@echo "  run RULE=path  Run a specific detection"
	@echo ""
	@echo "Attack Simulation:"
	@echo "  atomic T=id    Run Atomic Red Team test (e.g., make atomic T=T1003)"
	@echo "  atomic-list    List available Atomic tests"
	@echo ""
	@echo "Utilities:"
	@echo "  clean          Remove all containers and volumes"
	@echo "  fmt            Format Terraform files"
	@echo "  shell          Open shell in Linux target"
	@echo ""
	@echo "Windows VM:"
	@echo "  windows-start  Start Windows UTM VM"
	@echo "  windows-stop   Stop Windows UTM VM"
	@echo "  windows-status Check Windows VM status"

# ============================================================================
# Infrastructure
# ============================================================================

setup:
	@echo "Setting up Detection Engineering Lab..."
	@./scripts/setup.sh

up:
	@echo "Starting Detection Lab..."
	cd infrastructure && terraform init && terraform apply -auto-approve -var-file=environments/local/terraform.tfvars
	@echo ""
	@echo "Lab is starting. Services will be available at:"
	@echo "  - Elasticsearch: http://localhost:9200"
	@echo "  - Kibana:        http://localhost:5601"
	@echo "  - MinIO Console: http://localhost:9001"
	@echo "  - Vector API:    http://localhost:8686"

up-compose:
	@echo "Starting Detection Lab with Docker Compose..."
	docker compose up -d
	@make status

down:
	@echo "Stopping Detection Lab..."
	cd infrastructure && terraform destroy -auto-approve -var-file=environments/local/terraform.tfvars || true
	docker compose down 2>/dev/null || true

status:
	@echo "Detection Lab Status"
	@echo "===================="
	@echo ""
	@echo "Docker Containers:"
	@docker ps --filter "label=project=detection-lab" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "No containers running"
	@echo ""
	@echo "Services:"
	@curl -s http://localhost:9200/_cluster/health 2>/dev/null | jq -r '"Elasticsearch: \(.status)"' || echo "Elasticsearch: not running"
	@curl -s http://localhost:5601/api/status 2>/dev/null | jq -r '"Kibana: \(.status.overall.level)"' || echo "Kibana: not running"
	@curl -s http://localhost:8686/health 2>/dev/null && echo "Vector: healthy" || echo "Vector: not running"
	@curl -s http://localhost:9000/minio/health/live 2>/dev/null && echo "MinIO: healthy" || echo "MinIO: not running"

logs:
	@docker compose logs -f 2>/dev/null || docker logs -f detection-lab-vector 2>/dev/null

logs-elastic:
	@docker logs -f detection-lab-elasticsearch

logs-vector:
	@docker logs -f detection-lab-vector

# ============================================================================
# Detection Testing
# ============================================================================

test:
	@echo "Running detection tests..."
	@python -m pytest tests/detection-tests/ -v

test-coverage:
	@python -m pytest tests/detection-tests/ --cov=lib/panther-mock --cov=detections/panther/rules --cov-report=term-missing

validate:
	@echo "Validating detections..."
	@echo ""
	@echo "Panther Rules:"
	@python scripts/run-detection.py validate detections/panther/rules/
	@echo ""
	@echo "Sigma Rules:"
	@sigma check detections/sigma/rules/ 2>/dev/null || echo "Install sigma-cli: pip install sigma-cli"
	@echo ""
	@echo "YARA Rules:"
	@for rule in detections/yara/rules/*.yar; do yara -w "$$rule" /dev/null 2>/dev/null && echo "  ✓ $$rule" || echo "  ✗ $$rule"; done

run:
ifndef RULE
	@echo "Usage: make run RULE=path/to/rule.py"
	@echo "Example: make run RULE=detections/panther/rules/aws_root_login.py"
else
	@python scripts/run-detection.py run $(RULE) -f logs/samples/aws_cloudtrail_samples.json
endif

list-detections:
	@python scripts/run-detection.py list detections/panther/rules/

# ============================================================================
# Attack Simulation
# ============================================================================

atomic:
ifndef T
	@echo "Usage: make atomic T=<technique_id>"
	@echo "Example: make atomic T=T1003.001"
else
	@./scripts/invoke-atomic.sh $(T)
endif

atomic-list:
ifndef T
	@echo "Usage: make atomic-list T=<technique_id>"
	@echo "Example: make atomic-list T=T1003"
else
	@./scripts/invoke-atomic.sh -l $(T)
endif

atomic-show:
ifndef T
	@echo "Usage: make atomic-show T=<technique_id>"
else
	@./scripts/invoke-atomic.sh -s $(T)
endif

# ============================================================================
# Windows VM Management
# ============================================================================

windows-start:
	@./infrastructure/scripts/utm-windows.sh start

windows-stop:
	@./infrastructure/scripts/utm-windows.sh stop

windows-status:
	@./infrastructure/scripts/utm-windows.sh status

windows-provision:
	@./infrastructure/scripts/utm-windows.sh provision

# ============================================================================
# Utilities
# ============================================================================

shell:
	@docker exec -it detection-lab-linux-target /bin/bash

shell-elastic:
	@docker exec -it detection-lab-elasticsearch /bin/bash

clean:
	@echo "Cleaning up Detection Lab..."
	@docker compose down -v 2>/dev/null || true
	@cd infrastructure && terraform destroy -auto-approve -var-file=environments/local/terraform.tfvars 2>/dev/null || true
	@docker volume rm detection-lab-elasticsearch-data detection-lab-minio-data detection-lab-vector-data 2>/dev/null || true
	@echo "Cleanup complete"

fmt:
	@cd infrastructure && terraform fmt -recursive

init:
	@cd infrastructure && terraform init

plan:
	@cd infrastructure && terraform plan -var-file=environments/local/terraform.tfvars

# Convert Sigma rules to Elasticsearch queries
sigma-convert:
	@mkdir -p output/sigma-elastic
	@for rule in detections/sigma/rules/*.yml; do \
		name=$$(basename "$$rule" .yml); \
		echo "Converting: $$rule"; \
		sigma convert -t elasticsearch -c detections/sigma/config/elastic.yml "$$rule" > "output/sigma-elastic/$${name}.json" 2>/dev/null || true; \
	done
	@echo "Converted rules saved to output/sigma-elastic/"

# Generate sample events
generate-samples:
	@echo "Generating sample events..."
	@docker exec detection-lab-linux-target bash -c "logger -t test 'Sample syslog message'"
	@curl -s -X POST http://localhost:8080 -H "Content-Type: application/json" -d '{"test": "event", "timestamp": "'$$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'
	@echo "Sample events sent to Vector"
