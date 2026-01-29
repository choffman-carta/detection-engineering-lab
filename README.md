# Detection Engineering Lab

A Terraform-based detection engineering lab for developing, testing, and validating security detections locally. Designed for Panther compatibility with support for Sigma, YARA, and Python detection formats.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Local Environment (M4 Mac)                   │
├─────────────────────────────────────────────────────────────────┤
│  Docker (via Terraform Docker Provider)                          │
│  ├── Elasticsearch + Kibana (SIEM)                              │
│  ├── Vector (log shipping)                                       │
│  ├── MinIO (S3-compatible, Panther-style ingestion)             │
│  ├── Linux Target (Ubuntu + auditd + osquery)                   │
│  └── Caldera Server (optional)                                   │
├─────────────────────────────────────────────────────────────────┤
│  UTM (managed via scripts)                                       │
│  └── Windows Server 2022 (Sysmon + WEF + osquery)               │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker Desktop
- Terraform >= 1.0
- Python 3.9+
- (Optional) UTM for Windows VM

### Setup

```bash
# Clone the repository
git clone <repo-url> detection-lab
cd detection-lab

# Copy and customize configuration
cp infrastructure/environments/local/terraform.tfvars.example \
   infrastructure/environments/local/terraform.tfvars

# Run setup script
./scripts/setup.sh

# Or manually:
cd infrastructure && terraform init
```

### Start the Lab

```bash
# Using Terraform (recommended)
make up

# Or using Docker Compose
make up-compose

# Check status
make status
```

### Access Services

| Service | URL |
|---------|-----|
| Elasticsearch | http://localhost:9200 |
| Kibana | http://localhost:5601 |
| MinIO Console | http://localhost:9001 |
| Vector API | http://localhost:8686 |

## Detection Formats

### Panther (Python)

```python
# detections/panther/rules/aws_root_login.py
from helpers import deep_get

def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "Root"
    )

def title(event):
    return f"Root login from {event.get('sourceIPAddress')}"
```

### Sigma (YAML)

```yaml
# detections/sigma/rules/aws_root_account_usage.yml
title: AWS Root Account Activity
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: 'Root'
  condition: selection
level: high
```

### YARA

```yara
# detections/yara/rules/suspicious_powershell.yar
rule Suspicious_PowerShell_Download {
    strings:
        $download = "DownloadString" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase
    condition:
        $download and $invoke
}
```

## Testing Detections

### Run Unit Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage
```

### Test Individual Rules

```bash
# Run a specific detection against sample logs
make run RULE=detections/panther/rules/aws_root_login.py

# Or use the CLI directly
python scripts/run-detection.py run detections/panther/rules/aws_root_login.py \
  -f logs/samples/aws_cloudtrail_samples.json
```

### Validate Rules

```bash
# Validate all detection syntax
make validate
```

## Attack Simulation

### Atomic Red Team

```bash
# List available tests for a technique
make atomic-list T=T1003

# Run a specific test
make atomic T=T1003.001

# Show test details
make atomic-show T=T1003.001
```

### Windows VM (UTM)

See [docs/windows-utm-setup.md](docs/windows-utm-setup.md) for Windows setup instructions.

```bash
# Check Windows VM status
make windows-status

# Start the VM
make windows-start
```

## Project Structure

```
detection-lab/
├── infrastructure/
│   ├── main.tf                    # Root module
│   ├── modules/
│   │   ├── siem/                  # Elasticsearch + Kibana
│   │   ├── log-shipping/          # Vector
│   │   ├── storage/               # MinIO
│   │   ├── linux-target/          # Ubuntu target
│   │   ├── caldera/               # MITRE Caldera (optional)
│   │   └── network/               # Docker network
│   ├── environments/
│   │   ├── local/                 # Local tfvars
│   │   └── cloud/                 # Cloud tfvars (future)
│   └── scripts/
│       ├── utm-windows.sh         # UTM management
│       └── setup-windows.ps1      # Windows provisioning
├── detections/
│   ├── panther/
│   │   ├── rules/                 # Python detections
│   │   └── helpers/               # Shared helpers
│   ├── sigma/
│   │   ├── rules/                 # Sigma rules
│   │   └── config/                # Backend configs
│   └── yara/
│       └── rules/                 # YARA rules
├── tests/
│   ├── detection-tests/           # Unit tests
│   └── atomic-mappings/           # Detection → test mappings
├── lib/
│   └── panther-mock/              # Panther mock framework
├── logs/
│   └── samples/                   # Sample log data
├── scripts/
│   ├── run-detection.py           # Detection CLI
│   ├── invoke-atomic.sh           # Atomic runner
│   └── setup.sh                   # Setup script
├── .github/workflows/             # CI/CD pipelines
├── Makefile                       # Common commands
├── docker-compose.yml             # Compose alternative
└── README.md
```

## Configuration

### Enable Caldera

In `infrastructure/environments/local/terraform.tfvars`:

```hcl
enable_caldera = true
```

Then run `make up` to deploy.

### Customize Resources

Edit `infrastructure/environments/local/terraform.tfvars`:

```hcl
elasticsearch_memory = "8g"  # Increase for larger datasets
```

## CI/CD Pipeline

The lab includes GitHub Actions workflows:

- **validate.yml** - Syntax validation for all detection formats
- **test.yml** - Unit tests and coverage
- **integration.yml** - Full integration tests with Elasticsearch

## Resource Requirements

| Component | Memory | Storage |
|-----------|--------|---------|
| Elasticsearch | 4-8 GB | 10 GB |
| Kibana | 1 GB | - |
| Vector | 256 MB | - |
| MinIO | 512 MB | 5 GB |
| Linux Target | 1 GB | 2 GB |
| Caldera (optional) | 2 GB | 1 GB |
| Windows VM (UTM) | 8 GB | 40 GB |
| **Total (without Windows)** | ~8 GB | ~18 GB |
| **Total (with Windows)** | ~16 GB | ~58 GB |

## Common Commands

```bash
make help            # Show all commands
make up              # Start lab
make down            # Stop lab
make status          # Check status
make test            # Run tests
make validate        # Validate rules
make atomic T=T1003  # Run Atomic test
make logs            # Tail logs
make clean           # Full cleanup
make shell           # Shell into Linux target
```

## Troubleshooting

### Elasticsearch won't start
```bash
# Check Docker memory allocation
docker info | grep Memory

# Increase Docker memory in Docker Desktop preferences
```

### Vector can't connect to Elasticsearch
```bash
# Check Elasticsearch is healthy
curl http://localhost:9200/_cluster/health

# Check Vector logs
make logs-vector
```

### Detection tests fail
```bash
# Validate Python syntax
python -m py_compile detections/panther/rules/*.py

# Check helper imports
python -c "from helpers import deep_get; print('OK')"
```

## Future Enhancements

- [ ] Cloud deployment modules (AWS/Azure)
- [ ] Additional log sources (Okta, GitHub, GCP)
- [ ] Detection coverage reporting
- [ ] Automated detection-to-test mapping
- [ ] Integration with real Panther

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new detections
4. Submit a pull request
