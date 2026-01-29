#!/bin/bash
# Detection Engineering Lab Setup Script
# Installs dependencies and prepares the environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
    echo ""
}

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 (not found)"
        return 1
    fi
}

# Check operating system
check_os() {
    log_section "Checking Operating System"

    case "$(uname -s)" in
        Darwin)
            log_info "macOS detected"
            OS="macos"
            ;;
        Linux)
            log_info "Linux detected"
            OS="linux"
            ;;
        *)
            log_error "Unsupported operating system"
            exit 1
            ;;
    esac
}

# Check required tools
check_requirements() {
    log_section "Checking Requirements"

    MISSING=0

    check_command docker || MISSING=1
    check_command python3 || MISSING=1
    check_command terraform || MISSING=1
    check_command git || MISSING=1

    # Optional but recommended
    echo ""
    echo "Optional tools:"
    check_command sigma || echo "    Install: pip install sigma-cli"
    check_command yara || echo "    Install: brew install yara (macOS) or apt install yara (Linux)"
    check_command jq || echo "    Install: brew install jq (macOS) or apt install jq (Linux)"

    if [ $MISSING -eq 1 ]; then
        echo ""
        log_error "Missing required tools. Please install them and try again."
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    log_section "Installing Python Dependencies"

    cd "$PROJECT_ROOT"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv venv
    fi

    log_info "Activating virtual environment..."
    source venv/bin/activate

    log_info "Installing dependencies..."
    pip install --upgrade pip
    pip install pyyaml pytest pytest-cov

    # Optional: Sigma tools
    pip install sigma-cli pysigma-backend-elasticsearch 2>/dev/null || log_warn "Could not install sigma tools"

    log_info "Python dependencies installed"
}

# Initialize Terraform
init_terraform() {
    log_section "Initializing Terraform"

    cd "$PROJECT_ROOT/infrastructure"

    log_info "Running terraform init..."
    terraform init

    log_info "Validating configuration..."
    terraform validate

    log_info "Terraform initialized"
}

# Create necessary directories
create_directories() {
    log_section "Creating Directories"

    mkdir -p "$PROJECT_ROOT/logs/samples"
    mkdir -p "$PROJECT_ROOT/output/sigma-elastic"
    mkdir -p "$PROJECT_ROOT/infrastructure/modules/log-shipping/config"
    mkdir -p "$PROJECT_ROOT/infrastructure/modules/linux-target/build"

    log_info "Directories created"
}

# Set executable permissions
set_permissions() {
    log_section "Setting Permissions"

    chmod +x "$PROJECT_ROOT/scripts/"*.sh 2>/dev/null || true
    chmod +x "$PROJECT_ROOT/scripts/"*.py 2>/dev/null || true
    chmod +x "$PROJECT_ROOT/infrastructure/scripts/"*.sh 2>/dev/null || true

    log_info "Permissions set"
}

# Check Docker is running
check_docker() {
    log_section "Checking Docker"

    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi

    log_info "Docker is running"

    # Check available resources
    DOCKER_MEM=$(docker info 2>/dev/null | grep "Total Memory" | awk '{print $3}')
    log_info "Docker memory: $DOCKER_MEM"
}

# Print summary
print_summary() {
    log_section "Setup Complete!"

    cat << EOF
Detection Engineering Lab is ready.

Quick Start:
  make up              # Start the lab (Terraform)
  make up-compose      # Start the lab (Docker Compose)
  make status          # Check service status

Testing Detections:
  make test            # Run unit tests
  make validate        # Validate all rules

Running Attacks:
  make atomic T=T1003  # Run Atomic Red Team test

For more commands:
  make help

Documentation:
  docs/windows-utm-setup.md  # Windows VM setup guide

EOF
}

# Main
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          Detection Engineering Lab Setup                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    check_os
    check_requirements
    check_docker
    create_directories
    set_permissions
    install_python_deps
    init_terraform
    print_summary
}

main "$@"
