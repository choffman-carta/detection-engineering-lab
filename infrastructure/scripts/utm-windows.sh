#!/bin/bash
# UTM Windows Server Management Script
# Manages Windows Server 2022 VM lifecycle for detection lab

set -e

# Configuration
VM_NAME="detection-lab-windows"
UTM_APP="/Applications/UTM.app"
VM_BUNDLE="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/${VM_NAME}.utm"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_utm_installed() {
    if [ ! -d "$UTM_APP" ]; then
        log_error "UTM is not installed. Please install from https://mac.getutm.app/"
        exit 1
    fi
}

check_vm_exists() {
    if [ ! -d "$VM_BUNDLE" ]; then
        return 1
    fi
    return 0
}

get_vm_status() {
    # Check if VM process is running
    if pgrep -f "UTM.*${VM_NAME}" > /dev/null 2>&1; then
        echo "running"
    elif check_vm_exists; then
        echo "stopped"
    else
        echo "not_created"
    fi
}

cmd_status() {
    log_info "Checking Windows VM status..."

    check_utm_installed

    status=$(get_vm_status)
    case $status in
        running)
            log_info "VM Status: ${GREEN}Running${NC}"
            ;;
        stopped)
            log_info "VM Status: ${YELLOW}Stopped${NC}"
            ;;
        not_created)
            log_info "VM Status: ${RED}Not Created${NC}"
            log_info "Run '$0 create' to create the VM"
            ;;
    esac
}

cmd_start() {
    log_info "Starting Windows VM..."

    check_utm_installed

    if ! check_vm_exists; then
        log_error "VM does not exist. Run '$0 create' first."
        exit 1
    fi

    status=$(get_vm_status)
    if [ "$status" = "running" ]; then
        log_warn "VM is already running"
        return 0
    fi

    open -a UTM "${VM_BUNDLE}"
    log_info "VM starting... Please wait for Windows to boot."
}

cmd_stop() {
    log_info "Stopping Windows VM..."

    status=$(get_vm_status)
    if [ "$status" != "running" ]; then
        log_warn "VM is not running"
        return 0
    fi

    # Send ACPI shutdown via UTM CLI if available
    if command -v utmctl &> /dev/null; then
        utmctl stop "$VM_NAME"
    else
        log_warn "utmctl not found. Please stop VM manually via UTM GUI."
        log_info "Or use: osascript -e 'tell application \"UTM\" to stop vm \"${VM_NAME}\"'"
    fi
}

cmd_create() {
    log_info "Creating Windows Server VM configuration..."

    check_utm_installed

    if check_vm_exists; then
        log_warn "VM already exists at: $VM_BUNDLE"
        log_info "Use '$0 destroy' to remove it first."
        return 1
    fi

    cat << 'EOF'
=============================================================================
WINDOWS SERVER 2022 VM CREATION GUIDE
=============================================================================

UTM does not support automated VM creation via CLI. Please follow these steps:

1. Download Windows Server 2022 Evaluation ISO:
   https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022

   - Select "64-bit edition"
   - Choose ISO download
   - Valid for 180 days (can be re-armed)

2. Open UTM and create new VM:
   - Click "Create a New Virtual Machine"
   - Select "Virtualize" (for Apple Silicon) or "Emulate" (for Intel)
   - Choose "Windows"
   - Browse to downloaded ISO

3. Configure VM resources:
   - Memory: 8192 MB (8 GB)
   - CPU Cores: 4
   - Storage: 40 GB (or more)
   - Network: Bridged (for lab connectivity)

4. Name the VM: detection-lab-windows

5. Complete Windows installation:
   - Select "Windows Server 2022 Standard (Desktop Experience)"
   - Set Administrator password
   - Complete OOBE

6. After installation, run the provisioning script:
   ./setup-windows.ps1

=============================================================================
EOF
}

cmd_provision() {
    log_info "Preparing to provision Windows VM..."

    status=$(get_vm_status)
    if [ "$status" != "running" ]; then
        log_error "VM is not running. Start it first with '$0 start'"
        exit 1
    fi

    log_info "Provisioning script: ${SCRIPT_DIR}/setup-windows.ps1"

    cat << 'EOF'
=============================================================================
PROVISIONING INSTRUCTIONS
=============================================================================

Copy and run the setup script on the Windows VM:

Option 1: Using shared folder (if configured):
   - Copy setup-windows.ps1 to shared folder
   - Run from elevated PowerShell

Option 2: Using clipboard:
   - Open PowerShell as Administrator on Windows VM
   - Paste the script content and run

Option 3: Using remote access (if WinRM is enabled):
   $cred = Get-Credential
   Invoke-Command -ComputerName <VM_IP> -Credential $cred -FilePath setup-windows.ps1

=============================================================================
EOF

    log_info "Script location: ${SCRIPT_DIR}/setup-windows.ps1"
}

cmd_destroy() {
    log_info "Destroying Windows VM..."

    status=$(get_vm_status)
    if [ "$status" = "running" ]; then
        log_error "VM is running. Stop it first with '$0 stop'"
        exit 1
    fi

    if ! check_vm_exists; then
        log_warn "VM does not exist"
        return 0
    fi

    read -p "Are you sure you want to delete the VM? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cancelled"
        return 0
    fi

    rm -rf "$VM_BUNDLE"
    log_info "VM deleted successfully"
}

cmd_ssh() {
    log_info "SSH is not typically used for Windows. Use RDP or WinRM instead."
    log_info "For RDP on macOS, use Microsoft Remote Desktop from the App Store."
    log_info "Or use: open rdp://administrator@<VM_IP>"
}

cmd_help() {
    cat << EOF
UTM Windows Server Management Script

Usage: $0 <command>

Commands:
    status      Check VM status
    start       Start the Windows VM
    stop        Stop the Windows VM (graceful shutdown)
    create      Show VM creation instructions
    provision   Show provisioning instructions
    destroy     Delete the VM
    ssh         Show remote access options
    help        Show this help message

Examples:
    $0 status
    $0 start
    $0 provision

Requirements:
    - UTM installed (https://mac.getutm.app/)
    - Windows Server 2022 Evaluation ISO

EOF
}

# Main
case "${1:-help}" in
    status)
        cmd_status
        ;;
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    create)
        cmd_create
        ;;
    provision)
        cmd_provision
        ;;
    destroy)
        cmd_destroy
        ;;
    ssh|rdp)
        cmd_ssh
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        log_error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
