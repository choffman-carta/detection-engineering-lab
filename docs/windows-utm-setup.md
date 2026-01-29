# Windows Server 2022 UTM Setup Guide

This guide walks through setting up a Windows Server 2022 virtual machine in UTM for the Detection Engineering Lab.

## Prerequisites

- macOS with Apple Silicon (M1/M2/M3/M4) or Intel
- [UTM](https://mac.getutm.app/) installed
- At least 16GB RAM (8GB allocated to VM)
- 50GB free disk space
- Internet connection for downloads

## Step 1: Download Windows Server 2022 Evaluation

1. Visit the Microsoft Evaluation Center:
   https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022

2. Select **64-bit edition**

3. Choose **ISO** download format

4. Fill out the registration form (you can use any information)

5. Download the ISO file (~5GB)

> **Note**: The evaluation is valid for 180 days and can be re-armed up to 5 times for extended testing.

## Step 2: Create UTM Virtual Machine

### For Apple Silicon (M1/M2/M3/M4)

1. Open UTM
2. Click **Create a New Virtual Machine**
3. Select **Virtualize** (uses native ARM virtualization)
4. Choose **Windows**
5. Check **Install Windows 10 or higher**
6. Click **Browse** and select the downloaded ISO
7. Configure resources:
   - Memory: **8192 MB** (8 GB)
   - CPU Cores: **4**
8. Configure storage:
   - Size: **40 GB** (minimum, 64 GB recommended)
9. Configure network:
   - Select **Bridged** for lab connectivity
   - Or **Shared Network** for NAT
10. Name: `detection-lab-windows`
11. Click **Save**

### For Intel Macs

1. Open UTM
2. Click **Create a New Virtual Machine**
3. Select **Emulate** (uses QEMU)
4. Choose **Windows**
5. Select architecture: **x86_64**
6. Follow the same resource configuration as above

## Step 3: Install Windows Server

1. Start the VM in UTM
2. Press any key to boot from ISO when prompted
3. Select language and keyboard layout
4. Click **Install now**
5. Select **Windows Server 2022 Standard (Desktop Experience)**
6. Accept the license terms
7. Choose **Custom: Install Windows only**
8. Select the virtual disk and click **Next**
9. Wait for installation to complete (~15-20 minutes)
10. Set the Administrator password when prompted
11. Complete the Out-of-Box Experience (OOBE)

## Step 4: Initial Configuration

After Windows boots to the desktop:

### Enable Remote Desktop (Optional)
```powershell
# Run in elevated PowerShell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

### Configure Network
```powershell
# View network configuration
Get-NetIPConfiguration

# If using bridged networking, configure static IP (optional)
# New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 172.28.0.100 -PrefixLength 16 -DefaultGateway 172.28.0.1
```

### Install Guest Tools (SPICE)
For better integration:
1. Download SPICE Guest Tools: https://www.spice-space.org/download.html
2. Mount the ISO in UTM
3. Install from the mounted drive

## Step 5: Run Detection Lab Provisioning Script

1. Copy the provisioning script to the VM:
   - Use shared folders (if configured in UTM)
   - Or copy via clipboard
   - Or download from your repository

2. Open PowerShell as Administrator

3. Run the script:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup-windows.ps1
```

4. The script will install:
   - Sysmon with SwiftOnSecurity configuration
   - osquery
   - Atomic Red Team
   - Windows Event Forwarding
   - Enhanced audit logging

5. Reboot when prompted

## Step 6: Verify Installation

After reboot, verify the components:

```powershell
# Check Sysmon
Get-Service Sysmon64

# Check osquery
Get-Service osqueryd

# Check event logging
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# Check Atomic Red Team
Import-Module Invoke-AtomicRedTeam
Get-AtomicTechnique -ShowDetails | Select-Object -First 5
```

## Step 7: Configure Log Forwarding

To forward logs to the Vector container:

### Option A: Windows Event Forwarding (WEF)
The setup script configures WEF. Create a subscription for the Vector server.

### Option B: Direct Syslog (via nxlog or winlogbeat)

Install NXLog Community Edition:
```powershell
# Download from https://nxlog.co/products/nxlog-community-edition/download
# Or use winlogbeat
```

## UTM Management Script

Use the provided script for VM lifecycle management:

```bash
# Check VM status
./infrastructure/scripts/utm-windows.sh status

# Start VM
./infrastructure/scripts/utm-windows.sh start

# Stop VM
./infrastructure/scripts/utm-windows.sh stop

# Show provisioning instructions
./infrastructure/scripts/utm-windows.sh provision
```

## Running Atomic Tests

Once configured, run Atomic Red Team tests:

```powershell
# Import the module
Import-Module Invoke-AtomicRedTeam

# List available tests
Invoke-AtomicTest T1003 -ShowDetails

# Run a test
Invoke-AtomicTest T1003.001

# Run with cleanup
Invoke-AtomicTest T1003.001 -Cleanup

# Generate test plan
Invoke-AtomicTest T1003.001 -GetPrereqs
Invoke-AtomicTest T1003.001 -CheckPrereqs
```

## Troubleshooting

### VM Won't Start
- Ensure UTM is updated to the latest version
- Check available RAM (close other applications)
- Verify ISO path is correct

### Network Issues
- Switch between Bridged and Shared Network modes
- Check firewall settings
- Verify Docker network is running

### Sysmon Not Logging
- Check service status: `Get-Service Sysmon64`
- Verify config: `Sysmon64.exe -c`
- Check Event Viewer for errors

### Performance Issues
- Increase allocated memory
- Enable hardware virtualization in UTM settings
- Close unnecessary applications on host

## Resource Requirements Summary

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| CPU Cores | 2 | 4 |
| Storage | 40 GB | 64 GB |
| Host RAM | 16 GB | 32 GB |

## Security Considerations

- The evaluation ISO has a 180-day limit
- Default credentials should be changed for any shared environments
- The VM should be isolated from production networks
- Atomic Red Team tests may trigger real security tools
