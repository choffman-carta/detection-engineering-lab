#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2022 provisioning script for Detection Lab
.DESCRIPTION
    Installs and configures security tooling:
    - Sysmon (with SwiftOnSecurity config)
    - Windows Event Forwarding (WEF)
    - osquery
    - Atomic Red Team
.NOTES
    Run this script as Administrator on the Windows VM
#>

[CmdletBinding()]
param(
    [string]$VectorHost = "172.28.0.1",  # Docker host IP from container perspective
    [int]$VectorPort = 5514,
    [switch]$SkipReboot
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Configuration
$ToolsPath = "C:\Tools"
$LogPath = "C:\Logs"
$SysmonPath = "$ToolsPath\Sysmon"
$OsqueryPath = "$ToolsPath\osquery"
$AtomicPath = "$ToolsPath\AtomicRedTeam"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"  { "Green" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-InternetConnection {
    try {
        $null = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10
        return $true
    } catch {
        return $false
    }
}

function Install-Sysmon {
    Write-Log "Installing Sysmon..."

    # Create directories
    New-Item -ItemType Directory -Path $SysmonPath -Force | Out-Null

    # Download Sysmon
    $sysmonZip = "$SysmonPath\Sysmon.zip"
    $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"

    Write-Log "Downloading Sysmon from $sysmonUrl"
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
    Expand-Archive -Path $sysmonZip -DestinationPath $SysmonPath -Force
    Remove-Item $sysmonZip

    # Download SwiftOnSecurity Sysmon config
    $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $configPath = "$SysmonPath\sysmonconfig.xml"

    Write-Log "Downloading Sysmon configuration"
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing

    # Install Sysmon
    Write-Log "Installing Sysmon with configuration"
    $sysmonExe = "$SysmonPath\Sysmon64.exe"
    & $sysmonExe -accepteula -i $configPath

    Write-Log "Sysmon installed successfully"
}

function Install-Osquery {
    Write-Log "Installing osquery..."

    New-Item -ItemType Directory -Path $OsqueryPath -Force | Out-Null

    # Download osquery MSI
    $osqueryVersion = "5.9.1"
    $osqueryMsi = "$OsqueryPath\osquery.msi"
    $osqueryUrl = "https://pkg.osquery.io/windows/osquery-$osqueryVersion.msi"

    Write-Log "Downloading osquery $osqueryVersion"
    Invoke-WebRequest -Uri $osqueryUrl -OutFile $osqueryMsi -UseBasicParsing

    # Install osquery
    Write-Log "Installing osquery"
    Start-Process msiexec.exe -ArgumentList "/i `"$osqueryMsi`" /quiet /norestart" -Wait

    # Configure osquery
    $osqueryConfPath = "C:\Program Files\osquery\osquery.conf"
    $osqueryConf = @{
        options = @{
            logger_plugin = "filesystem"
            logger_path = "C:\Logs\osquery"
            disable_logging = $false
            schedule_splay_percent = 10
        }
        schedule = @{
            process_events = @{
                query = "SELECT * FROM process_events;"
                interval = 10
            }
            windows_events = @{
                query = "SELECT * FROM windows_events WHERE eventid IN (4624, 4625, 4688, 4697, 7045);"
                interval = 10
            }
            services = @{
                query = "SELECT * FROM services;"
                interval = 60
            }
            scheduled_tasks = @{
                query = "SELECT * FROM scheduled_tasks;"
                interval = 60
            }
            logged_in_users = @{
                query = "SELECT * FROM logged_in_users;"
                interval = 30
            }
            listening_ports = @{
                query = "SELECT * FROM listening_ports;"
                interval = 30
            }
        }
    }

    $osqueryConf | ConvertTo-Json -Depth 10 | Set-Content $osqueryConfPath

    # Start osquery service
    Start-Service osqueryd -ErrorAction SilentlyContinue

    Write-Log "osquery installed successfully"
}

function Install-AtomicRedTeam {
    Write-Log "Installing Atomic Red Team..."

    # Install prerequisites
    if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
        Write-Log "Installing Invoke-AtomicRedTeam PowerShell module"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
        Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force
    }

    # Clone Atomic Red Team repo
    if (-not (Test-Path $AtomicPath)) {
        New-Item -ItemType Directory -Path $AtomicPath -Force | Out-Null
        Write-Log "Cloning Atomic Red Team repository"

        # Use git if available, otherwise download zip
        if (Get-Command git -ErrorAction SilentlyContinue) {
            git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git $AtomicPath
        } else {
            $zipPath = "$env:TEMP\atomic.zip"
            Invoke-WebRequest -Uri "https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip" -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
            Move-Item "$env:TEMP\atomic-red-team-master\*" $AtomicPath -Force
            Remove-Item $zipPath, "$env:TEMP\atomic-red-team-master" -Recurse -Force
        }
    }

    Write-Log "Atomic Red Team installed successfully"
}

function Configure-WEF {
    Write-Log "Configuring Windows Event Forwarding..."

    # Enable WinRM
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

    # Configure Windows Event Collector service
    wecutil qc /q

    # Create subscription for security events
    $subscriptionXml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>DetectionLab-Security</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Detection Lab Security Events</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Normal</ConfigurationMode>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0" Path="Security">
                <Select Path="Security">*</Select>
            </Query>
            <Query Id="1" Path="Microsoft-Windows-Sysmon/Operational">
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
            </Query>
            <Query Id="2" Path="Microsoft-Windows-PowerShell/Operational">
                <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <Locale Language="en-US"/>
</Subscription>
"@

    $subscriptionPath = "$env:TEMP\wef-subscription.xml"
    $subscriptionXml | Set-Content $subscriptionPath
    wecutil cs $subscriptionPath 2>$null

    Write-Log "WEF configured successfully"
}

function Configure-Logging {
    Write-Log "Configuring enhanced logging..."

    # Create log directory
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    New-Item -ItemType Directory -Path "$LogPath\osquery" -Force | Out-Null

    # Enable PowerShell Script Block Logging
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLoggingPath)) {
        New-Item -Path $psLoggingPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1

    # Enable PowerShell Module Logging
    $psModulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $psModulePath)) {
        New-Item -Path $psModulePath -Force | Out-Null
    }
    Set-ItemProperty -Path $psModulePath -Name "EnableModuleLogging" -Value 1

    # Enable command line in process creation events (4688)
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $auditPath)) {
        New-Item -Path $auditPath -Force | Out-Null
    }
    Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

    # Configure audit policy
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Process Creation" /success:enable /failure:enable | Out-Null

    Write-Log "Enhanced logging configured"
}

function Configure-Firewall {
    Write-Log "Configuring firewall rules..."

    # Allow WinRM
    Enable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue

    # Allow syslog output to Vector
    New-NetFirewallRule -DisplayName "Allow Syslog UDP" -Direction Outbound -Protocol UDP -RemotePort $VectorPort -Action Allow -ErrorAction SilentlyContinue | Out-Null

    Write-Log "Firewall configured"
}

function Show-Summary {
    Write-Log "============================================"
    Write-Log "Detection Lab Windows Setup Complete!"
    Write-Log "============================================"
    Write-Log "Installed components:"
    Write-Log "  - Sysmon (with SwiftOnSecurity config)"
    Write-Log "  - osquery"
    Write-Log "  - Atomic Red Team"
    Write-Log "  - Windows Event Forwarding"
    Write-Log ""
    Write-Log "Log locations:"
    Write-Log "  - Sysmon: Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon"
    Write-Log "  - osquery: $LogPath\osquery"
    Write-Log ""
    Write-Log "To run Atomic tests:"
    Write-Log '  Import-Module Invoke-AtomicRedTeam'
    Write-Log '  Invoke-AtomicTest T1003.001 -ShowDetails'
    Write-Log '  Invoke-AtomicTest T1003.001'
    Write-Log ""
    if (-not $SkipReboot) {
        Write-Log "A reboot is recommended to apply all changes."
    }
}

# Main execution
function Main {
    Write-Log "Starting Detection Lab Windows Setup"
    Write-Log "Vector Host: $VectorHost`:$VectorPort"

    if (-not (Test-InternetConnection)) {
        Write-Log "No internet connection detected. Some downloads may fail." "WARN"
    }

    # Create tools directory
    New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null

    try {
        Install-Sysmon
        Install-Osquery
        Install-AtomicRedTeam
        Configure-WEF
        Configure-Logging
        Configure-Firewall
        Show-Summary

        if (-not $SkipReboot) {
            $response = Read-Host "Reboot now? (y/N)"
            if ($response -eq "y") {
                Restart-Computer -Force
            }
        }
    } catch {
        Write-Log "Setup failed: $_" "ERROR"
        throw
    }
}

Main
