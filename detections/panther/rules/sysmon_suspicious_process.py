"""
Detect Suspicious Process Execution via Sysmon

Detects execution of commonly abused binaries that may indicate
malicious activity or living-off-the-land techniques.
"""

from helpers import deep_get, pattern_match_list

LOG_TYPES = ["Custom.Sysmon"]
ENABLED = True
TAGS = ["Endpoint", "Execution", "Defense Evasion", "T1059"]

# Suspicious process patterns (case insensitive matching)
SUSPICIOUS_PROCESSES = [
    "*\\powershell.exe",
    "*\\cmd.exe",
    "*\\wscript.exe",
    "*\\cscript.exe",
    "*\\mshta.exe",
    "*\\regsvr32.exe",
    "*\\rundll32.exe",
    "*\\certutil.exe",
    "*\\bitsadmin.exe",
    "*\\msiexec.exe",
]

# Suspicious command line patterns
SUSPICIOUS_COMMANDS = [
    "*-enc*",  # Encoded PowerShell
    "*-encodedcommand*",
    "*downloadstring*",
    "*invoke-expression*",
    "*iex*",
    "*bypass*",
    "*hidden*",
    "*-nop*",
    "*-w hidden*",
    "*FromBase64String*",
]

# Suspicious parent processes
SUSPICIOUS_PARENTS = [
    "*\\winword.exe",
    "*\\excel.exe",
    "*\\outlook.exe",
    "*\\powerpnt.exe",
    "*\\mshta.exe",
]


def rule(event):
    """
    Detect suspicious process execution.

    Triggers on:
    - Sysmon Event ID 1 (Process Create)
    - Process in suspicious list OR
    - Command line contains suspicious patterns OR
    - Parent process is suspicious
    """
    # Only process creation events
    if event.get("EventID") != 1:
        return False

    image = (event.get("Image") or "").lower()
    command_line = (event.get("CommandLine") or "").lower()
    parent_image = (event.get("ParentImage") or "").lower()

    # Check for suspicious process
    is_suspicious_process = pattern_match_list(image, [p.lower() for p in SUSPICIOUS_PROCESSES])

    # Check for suspicious command line
    has_suspicious_command = pattern_match_list(command_line, [p.lower() for p in SUSPICIOUS_COMMANDS])

    # Check for suspicious parent
    has_suspicious_parent = pattern_match_list(parent_image, [p.lower() for p in SUSPICIOUS_PARENTS])

    # Alert if suspicious process with suspicious command OR suspicious parent spawning shell
    if is_suspicious_process and has_suspicious_command:
        return True

    if has_suspicious_parent and is_suspicious_process:
        return True

    return False


def title(event):
    """Generate alert title."""
    image = event.get("Image", "unknown")
    parent = event.get("ParentImage", "unknown")
    process_name = image.split("\\")[-1] if "\\" in image else image
    parent_name = parent.split("\\")[-1] if "\\" in parent else parent
    return f"Suspicious Process: {process_name} spawned by {parent_name}"


def severity(event):
    """Determine severity based on indicators."""
    command_line = (event.get("CommandLine") or "").lower()
    parent_image = (event.get("ParentImage") or "").lower()

    # Higher severity for encoded commands
    if "encodedcommand" in command_line or "-enc" in command_line:
        return "HIGH"

    # Higher severity for Office spawning shells
    office_apps = ["winword", "excel", "outlook", "powerpnt"]
    if any(app in parent_image for app in office_apps):
        return "HIGH"

    return "MEDIUM"


def description(event):
    """Generate detailed description."""
    return (
        "A potentially suspicious process execution was detected. "
        "This may indicate malicious activity such as malware execution, "
        "living-off-the-land attacks, or unauthorized script execution. "
        "Review the command line and parent process for legitimacy."
    )


def alert_context(event):
    """Additional context for the alert."""
    return {
        "image": event.get("Image"),
        "command_line": event.get("CommandLine"),
        "parent_image": event.get("ParentImage"),
        "parent_command_line": event.get("ParentCommandLine"),
        "user": event.get("User"),
        "process_id": event.get("ProcessId"),
        "parent_process_id": event.get("ParentProcessId"),
        "current_directory": event.get("CurrentDirectory"),
        "utc_time": event.get("UtcTime"),
        "hostname": event.get("Computer"),
    }


def dedup(event):
    """Deduplication key."""
    image = (event.get("Image") or "unknown").split("\\")[-1]
    host = event.get("Computer", "unknown")
    return f"suspicious_process_{host}_{image}"
