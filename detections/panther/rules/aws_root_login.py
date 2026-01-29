"""
Detect AWS Root Account Console Login

This detection fires when the AWS root account is used to log into the console.
Root account usage should be minimized and monitored closely.
"""

from helpers import deep_get

LOG_TYPES = ["AWS.CloudTrail"]
ENABLED = True
TAGS = ["AWS", "Initial Access", "T1078"]


def rule(event):
    """
    Detect root account console logins.

    Returns True if:
    - Event is a ConsoleLogin
    - User identity type is Root
    """
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "Root"
    )


def title(event):
    """Generate alert title."""
    source_ip = event.get("sourceIPAddress", "unknown")
    return f"AWS Root Console Login from {source_ip}"


def severity(event):
    """
    Determine severity based on context.
    MFA usage reduces severity slightly.
    """
    mfa_used = deep_get(event, "additionalEventData", "MFAUsed") == "Yes"
    return "HIGH" if not mfa_used else "MEDIUM"


def description(event):
    """Generate detailed description."""
    return (
        "The AWS root account was used to log into the AWS Console. "
        "Root account usage should be minimized and reserved for emergency access only. "
        "Consider using IAM users with appropriate permissions instead."
    )


def reference(event):
    """Link to relevant documentation."""
    return "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"


def runbook(event):
    """Incident response steps."""
    return """
1. Verify if this login was authorized
2. Check what actions were performed during the session
3. If unauthorized, immediately rotate root credentials
4. Enable MFA if not already enabled
5. Review CloudTrail for any suspicious activity
"""


def alert_context(event):
    """Additional context for the alert."""
    return {
        "source_ip": event.get("sourceIPAddress"),
        "user_agent": event.get("userAgent"),
        "aws_region": event.get("awsRegion"),
        "mfa_used": deep_get(event, "additionalEventData", "MFAUsed"),
        "event_time": event.get("eventTime"),
        "console_login": deep_get(event, "responseElements", "ConsoleLogin"),
    }


def dedup(event):
    """Deduplication key."""
    # Dedupe by source IP to avoid alert fatigue from same source
    return f"root_login_{event.get('sourceIPAddress', 'unknown')}"
