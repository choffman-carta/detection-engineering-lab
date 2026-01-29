"""
Detect AWS IAM Access Key Creation

Access keys provide programmatic access to AWS resources.
Monitor for unauthorized key creation which could indicate persistence attempts.
"""

from helpers import deep_get

LOG_TYPES = ["AWS.CloudTrail"]
ENABLED = True
TAGS = ["AWS", "Persistence", "Credential Access", "T1098"]


def rule(event):
    """
    Detect IAM access key creation events.

    Returns True if:
    - Event is CreateAccessKey
    - Event was successful (no error code)
    """
    return (
        event.get("eventName") == "CreateAccessKey"
        and event.get("errorCode") is None
    )


def title(event):
    """Generate alert title."""
    actor = deep_get(event, "userIdentity", "arn", default="unknown")
    target_user = deep_get(event, "requestParameters", "userName", default="self")
    return f"IAM Access Key Created for {target_user} by {actor}"


def severity(event):
    """
    Determine severity.
    Higher severity if creating key for a different user.
    """
    actor_arn = deep_get(event, "userIdentity", "arn", default="")
    target_user = deep_get(event, "requestParameters", "userName")

    # If no target user specified, key is for the actor themselves
    if not target_user:
        return "MEDIUM"

    # If actor is creating key for different user, higher severity
    if target_user not in actor_arn:
        return "HIGH"

    return "MEDIUM"


def description(event):
    """Generate detailed description."""
    return (
        "An IAM access key was created. Access keys provide programmatic access "
        "to AWS resources and should be carefully monitored. Verify this key creation "
        "was authorized and follows your organization's security policies."
    )


def alert_context(event):
    """Additional context for the alert."""
    return {
        "actor_arn": deep_get(event, "userIdentity", "arn"),
        "actor_type": deep_get(event, "userIdentity", "type"),
        "target_user": deep_get(event, "requestParameters", "userName"),
        "access_key_id": deep_get(event, "responseElements", "accessKey", "accessKeyId"),
        "source_ip": event.get("sourceIPAddress"),
        "user_agent": event.get("userAgent"),
        "event_time": event.get("eventTime"),
    }


def dedup(event):
    """Deduplication key."""
    target = deep_get(event, "requestParameters", "userName", default="self")
    return f"iam_key_created_{target}"
