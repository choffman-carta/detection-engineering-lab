"""
Panther-compatible helper functions for detection rules.
These mirror the built-in helpers available in Panther.
"""

import fnmatch
import re
from typing import Any, Dict, List, Optional, Union


def deep_get(event: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    Safely retrieve nested values from a dictionary.

    Args:
        event: The dictionary to search
        *keys: Variable number of keys representing the path
        default: Value to return if path doesn't exist

    Returns:
        The value at the specified path, or default if not found

    Example:
        event = {"userIdentity": {"type": "Root"}}
        deep_get(event, "userIdentity", "type")  # Returns "Root"
        deep_get(event, "missing", "key", default="N/A")  # Returns "N/A"
    """
    result = event
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        elif isinstance(result, list) and isinstance(key, int):
            try:
                result = result[key]
            except (IndexError, TypeError):
                return default
        else:
            return default
        if result is None:
            return default
    return result if result is not None else default


def deep_walk(
    event: Dict[str, Any],
    *keys: str,
    default: Any = None,
    return_val: str = "value"
) -> Any:
    """
    Walk through nested structures including arrays.

    Args:
        event: The dictionary to search
        *keys: Variable number of keys representing the path
        default: Value to return if path doesn't exist
        return_val: "value" to return values, "key" to return keys

    Returns:
        List of values/keys found at the path across all array elements

    Example:
        event = {"records": [{"id": 1}, {"id": 2}]}
        deep_walk(event, "records", "id")  # Returns [1, 2]
    """
    def _walk(obj: Any, remaining_keys: tuple) -> List[Any]:
        if not remaining_keys:
            if return_val == "key":
                return list(obj.keys()) if isinstance(obj, dict) else []
            return [obj] if obj is not None else []

        key = remaining_keys[0]
        rest = remaining_keys[1:]

        if isinstance(obj, dict):
            if key in obj:
                return _walk(obj[key], rest)
            return []
        elif isinstance(obj, list):
            results = []
            for item in obj:
                results.extend(_walk(item, remaining_keys))
            return results
        return []

    results = _walk(event, keys)
    return results if results else (default if default is not None else [])


def pattern_match(string: str, pattern: str) -> bool:
    """
    Check if string matches a shell-style wildcard pattern.

    Args:
        string: The string to test
        pattern: Shell-style pattern (* and ? wildcards)

    Returns:
        True if string matches pattern

    Example:
        pattern_match("GetSecretValue", "Get*")  # Returns True
        pattern_match("PutItem", "Get*")  # Returns False
    """
    if string is None:
        return False
    return fnmatch.fnmatch(str(string), pattern)


def pattern_match_list(string: str, patterns: List[str]) -> bool:
    """
    Check if string matches any pattern in a list.

    Args:
        string: The string to test
        patterns: List of shell-style patterns

    Returns:
        True if string matches any pattern

    Example:
        pattern_match_list("GetSecretValue", ["Get*", "Describe*"])  # True
    """
    if string is None:
        return False
    return any(pattern_match(string, p) for p in patterns)


def is_ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is within a CIDR network range.

    Args:
        ip: IP address to check
        network: CIDR notation network (e.g., "10.0.0.0/8")

    Returns:
        True if IP is in network range
    """
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def get_string_set(event: Dict[str, Any], key: str) -> set:
    """
    Get a set of strings from an event field.

    Args:
        event: Event dictionary
        key: Key to extract

    Returns:
        Set of strings
    """
    value = event.get(key)
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple)):
        return set(str(v) for v in value if v is not None)
    return {str(value)}


def aws_arn_parse(arn: str) -> Optional[Dict[str, str]]:
    """
    Parse an AWS ARN into its components.

    Args:
        arn: AWS ARN string

    Returns:
        Dictionary with partition, service, region, account, resource
        or None if invalid ARN

    Example:
        aws_arn_parse("arn:aws:iam::123456789012:user/admin")
        # Returns {"partition": "aws", "service": "iam", ...}
    """
    if not arn or not arn.startswith("arn:"):
        return None

    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None

    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account": parts[4],
        "resource": parts[5],
    }


def aws_guardduty_context(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract useful context from a GuardDuty finding.

    Args:
        event: GuardDuty finding event

    Returns:
        Dictionary with extracted context
    """
    return {
        "finding_type": deep_get(event, "detail", "type"),
        "severity": deep_get(event, "detail", "severity"),
        "account_id": deep_get(event, "detail", "accountId"),
        "region": deep_get(event, "detail", "region"),
        "resource_type": deep_get(event, "detail", "resource", "resourceType"),
    }


def time_parse(time_string: str) -> Optional[Any]:
    """
    Parse a time string into a datetime object.

    Args:
        time_string: ISO 8601 or similar time string

    Returns:
        datetime object or None if parsing fails
    """
    from datetime import datetime

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(time_string, fmt)
        except (ValueError, TypeError):
            continue
    return None


def is_dmz_ip(ip: str) -> bool:
    """
    Check if IP is in common DMZ/public ranges.
    This is a placeholder - customize based on your network.

    Args:
        ip: IP address to check

    Returns:
        True if IP appears to be in DMZ
    """
    # Override this based on your network configuration
    dmz_ranges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    return any(is_ip_in_network(ip, net) for net in dmz_ranges)


def is_internal_ip(ip: str) -> bool:
    """
    Check if IP is in RFC 1918 private ranges.

    Args:
        ip: IP address to check

    Returns:
        True if IP is private/internal
    """
    private_ranges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ]
    return any(is_ip_in_network(ip, net) for net in private_ranges)


# Commonly used lookup tables
SENSITIVE_AWS_ACTIONS = {
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "ec2:CreateKeyPair",
    "ec2:ImportKeyPair",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
}

HIGH_RISK_PORTS = {22, 23, 3389, 5985, 5986, 445, 139, 1433, 3306, 5432, 27017, 6379}


def is_sensitive_aws_action(action: str) -> bool:
    """Check if AWS action is considered sensitive."""
    return action.lower() in {a.lower() for a in SENSITIVE_AWS_ACTIONS}


def is_high_risk_port(port: Union[int, str]) -> bool:
    """Check if port number is considered high-risk."""
    try:
        return int(port) in HIGH_RISK_PORTS
    except (ValueError, TypeError):
        return False
