"""
Log schema definitions for Panther-compatible detections.
Mirrors Panther's built-in log types.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class LogType(Enum):
    """Supported log types matching Panther naming conventions."""

    # AWS Logs
    AWS_CLOUDTRAIL = "AWS.CloudTrail"
    AWS_GUARDDUTY = "AWS.GuardDuty"
    AWS_S3_SERVER_ACCESS = "AWS.S3ServerAccess"
    AWS_VPC_FLOW = "AWS.VPCFlow"
    AWS_ALB = "AWS.ALB"

    # Okta
    OKTA_SYSTEM_LOG = "Okta.SystemLog"

    # GitHub
    GITHUB_AUDIT = "GitHub.Audit"

    # GCP
    GCP_AUDIT = "GCP.AuditLog"

    # Endpoint Logs
    SYSMON = "Custom.Sysmon"
    OSQUERY = "Custom.Osquery"
    AUDITD = "Custom.Auditd"

    # Generic
    CUSTOM_JSON = "Custom.JSON"


@dataclass
class SchemaField:
    """Definition of a field in a log schema."""

    name: str
    type: str  # string, int, float, bool, object, array, timestamp
    required: bool = False
    description: str = ""
    nested_schema: Optional[Dict[str, Any]] = None


@dataclass
class LogSchema:
    """Definition of a log type schema."""

    log_type: LogType
    description: str
    fields: Dict[str, SchemaField] = field(default_factory=dict)
    required_fields: Set[str] = field(default_factory=set)
    timestamp_field: str = "timestamp"

    def validate(self, event: Dict[str, Any]) -> List[str]:
        """
        Validate an event against this schema.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check required fields
        for field_name in self.required_fields:
            if field_name not in event:
                errors.append(f"Missing required field: {field_name}")

        # Type checking (basic)
        for field_name, field_def in self.fields.items():
            if field_name in event:
                value = event[field_name]
                if not self._check_type(value, field_def.type):
                    errors.append(
                        f"Field '{field_name}' has wrong type. "
                        f"Expected {field_def.type}, got {type(value).__name__}"
                    )

        return errors

    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Check if value matches expected type."""
        if value is None:
            return True

        type_map = {
            "string": str,
            "int": int,
            "float": (int, float),
            "bool": bool,
            "object": dict,
            "array": list,
            "timestamp": str,  # ISO format strings
        }

        expected = type_map.get(expected_type)
        if expected is None:
            return True

        return isinstance(value, expected)


# Pre-defined schemas for common log types
SCHEMAS: Dict[LogType, LogSchema] = {}


def _init_schemas():
    """Initialize built-in schemas."""

    # AWS CloudTrail
    SCHEMAS[LogType.AWS_CLOUDTRAIL] = LogSchema(
        log_type=LogType.AWS_CLOUDTRAIL,
        description="AWS CloudTrail audit logs",
        timestamp_field="eventTime",
        required_fields={"eventVersion", "eventSource", "eventName"},
        fields={
            "eventVersion": SchemaField("eventVersion", "string", True),
            "eventSource": SchemaField("eventSource", "string", True),
            "eventName": SchemaField("eventName", "string", True),
            "eventTime": SchemaField("eventTime", "timestamp", True),
            "awsRegion": SchemaField("awsRegion", "string"),
            "sourceIPAddress": SchemaField("sourceIPAddress", "string"),
            "userAgent": SchemaField("userAgent", "string"),
            "userIdentity": SchemaField("userIdentity", "object"),
            "requestParameters": SchemaField("requestParameters", "object"),
            "responseElements": SchemaField("responseElements", "object"),
            "errorCode": SchemaField("errorCode", "string"),
            "errorMessage": SchemaField("errorMessage", "string"),
        },
    )

    # AWS GuardDuty
    SCHEMAS[LogType.AWS_GUARDDUTY] = LogSchema(
        log_type=LogType.AWS_GUARDDUTY,
        description="AWS GuardDuty security findings",
        timestamp_field="time",
        required_fields={"detail-type", "source"},
        fields={
            "detail-type": SchemaField("detail-type", "string", True),
            "source": SchemaField("source", "string", True),
            "time": SchemaField("time", "timestamp"),
            "detail": SchemaField("detail", "object"),
            "account": SchemaField("account", "string"),
            "region": SchemaField("region", "string"),
        },
    )

    # Okta System Log
    SCHEMAS[LogType.OKTA_SYSTEM_LOG] = LogSchema(
        log_type=LogType.OKTA_SYSTEM_LOG,
        description="Okta System Log events",
        timestamp_field="published",
        required_fields={"eventType", "actor"},
        fields={
            "eventType": SchemaField("eventType", "string", True),
            "actor": SchemaField("actor", "object", True),
            "published": SchemaField("published", "timestamp"),
            "severity": SchemaField("severity", "string"),
            "displayMessage": SchemaField("displayMessage", "string"),
            "outcome": SchemaField("outcome", "object"),
            "target": SchemaField("target", "array"),
            "client": SchemaField("client", "object"),
            "authenticationContext": SchemaField("authenticationContext", "object"),
        },
    )

    # GitHub Audit
    SCHEMAS[LogType.GITHUB_AUDIT] = LogSchema(
        log_type=LogType.GITHUB_AUDIT,
        description="GitHub Audit log events",
        timestamp_field="@timestamp",
        required_fields={"action"},
        fields={
            "action": SchemaField("action", "string", True),
            "@timestamp": SchemaField("@timestamp", "timestamp"),
            "actor": SchemaField("actor", "string"),
            "actor_ip": SchemaField("actor_ip", "string"),
            "org": SchemaField("org", "string"),
            "repo": SchemaField("repo", "string"),
            "user": SchemaField("user", "string"),
        },
    )

    # Sysmon
    SCHEMAS[LogType.SYSMON] = LogSchema(
        log_type=LogType.SYSMON,
        description="Windows Sysmon events",
        timestamp_field="UtcTime",
        required_fields={"EventID"},
        fields={
            "EventID": SchemaField("EventID", "int", True),
            "UtcTime": SchemaField("UtcTime", "timestamp"),
            "ProcessId": SchemaField("ProcessId", "int"),
            "Image": SchemaField("Image", "string"),
            "CommandLine": SchemaField("CommandLine", "string"),
            "CurrentDirectory": SchemaField("CurrentDirectory", "string"),
            "User": SchemaField("User", "string"),
            "ParentProcessId": SchemaField("ParentProcessId", "int"),
            "ParentImage": SchemaField("ParentImage", "string"),
            "ParentCommandLine": SchemaField("ParentCommandLine", "string"),
            "TargetFilename": SchemaField("TargetFilename", "string"),
            "DestinationIp": SchemaField("DestinationIp", "string"),
            "DestinationPort": SchemaField("DestinationPort", "int"),
        },
    )

    # Osquery
    SCHEMAS[LogType.OSQUERY] = LogSchema(
        log_type=LogType.OSQUERY,
        description="osquery scheduled query results",
        timestamp_field="unixTime",
        required_fields={"name"},
        fields={
            "name": SchemaField("name", "string", True),
            "hostIdentifier": SchemaField("hostIdentifier", "string"),
            "unixTime": SchemaField("unixTime", "int"),
            "calendarTime": SchemaField("calendarTime", "string"),
            "columns": SchemaField("columns", "object"),
            "action": SchemaField("action", "string"),
        },
    )


# Initialize schemas on module load
_init_schemas()


def get_schema(log_type: LogType) -> Optional[LogSchema]:
    """
    Get the schema definition for a log type.

    Args:
        log_type: The LogType enum value

    Returns:
        LogSchema or None if not defined
    """
    return SCHEMAS.get(log_type)


def validate_event(event: Dict[str, Any], log_type: LogType) -> List[str]:
    """
    Validate an event against its schema.

    Args:
        event: The event dictionary
        log_type: Expected log type

    Returns:
        List of validation errors (empty if valid)
    """
    schema = get_schema(log_type)
    if schema is None:
        return []  # No schema defined, allow anything
    return schema.validate(event)


def add_custom_schema(
    log_type_name: str,
    description: str,
    fields: Dict[str, Dict[str, Any]],
    required_fields: Optional[List[str]] = None,
    timestamp_field: str = "timestamp",
) -> LogType:
    """
    Add a custom log schema.

    Args:
        log_type_name: Name for the custom log type (e.g., "Custom.MyApp")
        description: Description of the log type
        fields: Dictionary of field definitions
        required_fields: List of required field names
        timestamp_field: Name of the timestamp field

    Returns:
        The created LogType
    """
    # For custom schemas, we use the CUSTOM_JSON type as a base
    schema_fields = {
        name: SchemaField(
            name=name,
            type=field_def.get("type", "string"),
            required=field_def.get("required", False),
            description=field_def.get("description", ""),
        )
        for name, field_def in fields.items()
    }

    schema = LogSchema(
        log_type=LogType.CUSTOM_JSON,
        description=description,
        fields=schema_fields,
        required_fields=set(required_fields) if required_fields else set(),
        timestamp_field=timestamp_field,
    )

    # Store with a custom key
    SCHEMAS[log_type_name] = schema
    return LogType.CUSTOM_JSON
