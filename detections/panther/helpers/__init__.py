"""
Shared helper functions for Panther detections.
Import these in your detection rules.
"""

# Re-export from panther-mock helpers
import sys
from pathlib import Path

# Add panther-mock to path
panther_mock_path = Path(__file__).parent.parent.parent.parent / "lib" / "panther-mock"
if str(panther_mock_path) not in sys.path:
    sys.path.insert(0, str(panther_mock_path))

from helpers import (
    deep_get,
    deep_walk,
    pattern_match,
    pattern_match_list,
    is_ip_in_network,
    is_internal_ip,
    get_string_set,
    aws_arn_parse,
    time_parse,
    is_sensitive_aws_action,
    is_high_risk_port,
)

__all__ = [
    "deep_get",
    "deep_walk",
    "pattern_match",
    "pattern_match_list",
    "is_ip_in_network",
    "is_internal_ip",
    "get_string_set",
    "aws_arn_parse",
    "time_parse",
    "is_sensitive_aws_action",
    "is_high_risk_port",
]
