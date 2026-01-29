"""
Panther Mock Framework
A local testing framework for Panther-compatible Python detections.
"""

try:
    from .engine import DetectionEngine, run_detection, run_detections
    from .helpers import deep_get, deep_walk, pattern_match, pattern_match_list
    from .schemas import LogType, get_schema
except ImportError:
    from engine import DetectionEngine, run_detection, run_detections
    from helpers import deep_get, deep_walk, pattern_match, pattern_match_list
    from schemas import LogType, get_schema

__version__ = "0.1.0"

__all__ = [
    "DetectionEngine",
    "run_detection",
    "run_detections",
    "deep_get",
    "deep_walk",
    "pattern_match",
    "pattern_match_list",
    "LogType",
    "get_schema",
]
