"""
Detection Engine for Panther-compatible rules.
Executes detection rules against log events.
"""

import importlib.util
import json
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

try:
    from .helpers import deep_get
    from .schemas import LogType, validate_event
except ImportError:
    from helpers import deep_get
    from schemas import LogType, validate_event


@dataclass
class DetectionResult:
    """Result of running a detection against an event."""

    rule_id: str
    rule_file: str
    matched: bool
    event: Dict[str, Any]
    title: Optional[str] = None
    severity: str = "MEDIUM"
    description: Optional[str] = None
    reference: Optional[str] = None
    runbook: Optional[str] = None
    alert_context: Optional[Dict[str, Any]] = None
    dedup_string: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_file": self.rule_file,
            "matched": self.matched,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "reference": self.reference,
            "runbook": self.runbook,
            "alert_context": self.alert_context,
            "dedup_string": self.dedup_string,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
            "event": self.event,
        }


@dataclass
class Detection:
    """A loaded detection rule."""

    rule_id: str
    file_path: Path
    rule_func: Callable[[Dict[str, Any]], bool]
    title_func: Optional[Callable[[Dict[str, Any]], str]] = None
    severity_func: Optional[Callable[[Dict[str, Any]], str]] = None
    description_func: Optional[Callable[[Dict[str, Any]], str]] = None
    reference_func: Optional[Callable[[Dict[str, Any]], str]] = None
    runbook_func: Optional[Callable[[Dict[str, Any]], str]] = None
    alert_context_func: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    dedup_func: Optional[Callable[[Dict[str, Any]], str]] = None
    log_types: List[str] = field(default_factory=list)
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    @property
    def default_severity(self) -> str:
        return "MEDIUM"


class DetectionEngine:
    """
    Engine for loading and executing Panther-compatible detection rules.

    Usage:
        engine = DetectionEngine()
        engine.load_rules("detections/panther/rules")
        results = engine.run(events)
    """

    def __init__(self, helpers_path: Optional[Path] = None):
        """
        Initialize the detection engine.

        Args:
            helpers_path: Optional path to custom helpers directory
        """
        self.detections: Dict[str, Detection] = {}
        self.helpers_path = helpers_path
        self._setup_helpers()

    def _setup_helpers(self):
        """Add helpers to the path for rule imports."""
        # Add panther-mock helpers to path
        panther_mock_path = Path(__file__).parent
        if str(panther_mock_path) not in sys.path:
            sys.path.insert(0, str(panther_mock_path))

        # Add custom helpers if provided
        if self.helpers_path and self.helpers_path.exists():
            if str(self.helpers_path) not in sys.path:
                sys.path.insert(0, str(self.helpers_path))

    def load_rule(self, rule_path: Union[str, Path]) -> Detection:
        """
        Load a single detection rule from a Python file.

        Args:
            rule_path: Path to the rule file

        Returns:
            Loaded Detection object
        """
        rule_path = Path(rule_path)
        if not rule_path.exists():
            raise FileNotFoundError(f"Rule file not found: {rule_path}")

        # Generate rule ID from filename
        rule_id = rule_path.stem

        # Load the module
        spec = importlib.util.spec_from_file_location(rule_id, rule_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load rule from {rule_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[rule_id] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            raise ImportError(f"Error loading rule {rule_path}: {e}")

        # Extract rule function (required)
        if not hasattr(module, "rule"):
            raise ValueError(f"Rule {rule_path} must define a 'rule' function")

        detection = Detection(
            rule_id=rule_id,
            file_path=rule_path,
            rule_func=module.rule,
            title_func=getattr(module, "title", None),
            severity_func=getattr(module, "severity", None),
            description_func=getattr(module, "description", None),
            reference_func=getattr(module, "reference", None),
            runbook_func=getattr(module, "runbook", None),
            alert_context_func=getattr(module, "alert_context", None),
            dedup_func=getattr(module, "dedup", None),
            log_types=getattr(module, "LOG_TYPES", []),
            enabled=getattr(module, "ENABLED", True),
            tags=getattr(module, "TAGS", []),
        )

        self.detections[rule_id] = detection
        return detection

    def load_rules(self, rules_dir: Union[str, Path]) -> List[Detection]:
        """
        Load all detection rules from a directory.

        Args:
            rules_dir: Path to directory containing rule files

        Returns:
            List of loaded Detection objects
        """
        rules_dir = Path(rules_dir)
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        loaded = []
        for rule_file in rules_dir.glob("*.py"):
            if rule_file.name.startswith("_"):
                continue
            try:
                detection = self.load_rule(rule_file)
                loaded.append(detection)
            except Exception as e:
                print(f"Warning: Failed to load rule {rule_file}: {e}")

        return loaded

    def run_detection(
        self, detection: Detection, event: Dict[str, Any]
    ) -> DetectionResult:
        """
        Run a single detection against an event.

        Args:
            detection: The detection rule to run
            event: The event to analyze

        Returns:
            DetectionResult with match status and metadata
        """
        start_time = datetime.now()

        # Initialize result
        result = DetectionResult(
            rule_id=detection.rule_id,
            rule_file=str(detection.file_path),
            matched=False,
            event=event,
        )

        try:
            # Run the rule function
            matched = detection.rule_func(event)
            result.matched = bool(matched)

            if result.matched:
                # Extract additional metadata for alerts
                if detection.title_func:
                    result.title = detection.title_func(event)

                if detection.severity_func:
                    result.severity = detection.severity_func(event)
                else:
                    result.severity = detection.default_severity

                if detection.description_func:
                    result.description = detection.description_func(event)

                if detection.reference_func:
                    result.reference = detection.reference_func(event)

                if detection.runbook_func:
                    result.runbook = detection.runbook_func(event)

                if detection.alert_context_func:
                    result.alert_context = detection.alert_context_func(event)

                if detection.dedup_func:
                    result.dedup_string = detection.dedup_func(event)

        except Exception as e:
            result.error = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"

        # Calculate execution time
        result.execution_time_ms = (datetime.now() - start_time).total_seconds() * 1000

        return result

    def run(
        self,
        events: Union[Dict[str, Any], List[Dict[str, Any]]],
        rule_ids: Optional[List[str]] = None,
    ) -> List[DetectionResult]:
        """
        Run all loaded detections against event(s).

        Args:
            events: Single event or list of events
            rule_ids: Optional list of specific rule IDs to run

        Returns:
            List of DetectionResults
        """
        if isinstance(events, dict):
            events = [events]

        results = []

        for event in events:
            for rule_id, detection in self.detections.items():
                # Skip if specific rules requested and this isn't one
                if rule_ids and rule_id not in rule_ids:
                    continue

                # Skip disabled rules
                if not detection.enabled:
                    continue

                result = self.run_detection(detection, event)
                results.append(result)

        return results

    def run_matching(
        self,
        events: Union[Dict[str, Any], List[Dict[str, Any]]],
        rule_ids: Optional[List[str]] = None,
    ) -> List[DetectionResult]:
        """
        Run detections and return only matching results.

        Args:
            events: Single event or list of events
            rule_ids: Optional list of specific rule IDs to run

        Returns:
            List of DetectionResults where matched=True
        """
        all_results = self.run(events, rule_ids)
        return [r for r in all_results if r.matched]


def run_detection(
    rule_path: Union[str, Path],
    event: Dict[str, Any],
) -> DetectionResult:
    """
    Convenience function to run a single rule against a single event.

    Args:
        rule_path: Path to the rule file
        event: Event to analyze

    Returns:
        DetectionResult
    """
    engine = DetectionEngine()
    detection = engine.load_rule(rule_path)
    return engine.run_detection(detection, event)


def run_detections(
    rules_dir: Union[str, Path],
    events: Union[Dict[str, Any], List[Dict[str, Any]]],
) -> List[DetectionResult]:
    """
    Convenience function to run all rules in a directory against events.

    Args:
        rules_dir: Directory containing rule files
        events: Event(s) to analyze

    Returns:
        List of DetectionResults
    """
    engine = DetectionEngine()
    engine.load_rules(rules_dir)
    return engine.run(events)


def load_events_from_file(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """
    Load events from a JSON or JSONL file.

    Args:
        file_path: Path to the file

    Returns:
        List of event dictionaries
    """
    file_path = Path(file_path)
    events = []

    with open(file_path, "r") as f:
        content = f.read().strip()

        # Try JSON array first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                events = data
            else:
                events = [data]
        except json.JSONDecodeError:
            # Try JSONL format
            for line in content.split("\n"):
                line = line.strip()
                if line:
                    events.append(json.loads(line))

    return events
