#!/usr/bin/env python3
"""
Detection Testing CLI
Run and test detection rules against sample events.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

# Add lib to path
script_dir = Path(__file__).parent.parent
sys.path.insert(0, str(script_dir / "lib" / "panther-mock"))
sys.path.insert(0, str(script_dir / "detections" / "panther" / "helpers"))

from engine import (
    DetectionEngine,
    DetectionResult,
    load_events_from_file,
    run_detection,
    run_detections,
)


def print_result(result: DetectionResult, verbose: bool = False) -> None:
    """Print a detection result."""
    status = "✓ MATCH" if result.matched else "✗ NO MATCH"
    color = "\033[92m" if result.matched else "\033[91m"
    reset = "\033[0m"

    print(f"{color}{status}{reset} | {result.rule_id}")

    if result.error:
        print(f"  └─ ERROR: {result.error}")
        return

    if result.matched:
        if result.title:
            print(f"  └─ Title: {result.title}")
        print(f"  └─ Severity: {result.severity}")
        if result.dedup_string:
            print(f"  └─ Dedup: {result.dedup_string}")

    if verbose:
        print(f"  └─ Execution time: {result.execution_time_ms:.2f}ms")
        if result.alert_context:
            print(f"  └─ Context: {json.dumps(result.alert_context, indent=6)}")


def cmd_run(args: argparse.Namespace) -> int:
    """Run a detection against events."""
    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"Error: Rule file not found: {rule_path}", file=sys.stderr)
        return 1

    # Load events
    if args.event:
        events = [json.loads(args.event)]
    elif args.events_file:
        events_path = Path(args.events_file)
        if not events_path.exists():
            print(f"Error: Events file not found: {events_path}", file=sys.stderr)
            return 1
        events = load_events_from_file(events_path)
    else:
        print("Error: Must provide --event or --events-file", file=sys.stderr)
        return 1

    print(f"Running {rule_path.name} against {len(events)} event(s)...\n")

    engine = DetectionEngine()
    detection = engine.load_rule(rule_path)

    matches = 0
    for i, event in enumerate(events):
        result = engine.run_detection(detection, event)
        if not args.quiet or result.matched:
            if len(events) > 1:
                print(f"Event #{i + 1}:")
            print_result(result, verbose=args.verbose)
            print()
        if result.matched:
            matches += 1

    print(f"Results: {matches}/{len(events)} events matched")
    return 0 if matches > 0 else 1


def cmd_test(args: argparse.Namespace) -> int:
    """Test all detections in a directory."""
    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    events_dir = Path(args.events_dir) if args.events_dir else None

    print(f"Loading rules from {rules_dir}...")
    engine = DetectionEngine()
    detections = engine.load_rules(rules_dir)
    print(f"Loaded {len(detections)} detection(s)\n")

    if not events_dir:
        # Just validate rules can be loaded
        print("Validation complete. No events directory specified.")
        return 0

    # Load all sample events
    all_events = []
    for events_file in events_dir.glob("*.json"):
        events = load_events_from_file(events_file)
        all_events.extend(events)
        print(f"Loaded {len(events)} events from {events_file.name}")

    print(f"\nRunning {len(detections)} detection(s) against {len(all_events)} event(s)...\n")

    results = engine.run(all_events)
    matches = [r for r in results if r.matched]

    if args.verbose or args.show_matches:
        for result in matches:
            print_result(result, verbose=args.verbose)
            print()

    print(f"Results: {len(matches)} match(es) from {len(results)} checks")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate detection rules syntax."""
    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    print(f"Validating rules in {rules_dir}...")

    errors = []
    valid = 0

    for rule_file in rules_dir.glob("*.py"):
        if rule_file.name.startswith("_"):
            continue
        try:
            engine = DetectionEngine()
            engine.load_rule(rule_file)
            valid += 1
            if args.verbose:
                print(f"  ✓ {rule_file.name}")
        except Exception as e:
            errors.append((rule_file, str(e)))
            print(f"  ✗ {rule_file.name}: {e}")

    print(f"\nValidation: {valid} valid, {len(errors)} error(s)")
    return 0 if not errors else 1


def cmd_list(args: argparse.Namespace) -> int:
    """List available detections."""
    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    engine = DetectionEngine()
    detections = engine.load_rules(rules_dir)

    print(f"Detections in {rules_dir}:\n")
    for detection in sorted(detections, key=lambda d: d.rule_id):
        status = "enabled" if detection.enabled else "disabled"
        tags = ", ".join(detection.tags) if detection.tags else "no tags"
        print(f"  {detection.rule_id}")
        print(f"    Status: {status}")
        print(f"    Log Types: {', '.join(detection.log_types) or 'any'}")
        print(f"    Tags: {tags}")
        print()

    print(f"Total: {len(detections)} detection(s)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Detection Testing CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a single rule against a JSON event
  %(prog)s run detections/panther/rules/aws_root_login.py -e '{"eventName": "ConsoleLogin"}'

  # Run a rule against a file of events
  %(prog)s run detections/panther/rules/aws_root_login.py -f logs/samples/cloudtrail.json

  # Test all rules in a directory
  %(prog)s test detections/panther/rules/ -e logs/samples/

  # Validate rule syntax
  %(prog)s validate detections/panther/rules/

  # List available detections
  %(prog)s list detections/panther/rules/
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a detection against events")
    run_parser.add_argument("rule", help="Path to detection rule file")
    run_parser.add_argument("-e", "--event", help="JSON event string")
    run_parser.add_argument("-f", "--events-file", help="Path to events file (JSON/JSONL)")
    run_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    run_parser.add_argument("-q", "--quiet", action="store_true", help="Only show matches")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test all detections in a directory")
    test_parser.add_argument("rules_dir", help="Path to rules directory")
    test_parser.add_argument("-e", "--events-dir", help="Path to events directory")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    test_parser.add_argument("-m", "--show-matches", action="store_true", help="Show matching results")

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate detection rules")
    validate_parser.add_argument("rules_dir", help="Path to rules directory")
    validate_parser.add_argument("-v", "--verbose", action="store_true", help="Show each validated rule")

    # List command
    list_parser = subparsers.add_parser("list", help="List available detections")
    list_parser.add_argument("rules_dir", help="Path to rules directory")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "run": cmd_run,
        "test": cmd_test,
        "validate": cmd_validate,
        "list": cmd_list,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
