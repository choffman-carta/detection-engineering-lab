#!/usr/bin/env python3
"""
Unit tests for AWS detection rules.
"""

import json
import sys
import unittest
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "lib" / "panther-mock"))
sys.path.insert(0, str(project_root / "detections" / "panther" / "helpers"))

from engine import DetectionEngine


class TestAWSRootLogin(unittest.TestCase):
    """Tests for aws_root_login.py detection."""

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        cls.detection = cls.engine.load_rule(
            project_root / "detections" / "panther" / "rules" / "aws_root_login.py"
        )

    def test_root_console_login_matches(self):
        """Should match when root user logs into console."""
        event = {
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.50",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertIn("203.0.113.50", result.title)

    def test_root_console_login_without_mfa_high_severity(self):
        """Should be HIGH severity without MFA."""
        event = {
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "10.0.0.1",
            "additionalEventData": {"MFAUsed": "No"},
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "HIGH")

    def test_root_console_login_with_mfa_medium_severity(self):
        """Should be MEDIUM severity with MFA."""
        event = {
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "10.0.0.1",
            "additionalEventData": {"MFAUsed": "Yes"},
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "MEDIUM")

    def test_iam_user_login_no_match(self):
        """Should not match IAM user logins."""
        event = {
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "IAMUser", "userName": "admin"},
            "sourceIPAddress": "10.0.0.1",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)

    def test_non_console_login_no_match(self):
        """Should not match non-login events."""
        event = {
            "eventName": "DescribeInstances",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "10.0.0.1",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)


class TestAWSIAMAccessKeyCreated(unittest.TestCase):
    """Tests for aws_iam_access_key_created.py detection."""

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        cls.detection = cls.engine.load_rule(
            project_root / "detections" / "panther" / "rules" / "aws_iam_access_key_created.py"
        )

    def test_access_key_created_matches(self):
        """Should match successful access key creation."""
        event = {
            "eventName": "CreateAccessKey",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/admin",
            },
            "requestParameters": {"userName": "service-account"},
            "responseElements": {
                "accessKey": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE"}
            },
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)

    def test_access_key_for_different_user_high_severity(self):
        """Should be HIGH severity when creating key for different user."""
        event = {
            "eventName": "CreateAccessKey",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/admin",
            },
            "requestParameters": {"userName": "other-user"},
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "HIGH")

    def test_access_key_for_self_medium_severity(self):
        """Should be MEDIUM severity when creating key for self."""
        event = {
            "eventName": "CreateAccessKey",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/admin",
            },
            "requestParameters": {},  # No userName means self
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "MEDIUM")

    def test_failed_access_key_creation_no_match(self):
        """Should not match failed access key creation."""
        event = {
            "eventName": "CreateAccessKey",
            "userIdentity": {"type": "IAMUser"},
            "errorCode": "AccessDenied",
            "errorMessage": "User is not authorized",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)

    def test_other_iam_event_no_match(self):
        """Should not match other IAM events."""
        event = {
            "eventName": "DeleteAccessKey",
            "userIdentity": {"type": "IAMUser"},
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)


if __name__ == "__main__":
    unittest.main()
