"""
Integration tests for Cyber Shield scanner.
Validates primary static analysis pipeline.

Author: Rugved Suryawanshi
"""

import unittest
import tempfile
import os
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.scanner import scan_file
from scanner.rules_loader import check_yara_installation


class TestScannerIntegration(unittest.TestCase):
    """Integration tests for static scanner."""

    def setUp(self):
        """Create temporary test files."""
        self.temp_dir = tempfile.mkdtemp()

        # Suspicious file (should trigger YARA rules)
        self.suspicious_file = os.path.join(self.temp_dir, "suspicious.txt")
        with open(self.suspicious_file, "w", encoding="utf-8") as f:
            f.write(
                "powershell -nop Invoke-Expression "
                "CreateRemoteThread VirtualAllocEx"
            )

        # Benign file
        self.benign_file = os.path.join(self.temp_dir, "benign.txt")
        with open(self.benign_file, "w", encoding="utf-8") as f:
            f.write("This is harmless text with no malicious intent.")

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_file_returns_expected_fields(self):
        """scan_file should return core analysis fields."""
        result = scan_file(self.benign_file)

        self.assertIn("file", result)
        self.assertIn("risk_score", result)
        self.assertIn("risk_band", result)
        self.assertIn("signals", result)

        self.assertEqual(result["file"], self.benign_file)

    def test_benign_file_low_risk(self):
        """Benign file should not be flagged high risk."""
        result = scan_file(self.benign_file)

        self.assertIn(result["risk_band"], ["clean", "low"])
        self.assertLess(result["risk_score"], 40)

    @unittest.skipIf(
        not check_yara_installation(),
        "YARA not installed, skipping YARA integration test"
    )
    def test_suspicious_file_higher_risk(self):
        """Suspicious content should increase risk score."""
        result = scan_file(self.suspicious_file)

        self.assertGreater(result["risk_score"], 0)
        self.assertIn(result["risk_band"], ["medium", "high"])

        # At least one YARA-related signal should be present
        self.assertTrue(
            any("powershell" in reason.lower() or "execution" in reason.lower()
                for reason in result["signals"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
