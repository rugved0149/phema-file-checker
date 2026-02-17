"""
Unit tests for risk scoring module.
Primary static analysis — intent-based scoring.

Author: Rugved Suryawanshi
"""

import unittest
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.score import score_signals


class TestScoring(unittest.TestCase):
    """Test cases for intent-based risk scoring."""

    def test_no_signals_clean(self):
        """No signals should result in clean score."""
        signals = {
            "entropy": 0.5,
            "yara_hits": []
        }

        result = score_signals(signals)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_band"], "clean")
        self.assertEqual(result["signals"], [])

    def test_entropy_only_low_risk(self):
        """High entropy alone should produce low risk."""
        signals = {
            "entropy": 7.8,
            "yara_hits": []
        }

        result = score_signals(signals)

        self.assertGreater(result["risk_score"], 0)
        self.assertEqual(result["risk_band"], "low")
        self.assertTrue(any("entropy" in s.lower() for s in result["signals"]))

    def test_single_low_weight_yara_hit(self):
        """Single low-impact YARA hit should be low risk."""
        signals = {
            "entropy": 0.2,
            "yara_hits": [
                {
                    "rule": "Test_Network_Indicator",
                    "category": "network"
                }
            ]
        }

        result = score_signals(signals)

        self.assertGreater(result["risk_score"], 0)
        self.assertEqual(result["risk_band"], "low")

    def test_high_risk_category(self):
        """Credential-access category should push risk to high."""
        signals = {
            "entropy": 0.5,
            "yara_hits": [
                {
                    "rule": "Credential_Dumping_Indicators",
                    "category": "credential-access"
                }
            ]
        }

        result = score_signals(signals)

        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertEqual(result["risk_band"], "high")

    def test_multiple_signals_capped_score(self):
        """Multiple high-risk signals should cap score at 100."""
        signals = {
            "entropy": 8.0,
            "yara_hits": [
                {"rule": "Injection", "category": "injection"},
                {"rule": "Credential", "category": "credential-access"},
                {"rule": "AntiAnalysis", "category": "anti-analysis"}
            ]
        }

        result = score_signals(signals)

        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_band"], "high")
        self.assertGreaterEqual(len(result["signals"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
