"""
Unit tests for YARA rules loader.
Validates unified rule compilation.

Author: Rugved Suryawanshi
"""

import unittest
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.rules_loader import (
    load_yara_rules,
    check_yara_installation
)


class TestRulesLoader(unittest.TestCase):
    """Test cases for YARA rules loader."""

    def test_yara_installation_check(self):
        """YARA availability check should return boolean."""
        result = check_yara_installation()
        self.assertIsInstance(result, bool)

    @unittest.skipIf(
        not check_yara_installation(),
        "YARA not installed, skipping rule compilation test"
    )
    def test_load_yara_rules_success(self):
        """Rules should compile successfully from rules/yara."""
        rules = load_yara_rules()

        # We cannot import yara safely if missing, so check attributes
        self.assertTrue(hasattr(rules, "match"))

    @unittest.skipIf(
        not check_yara_installation(),
        "YARA not installed, skipping negative test"
    )
    def test_missing_rules_directory_raises(self):
        """Missing rules directory should raise RuntimeError."""
        from scanner import rules_loader

        original_dir = rules_loader.RULES_DIR
        try:
            rules_loader.RULES_DIR = Path("nonexistent_rules_dir")

            with self.assertRaises(RuntimeError):
                rules_loader.load_yara_rules()
        finally:
            rules_loader.RULES_DIR = original_dir


if __name__ == "__main__":
    unittest.main(verbosity=2)
