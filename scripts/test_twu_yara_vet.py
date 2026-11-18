#!/usr/bin/env python3
# ==============================================================================
# Program: test_twu_yara_vet.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Unit test suite for twu_yara_vet.py verifying fail-closed rule validation,
#          disallowed import module detection, global rule blocking, and cryptographic
#          SHA-256 tamper-evident integrity tracking.
# ==============================================================================

from __future__ import annotations
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure local scripts directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_yara_vet as v  # noqa: E402


class Static(unittest.TestCase):
    """Static security and syntax boundary tests."""

    def test_ok(self):
        """Verifies that clean rules with permitted modules pass static check."""
        names, why = v.static_check('import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }')
        self.assertEqual((names, why), (["A", "B"], None))

    def test_disabled_module(self):
        """Verifies that unvetted modules outside ALLOWED_MODULES trigger rejection."""
        self.assertIn("disabled module", v.static_check('import "cuckoo"\nrule A { condition: true }')[1])

    def test_import_in_comment_ignored(self):
        """Verifies that commented module imports are properly ignored."""
        self.assertIsNone(v.static_check('// import "cuckoo"\nrule A { condition: true }')[1])

    def test_global_and_include_rejected(self):
        """Verifies that global rules and include directives are strictly rejected."""
        self.assertIn("global", v.static_check("global rule G { condition: true }")[1])
        self.assertIn("include", v.static_check('include "x.yar"\nrule A { condition: true }')[1])


class Real(unittest.TestCase):
    """Cryptographic manifest and filesystem integrity verification tests."""

    def setUp(self):
        """Skips tests if vetted rules directory or manifest is not present in standalone repo."""
        if not v.RULES.is_dir() or not (v.RULES / "MANIFEST.json").is_file():
            self.skipTest("vetted rules manifest not present in standalone test environment")

    def test_repo_rules_verify(self):
        """Verifies that repository rules match manifest SHA-256 digests."""
        self.assertEqual(v.verify(compile_index=False), [])

    def test_tamper_detected(self):
        """Verifies that tampering with a single byte in a rule triggers a sha256 mismatch alert."""
        with tempfile.TemporaryDirectory() as td:
            shutil.copytree(str(v.RULES), td + "/r")
            man = json.loads(Path(td, "r", "MANIFEST.json").read_text())
            target = Path(td, "r", man["files"][0]["path"])
            target.write_text(target.read_text() + "\n// tampered\n")
            self.assertTrue(any("sha256 mismatch" in p for p in v.verify(Path(td) / "r", compile_index=False)))

    def test_exclusions_file_lists_reason(self):
        """Verifies that any excluded rule has a documented justification."""
        ex = json.loads((v.RULES / "EXCLUSIONS.json").read_text())
        for e in ex["excluded"]:
            self.assertTrue(e["rule"] and e["why"])

    def test_licenses_recorded(self):
        """Verifies that source licenses, 40-character commit hashes, and URLs are recorded."""
        man = json.loads((v.RULES / "MANIFEST.json").read_text())
        for s in man["sources"]:
            self.assertTrue(s["license"] and len(s["commit"]) == 40 and s["url"].startswith("https://github.com/"))
        self.assertTrue(all(len(f["sha256"]) == 64 for f in man["files"]))


if __name__ == "__main__":
    unittest.main()
