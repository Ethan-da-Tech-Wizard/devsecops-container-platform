#!/usr/bin/env python3
# Program: devsecops-container-platform - test_twu_yara_vet.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Unit tests (unittest) for twu_yara_vet covering the static rule checks and, when the vetted rules folder exists, manifest hash verification and tamper detection.
"""
==============================================================================
Program: Test Suite for Cryptographic YARA Rule Vetting (test_twu_yara_vet.py)
Programmer: The Maintainer <maintainer@example.invalid>
Organization: TWU LLC
License: MIT License 2026
Purpose: Validate static security checks, disallowed module rejection, global rule
         blocking, include statement denial, and cryptographic SHA-256 tamper
         detection across threat detection rules.

Threat Model & Security Regressions Tested:
  - Disallowed Native C Modules: Ensures imports like 'cuckoo' are rejected.
  - Cross-Rule Condition Poisoning: Asserts that 'global rule' definitions fail static checks.
  - Uncontrolled Inclusion: Asserts that 'include "..."' statements are rejected.
  - Manifest Tamper Resistance: Asserts that any byte modification in a vetted rule file
    is immediately detected as a SHA-256 mismatch.
==============================================================================
"""

# Imports: testing tools, temp folders, JSON and paths.
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Make the sibling twu_yara_vet.py importable, then import it as 'v' for short.
# Ensure local scripts directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_yara_vet as v  # noqa: E402


# Tests for the static_check function (no external tools needed).
class Static(unittest.TestCase):
    """Static security and syntax boundary tests."""

    def test_ok(self):
        """Verifies that clean rules with permitted modules pass static check."""
        # Good file: allowed import plus a normal and a private rule should give both names and no error.
        names, why = v.static_check('import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }')
        self.assertEqual((names, why), (["A", "B"], None))

    def test_disabled_module(self):
        """Verifies that unvetted modules outside ALLOWED_MODULES trigger rejection."""
        # Importing a module not on the allowed list must be rejected.
        self.assertIn("disabled module", v.static_check('import "cuckoo"\nrule A { condition: true }')[1])

    def test_import_in_comment_ignored(self):
        """Verifies that commented module imports are properly ignored."""
        # A commented-out import must not cause rejection.
        self.assertIsNone(v.static_check('// import "cuckoo"\nrule A { condition: true }')[1])

    def test_global_and_include_rejected(self):
        """Verifies that global rules and include directives are strictly rejected."""
        # 'global' rules and 'include' lines must both be rejected.
        self.assertIn("global", v.static_check("global rule G { condition: true }")[1])
        self.assertIn("include", v.static_check('include "x.yar"\nrule A { condition: true }')[1])


# Tests that need the real vetted rules folder and its MANIFEST.json.
class Real(unittest.TestCase):
    """Cryptographic manifest and filesystem integrity verification tests."""

    # setUp runs before each test; skip them all if the rules data is absent.
    def setUp(self):
        """Skips tests if vetted rules directory or manifest is not present in standalone repo."""
        if not v.RULES.is_dir() or not (v.RULES / "MANIFEST.json").is_file():
            self.skipTest("vetted rules manifest not present in standalone test environment")

    # Every file's hash must match the manifest.
    def test_repo_rules_verify(self):
        """Verifies that repository rules match manifest SHA-256 digests."""
        self.assertEqual(v.verify(compile_index=False), [])

    # Copy the rules, change one file, and confirm verify reports a sha256 mismatch.
    def test_tamper_detected(self):
        """Verifies that tampering with a single byte in a rule triggers a sha256 mismatch alert."""
        with tempfile.TemporaryDirectory() as td:
            shutil.copytree(str(v.RULES), td + "/r")
            man = json.loads(Path(td, "r", "MANIFEST.json").read_text())
            target = Path(td, "r", man["files"][0]["path"])
            target.write_text(target.read_text() + "\n// tampered\n")
            self.assertTrue(any("sha256 mismatch" in p for p in v.verify(Path(td) / "r", compile_index=False)))

    # Every exclusion must come with a written reason.
    def test_exclusions_file_lists_reason(self):
        """Verifies that any excluded rule has a documented justification."""
        ex = json.loads((v.RULES / "EXCLUSIONS.json").read_text())
        for e in ex["excluded"]:
            self.assertTrue(e["rule"] and e["why"])

    # Every source needs a license, a full 40-character commit id and a GitHub URL; every file hash is 64 hex characters.
    def test_licenses_recorded(self):
        """Verifies that source licenses, 40-character commit hashes, and URLs are recorded."""
        man = json.loads((v.RULES / "MANIFEST.json").read_text())
        for s in man["sources"]:
            self.assertTrue(s["license"] and len(s["commit"]) == 40 and s["url"].startswith("https://github.com/"))
        self.assertTrue(all(len(f["sha256"]) == 64 for f in man["files"]))


# Lets you run this file directly to execute the tests.
if __name__ == "__main__":
    unittest.main()
