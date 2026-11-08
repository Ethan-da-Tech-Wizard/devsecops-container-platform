#!/usr/bin/env python3
"""
==============================================================================
Program: Test Suite for Deterministic Document Generator (test_twu_docgen.py)
Programmer: The Maintainer <maintainer@example.invalid>
Organization: TWU LLC
License: MIT License 2026
Purpose: Validate static AST parsing, Dockerfile directive extraction, GitHub
         Actions workflow parsing, and whitepaper synthesis logic with zero
         network calls and zero external dependencies.

Threat Model & Regression Vectors Tested:
  - Regression in Dockerfile Security Parsing: Ensures detection of non-root users,
    exec-form entrypoints, multi-stage stages, and healthcheck probes.
  - Regression in CI/CD Workflow Inspection: Verifies accurate detection of ShellCheck,
    Bandit SAST, Trivy scanner, and Python version matrices.
  - Exception Handling on Malformed Paths: Asserts ValueError on invalid directories.
==============================================================================
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

# Ensure local scripts directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_docgen


class TestDocgen(unittest.TestCase):
    """Unit test suite verifying deterministic AST document generation."""

    def setUp(self):
        """Creates an isolated temporary test directory before each test."""
        self.test_dir = tempfile.mkdtemp(prefix="twu-docgen-test-")
        self.root = Path(self.test_dir)

    def tearDown(self):
        """Cleans up the temporary directory after each test."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_invalid_directory_raises(self):
        """Verifies that an unresolvable or nonexistent directory raises ValueError."""
        with self.assertRaises(ValueError):
            twu_docgen.ProjectAnalyzer(self.root / "nonexistent_dir_123")

    def test_dockerfile_analysis(self):
        """Verifies extraction of base images, stages, non-root user, and healthcheck from Dockerfile."""
        dockerfile = self.root / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim-bookworm AS builder\n"
            "WORKDIR /build\n"
            "FROM python:3.12-slim-bookworm AS runtime\n"
            "USER appuser:appgroup\n"
            "HEALTHCHECK CMD curl -f http://localhost/\n"
            "ENTRYPOINT [\"python3\"]\n",
            encoding="utf-8"
        )
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        info = analyzer.inspect_dockerfile()

        self.assertTrue(info["present"])
        self.assertIn("builder", info["stages"])
        self.assertIn("runtime", info["stages"])
        self.assertEqual(info["non_root_user"], "appuser:appgroup")
        self.assertTrue(info["has_healthcheck"])
        self.assertTrue(any("Exec-form" in feat for feat in info["security_features"]))

    def test_workflows_analysis(self):
        """Verifies parsing of GitHub Actions workflow jobs, tools, and python-version matrices."""
        wf_dir = self.root / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        ci_yml = wf_dir / "ci.yml"
        ci_yml.write_text(
            "name: DevSecOps CI\n"
            "jobs:\n"
            "  lint:\n"
            "    steps:\n"
            "      - run: shellcheck scripts/*.sh\n"
            "      - run: bandit -r scripts/\n"
            "  scan:\n"
            "    steps:\n"
            "      - uses: aquasecurity/trivy-action\n"
            "  test:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        python-version: ['3.10', '3.12']\n",
            encoding="utf-8"
        )
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        workflows = analyzer.inspect_workflows()

        self.assertEqual(len(workflows), 1)
        wf = workflows[0]
        self.assertEqual(wf["name"], "DevSecOps CI")
        self.assertIn("lint", wf["jobs"])
        self.assertIn("scan", wf["jobs"])
        self.assertIn("3.10", wf["matrix_versions"])
        self.assertIn("3.12", wf["matrix_versions"])
        self.assertTrue(any("ShellCheck" in s for s in wf["security_scans"]))
        self.assertTrue(any("Bandit" in s for s in wf["security_scans"]))
        self.assertTrue(any("Trivy" in s for s in wf["security_scans"]))

    def test_whitepaper_synthesis(self):
        """Verifies deterministic synthesis of executive summary, threat model, and STAR interview sections."""
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        doc = generator.generate()

        self.assertIn("# Platform Architecture & DevSecOps Technical Whitepaper", doc)
        self.assertIn("## 1. Executive Summary", doc)
        self.assertIn("## 4. Supply Chain Threat Model", doc)
        self.assertIn("## 5. Senior Engineering Interview Talking Points (STAR Method)", doc)

    def test_quickstart_synthesis(self):
        """Verifies generation of quickstart runbook containing shellcheck, compileall, and test commands."""
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        qs = generator.generate_quickstart()

        self.assertIn("# Quick Start Runbook:", qs)
        self.assertIn("shellcheck", qs)
        self.assertIn("compileall", qs)


if __name__ == "__main__":
    unittest.main()
