#!/usr/bin/env python3
# ==============================================================================
# Program: test_twu_docgen.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Comprehensive unit test suite for twu_docgen.py verifying static AST
#          parsing, Dockerfile directive extraction, CI/CD workflow security inspection,
#          and deterministic whitepaper synthesis without network dependencies.
# ==============================================================================

# Deferred annotations, matching the module under test.
from __future__ import annotations
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

# Ensure local scripts directory is importable
# Scripts are not an installed package, so put this directory on sys.path first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_docgen


class TestDocgen(unittest.TestCase):
    """Unit test suite verifying deterministic AST document generation.

    The module under test (twu_docgen.py) reads a project folder statically (it never runs
    Docker or GitHub Actions) and renders Markdown. Each test builds a minimal fake project
    in a temp directory, so results depend only on the fixture text, never on this repo's files.
    Run: python3 -m unittest discover -s scripts/ -p "test_*.py" (same command as CI).
    """

    def setUp(self):
        """Creates an isolated temporary test directory before each test."""
        # Fresh scratch project per test so fixtures never leak between cases.
        self.test_dir = tempfile.mkdtemp(prefix="twu-docgen-test-")
        self.root = Path(self.test_dir)

    def tearDown(self):
        """Cleans up the temporary directory after each test."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # Input validation comes first: the analyzer must refuse a bad root up front instead of
    # producing an empty (and misleading) report later.
    def test_invalid_directory_raises(self):
        """Verifies that an unresolvable or nonexistent directory raises ValueError.

        Scenario: a path that does not exist under the temp dir. Why it matters: a typo in the
        CLI argument must fail loudly rather than document an empty project.
        """
        with self.assertRaises(ValueError):
            twu_docgen.ProjectAnalyzer(self.root / "nonexistent_dir_123")

    def test_dockerfile_analysis(self):
        """Verifies extraction of base images, stages, non-root user, and healthcheck from Dockerfile.

        Scenario: two stages (builder, runtime), USER appuser:appgroup, a HEALTHCHECK and an exec-form
        ENTRYPOINT. Why it matters: these facts feed the whitepaper's security-posture claims, so
        they must come from the file, not from assumptions.
        """
        # Fixture: a two-stage Dockerfile with a non-root user, healthcheck and exec-form entrypoint.
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
        # Stage names are stored lower-cased.
        self.assertIn("builder", info["stages"])
        self.assertIn("runtime", info["stages"])
        self.assertEqual(info["non_root_user"], "appuser:appgroup")
        self.assertTrue(info["has_healthcheck"])
        self.assertTrue(any("Exec-form" in feat for feat in info["security_features"]))

    def test_workflows_analysis(self):
        """Verifies parsing of GitHub Actions workflow jobs, tools, and python-version matrices.

        Scenario: one workflow with lint/scan/test jobs that invoke shellcheck, bandit and the Trivy
        action. Why it matters: the document lists which security scanners CI runs; a missed or
        invented scanner would make the report wrong. The parser is a plain-text scan (no YAML library).
        """
        wf_dir = self.root / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        # Fixture workflow: three jobs (lint, scan, test) plus a python-version matrix; the `strategy` key must not be counted as a job.
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

        # Exactly one workflow file was created, so exactly one record is expected.
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
        """Verifies deterministic synthesis of executive summary, threat model, and STAR interview sections.

        Scenario: an empty project. Pins the section headings other docs and readers link to.
        """
        # An empty project is enough: the whitepaper text is static apart from detected facts.
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        doc = generator.generate()

        self.assertIn("# Platform Architecture & DevSecOps Technical Whitepaper", doc)
        self.assertIn("## 1. Executive Summary", doc)
        self.assertIn("## 4. Supply Chain Threat Model", doc)
        self.assertIn("## 5. Senior Engineering Interview Talking Points (STAR Method)", doc)

    def test_quickstart_synthesis(self):
        """Verifies generation of quickstart runbook containing shellcheck, compileall, and test commands.

        Scenario: an empty project; the runbook text is static, so it must always list the
        validation commands (shellcheck and compileall are asserted; test commands are listed too).
        """
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        qs = generator.generate_quickstart()

        self.assertIn("# Quick Start Runbook:", qs)
        self.assertIn("shellcheck", qs)
        self.assertIn("compileall", qs)


if __name__ == "__main__":
    unittest.main()
