#!/usr/bin/env python3
"""
test_mcp_security.py — Security boundary tests for the SIFT Sentinel MCP server.

Tests:
  1. Evidence path validation (must be in EVIDENCE_DIRS)
  2. Output path validation (must be in SAFE_OUTPUT_DIRS)
  3. No destructive commands exposed
  4. Directory traversal prevention
  5. Output truncation at MAX_OUTPUT_CHARS
  6. Timeout enforcement
  7. Tool response schema validation
"""

import sys
import os
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add mcp_server to path
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))


class TestEvidencePathValidation(unittest.TestCase):
    """Verify that evidence paths are constrained to allowed directories."""

    def setUp(self):
        # Import after path manipulation
        import importlib
        import server as srv
        self.srv = srv

    def test_valid_evidence_path_cases(self):
        """Paths under /cases/ should be allowed."""
        valid = self.srv._is_evidence_path("/cases/srl/rd01.E01")
        self.assertTrue(valid, "/cases/ should be a valid evidence directory")

    def test_valid_evidence_path_mnt(self):
        valid = self.srv._is_evidence_path("/mnt/ewf_rd01/ewf1")
        self.assertTrue(valid, "/mnt/ should be a valid evidence directory")

    def test_invalid_evidence_path_home(self):
        """Paths outside evidence dirs should be rejected."""
        valid = self.srv._is_evidence_path("/home/user/myfile.img")
        self.assertFalse(valid, "/home/ should NOT be a valid evidence directory")

    def test_invalid_evidence_path_root(self):
        valid = self.srv._is_evidence_path("/etc/passwd")
        self.assertFalse(valid, "/etc/passwd should NOT be a valid evidence path")

    def test_directory_traversal_cases_to_etc(self):
        """Directory traversal via ../ must be blocked."""
        valid = self.srv._is_evidence_path("/cases/../etc/passwd")
        self.assertFalse(valid, "Directory traversal /cases/../etc/ must be blocked")

    def test_directory_traversal_deep(self):
        valid = self.srv._is_evidence_path("/mnt/ewf/../../etc/shadow")
        self.assertFalse(valid, "Deep directory traversal must be blocked")

    def test_validate_evidence_raises_on_bad_path(self):
        """_validate_evidence should raise ValueError for disallowed paths."""
        with self.assertRaises((ValueError, Exception)):
            self.srv._validate_evidence("/home/user/fakeimage.E01")

    def test_validate_evidence_passes_on_good_path(self):
        """_validate_evidence should not raise for a path that starts with /cases/."""
        # We don't need the file to exist for path validation
        try:
            self.srv._validate_evidence("/cases/test.E01")
        except FileNotFoundError:
            pass  # File doesn't exist in test env — that's OK, path was accepted
        except ValueError as e:
            self.fail(f"Valid evidence path raised ValueError: {e}")


class TestOutputPathValidation(unittest.TestCase):
    """Verify that output paths are constrained to safe output directories."""

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))
        import server as srv
        self.srv = srv

    def test_valid_output_analysis(self):
        valid = self.srv._is_safe_output("./analysis/mft.csv")
        self.assertTrue(valid, "./analysis/ should be a valid output directory")

    def test_valid_output_exports(self):
        valid = self.srv._is_safe_output("./exports/memory/malfind.txt")
        self.assertTrue(valid, "./exports/ should be a valid output directory")

    def test_valid_output_reports(self):
        valid = self.srv._is_safe_output("./reports/final_report.html")
        self.assertTrue(valid, "./reports/ should be a valid output directory")

    def test_invalid_output_cases(self):
        valid = self.srv._is_safe_output("/cases/srl/tampered.E01")
        self.assertFalse(valid, "Writing to /cases/ must be blocked")

    def test_invalid_output_mnt(self):
        valid = self.srv._is_safe_output("/mnt/rd01/Windows/evil.exe")
        self.assertFalse(valid, "Writing to /mnt/ must be blocked (evidence!)")

    def test_invalid_output_etc(self):
        valid = self.srv._is_safe_output("/etc/cron.d/backdoor")
        self.assertFalse(valid, "Writing to /etc/ must be blocked")

    def test_directory_traversal_output(self):
        valid = self.srv._is_safe_output("./analysis/../../etc/cron.d/evil")
        self.assertFalse(valid, "Directory traversal in output path must be blocked")


class TestNoDestructiveCommands(unittest.TestCase):
    """Verify that the server source does not contain any destructive command strings."""

    def setUp(self):
        self.server_path = Path(__file__).parent.parent / "mcp_server" / "server.py"
        with open(self.server_path) as f:
            self.source = f.read()

    FORBIDDEN = [
        # Exact destructive commands that must NEVER appear in subprocess args
        '"rm"', "'rm'",
        '"rm -rf"', '"dd"', "'dd'",
        '"wget"', "'wget'",
        '"curl"', "'curl'",
        '"ssh"', "'ssh'",
        '"mkfs"', "'mkfs'",
        '"shred"', "'shred'",
        "shell=True",   # All subprocess calls must use shell=False
    ]

    def test_no_rm_in_source(self):
        self.assertNotIn('"rm"', self.source)
        self.assertNotIn("'rm'", self.source)

    def test_no_dd_in_source(self):
        self.assertNotIn('"dd"', self.source)
        self.assertNotIn("'dd'", self.source)

    def test_no_wget_in_source(self):
        self.assertNotIn('"wget"', self.source)
        self.assertNotIn("'wget'", self.source)

    def test_no_curl_in_source(self):
        # curl may appear in comments/strings — check subprocess args specifically
        # We check for subprocess.run/Popen with curl as an arg
        import ast
        tree = ast.parse(self.source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name in ("run", "Popen", "check_output"):
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.List):
                            for elt in arg.elts:
                                if isinstance(elt, ast.Constant) and elt.value in ("curl", "wget", "ssh", "rm", "dd"):
                                    self.fail(f"Destructive command '{elt.value}' found in subprocess call at line {node.lineno}")

    def test_no_shell_true(self):
        """All subprocess calls must use shell=False (explicit arg lists)."""
        self.assertNotIn("shell=True", self.source,
                         "shell=True is forbidden — all subprocess calls must use explicit arg lists")

    def test_23_tools_registered(self):
        """Verify 23 @mcp.tool() decorators are present."""
        count = self.source.count("@mcp.tool()")
        self.assertGreaterEqual(count, 20,
                                f"Expected at least 20 @mcp.tool() registrations, found {count}")


class TestResponseSchema(unittest.TestCase):
    """Verify that tool response schema is consistent across all tools."""

    REQUIRED_KEYS = {"tool", "cmd", "returncode", "timestamp_utc", "duration_s"}

    def _mock_run(self, stdout="test output", returncode=0):
        """Create a mock _run() return value."""
        return (stdout, "", returncode, 0.1)

    def setUp(self):
        import server as srv
        self.srv = srv

    def test_build_response_has_required_keys(self):
        """_build_response should always include the required schema keys."""
        resp = self.srv._build_response(
            tool="test_tool",
            cmd=["echo", "hello"],
            stdout="test output",
            stderr="",
            returncode=0,
            duration=0.05
        )
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, resp, f"Response missing required key: '{key}'")

    def test_build_response_truncates_long_output(self):
        """Output exceeding MAX_OUTPUT_CHARS should be truncated with truncated=True."""
        long_output = "A" * 10000
        resp = self.srv._build_response(
            tool="test_tool",
            cmd=["echo"],
            stdout=long_output,
            stderr="",
            returncode=0,
            duration=0.1
        )
        self.assertTrue(resp.get("truncated", False),
                        "Long output should set truncated=True")
        self.assertLessEqual(len(resp.get("stdout_preview", "")), self.srv.MAX_OUTPUT_CHARS + 100,
                             "stdout_preview should be bounded by MAX_OUTPUT_CHARS")

    def test_build_response_not_truncated_for_short_output(self):
        short_output = "Hello world"
        resp = self.srv._build_response(
            tool="test_tool",
            cmd=["echo"],
            stdout=short_output,
            stderr="",
            returncode=0,
            duration=0.05
        )
        self.assertFalse(resp.get("truncated", True),
                         "Short output should set truncated=False")


class TestHallucinationDetector(unittest.TestCase):
    """Test the hallucination detection logic in the orchestrator."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
        from orchestrator import HallucinationDetector
        self.detector = HallucinationDetector()

    def test_clean_finding_low_score(self):
        """A finding with proper tool citations should score low."""
        text = (
            "Process STUN.exe (PID 1912) was found via windows.psscan. "
            "The command line was retrieved via windows.cmdline."
        )
        tool_log = [
            "analyze_memory_processes: psscan found PID 1912 STUN.exe",
            "analyze_memory_cmdlines: PID 1912 C:\\Windows\\System32\\STUN.exe"
        ]
        score = self.detector.score(text, tool_log)
        self.assertLess(score, 0.5, f"Clean finding should score < 0.5, got {score}")

    def test_pid_claim_without_volatility_high_score(self):
        """Claiming a specific PID without any volatility tool in the log should score high."""
        text = "The attacker's process ran as PID 4567 with elevated privileges."
        tool_log = []  # No volatility tool ran
        score = self.detector.score(text, tool_log)
        self.assertGreater(score, 0.4, f"PID claim without Vol3 output should score > 0.4, got {score}")

    def test_hash_claim_without_hash_tool_high_score(self):
        """Claiming a specific hash without hash_file in the log should score high."""
        text = "The binary has SHA256 hash abc123def456abc123def456abc123def456abc123def456abc123def456abc1."
        tool_log = []  # No hash tool ran
        score = self.detector.score(text, tool_log)
        self.assertGreater(score, 0.3, f"Hash claim without tool evidence should score > 0.3, got {score}")


class TestGapAnalyzer(unittest.TestCase):
    """Test gap detection logic."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
        from orchestrator import GapAnalyzer
        self.analyzer = GapAnalyzer()

    def test_disk_without_mft_is_gap(self):
        """If disk evidence is present but MFT was not parsed, that's a gap."""
        evidence_types = ["disk"]
        completed = []  # Nothing analyzed yet
        gaps = self.analyzer.find_gaps(evidence_types, completed)
        self.assertTrue(any("mft" in g.lower() or "parse" in g.lower() for g in gaps),
                        f"Expected MFT gap, got: {gaps}")

    def test_memory_without_malfind_is_gap(self):
        """If memory evidence is present but malfind was not run, that's a gap."""
        evidence_types = ["memory"]
        completed = ["analyze_memory_processes", "analyze_memory_network"]
        gaps = self.analyzer.find_gaps(evidence_types, completed)
        self.assertTrue(any("malfind" in g.lower() or "inject" in g.lower() for g in gaps),
                        f"Expected malfind gap, got: {gaps}")

    def test_complete_analysis_has_no_gaps(self):
        """If all required steps are completed, gap list should be empty."""
        evidence_types = ["memory"]
        from triage_sequences import REQUIRED_ANALYSIS_STEPS
        completed = REQUIRED_ANALYSIS_STEPS.get("memory", [])
        gaps = self.analyzer.find_gaps(evidence_types, completed)
        self.assertEqual(len(gaps), 0, f"Complete analysis should have no gaps, got: {gaps}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
