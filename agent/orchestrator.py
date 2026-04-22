#!/usr/bin/env python3
"""
orchestrator.py — Self-correcting incident response agent orchestrator.

SANS "Find Evil!" Hackathon — SIFT Autonomous Agent
Protocol SIFT / Claude Code integration layer

Usage:
    python orchestrator.py \
        --case-dir /cases/srl \
        --evidence disk:/cases/srl/rd01.E01 memory:/cases/memory/rd01.img \
        --max-iterations 3 \
        --output-dir /cases/srl/analysis

The orchestrator drives Claude Code (claude --print) through an autonomous
DFIR triage loop, evaluating output quality, detecting hallucinations,
identifying analysis gaps, and self-correcting across iterations.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from triage_sequences import (
    ANALYST_HEURISTICS,
    GAP_REMEDIATION,
    REQUIRED_ANALYSIS_STEPS,
    TRIAGE_SEQUENCES,
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

CONFIDENCE_LEVELS = ("confirmed", "probable", "possible", "unverified")


@dataclasses.dataclass
class Finding:
    """A single atomic forensic finding produced during analysis."""

    artifact_type: str          # process | network | file | registry | timeline | service | …
    description: str
    confidence: str             # confirmed | probable | possible | unverified
    tool_evidence: list[str]    # exact commands / tool outputs that support this finding
    ioc: str | None             # IP, hash, filename, domain, username, …
    timestamp_utc: str | None   # ISO-8601 if available
    is_hallucination: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Finding:
        d.setdefault("is_hallucination", False)
        return Finding(**d)

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []
        if self.confidence not in CONFIDENCE_LEVELS:
            errors.append(f"Unknown confidence level '{self.confidence}'")
        if not self.tool_evidence:
            errors.append("No tool_evidence citations — finding cannot be confirmed")
        if not self.description.strip():
            errors.append("Empty description")
        return errors


# ---------------------------------------------------------------------------
# Hallucination detector
# ---------------------------------------------------------------------------

class HallucinationDetector:
    """
    Scores free-form analyst text for hallucination risk.

    The detector looks for specific, verifiable claims (file contents,
    registry values, PID numbers, exact timestamps) and checks whether
    the corresponding tool that would have produced those details was
    actually executed.
    """

    # (claim_pattern, required_tool_pattern, description)
    CLAIM_RULES: list[tuple[re.Pattern[str], re.Pattern[str], str]] = [
        (
            re.compile(r"file content|file contains|reads:|content of", re.I),
            re.compile(r"icat|cat |strings |xxd |hexdump|file_read|read_file", re.I),
            "Specific file content claim without icat/cat/strings being run",
        ),
        (
            re.compile(r"registry value|reg key|HKLM|HKCU|CurrentVersion\\Run", re.I),
            re.compile(r"RECmd|regedit|reg query|printkey|hivelist|RegRipper", re.I),
            "Specific registry value claim without RECmd/volatility registry plugin",
        ),
        (
            re.compile(r"PID\s*[=:]?\s*\d+|process ID\s+\d+|\(PID\s+\d+\)", re.I),
            re.compile(r"pslist|psscan|pstree|tasklist|ps aux|procexp", re.I),
            "Specific PID referenced without process listing tool being run",
        ),
        (
            re.compile(
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",  # ISO-ish timestamp
                re.I,
            ),
            re.compile(
                r"log2timeline|mactime|MFTECmd|plaso|evtx_dump|timeline|"
                r"fls -m|ils -m|stat |istat",
                re.I,
            ),
            "Specific timestamp claim without timeline or MFT/log tool being run",
        ),
        (
            re.compile(r"hash[:\s]+[0-9a-fA-F]{32,64}|MD5[:\s]+|SHA-?256[:\s]+", re.I),
            re.compile(r"md5sum|sha256sum|hashdeep|Get-FileHash|fciv|certutil -hash", re.I),
            "Specific hash value without hashing tool being run",
        ),
        (
            re.compile(r"malfind|injected code|RWX region|shellcode at", re.I),
            re.compile(r"malfind|vol.*malfind", re.I),
            "Malfind / injection claim without volatility malfind being run",
        ),
        (
            re.compile(r"YARA rule|yara match|matched rule", re.I),
            re.compile(r"yara |yar |yara-python", re.I),
            "YARA match claim without YARA tool being run",
        ),
        (
            re.compile(r"network connection|listening on port|established.*:\d{2,5}", re.I),
            re.compile(r"netscan|netstat|ss -|lsof -i|nmap|tshark|tcpdump|netscan", re.I),
            "Network connection claim without network analysis tool being run",
        ),
    ]

    def score(self, text: str, tool_log: list[str]) -> float:
        """
        Return a hallucination risk score between 0.0 (clean) and 1.0 (high risk).
        Also returns detailed flagged items via self.suspicious_claims after calling.
        """
        self.suspicious_claims: list[dict[str, str]] = []
        tool_context = "\n".join(tool_log)

        triggered = 0
        for claim_re, tool_re, description in self.CLAIM_RULES:
            if claim_re.search(text):
                # The claim is made — check if supporting tool was run
                if not tool_re.search(tool_context):
                    self.suspicious_claims.append(
                        {
                            "rule": description,
                            "claim_snippet": self._extract_snippet(text, claim_re),
                        }
                    )
                    triggered += 1

        if not self.CLAIM_RULES:
            return 0.0

        raw_score = triggered / len(self.CLAIM_RULES)

        # Boost score if there are very specific numeric claims with no tool support
        specificity_bonus = 0.0
        ip_matches = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text
        )
        if len(ip_matches) > 3 and not re.search(
            r"netscan|netstat|tshark|tcpdump", tool_context, re.I
        ):
            specificity_bonus += 0.15

        return min(1.0, raw_score + specificity_bonus)

    # ------------------------------------------------------------------
    def report(self) -> dict[str, Any]:
        """Return structured report of suspicious claims from last score() call."""
        return {
            "suspicious_claim_count": len(getattr(self, "suspicious_claims", [])),
            "suspicious_claims": getattr(self, "suspicious_claims", []),
        }

    @staticmethod
    def _extract_snippet(text: str, pattern: re.Pattern[str], window: int = 80) -> str:
        m = pattern.search(text)
        if not m:
            return ""
        start = max(0, m.start() - window // 2)
        end = min(len(text), m.end() + window // 2)
        return text[start:end].replace("\n", " ").strip()


# ---------------------------------------------------------------------------
# Gap analyzer
# ---------------------------------------------------------------------------

class GapAnalyzer:
    """
    Identifies analytical gaps — things that SHOULD have been done given the
    available evidence but weren't recorded in the completed analysis set.
    """

    def find_gaps(
        self,
        evidence_types: list[str],
        completed_analyses: list[str],
    ) -> list[str]:
        """
        Return human-readable gap descriptions for the next iteration prompt.

        Args:
            evidence_types: e.g. ["disk", "memory"]
            completed_analyses: keys from REQUIRED_ANALYSIS_STEPS that were done
        """
        gaps: list[str] = []
        completed_set = set(completed_analyses)

        for ev_type in evidence_types:
            required = REQUIRED_ANALYSIS_STEPS.get(ev_type, [])
            for step in required:
                if step not in completed_set:
                    remedy = GAP_REMEDIATION.get(step, f"Complete {step} analysis.")
                    gaps.append(f"[{ev_type.upper()}] MISSING: {step} — {remedy}")

        # Cross-evidence gaps
        has_disk = "disk" in evidence_types
        has_memory = "memory" in evidence_types
        has_pcap = "pcap" in evidence_types

        if has_disk and has_memory and "disk_memory_correlation" not in completed_set:
            gaps.append(
                "[DISK+MEMORY] MISSING: disk_memory_correlation — "
                + GAP_REMEDIATION["disk_memory_correlation"]
            )
        if (has_disk or has_memory) and "persistence_checked" not in completed_set:
            gaps.append(
                "[PERSISTENCE] MISSING: persistence_checked — "
                + GAP_REMEDIATION["persistence_checked"]
            )
        if (has_disk or has_memory) and "ioc_enrichment" not in completed_set:
            gaps.append(
                "[ENRICHMENT] MISSING: ioc_enrichment — "
                + GAP_REMEDIATION["ioc_enrichment"]
            )
        if has_pcap and (has_disk or has_memory) and "network_process_correlation" not in completed_set:
            gaps.append(
                "[PCAP+HOST] MISSING: network_process_correlation — "
                + GAP_REMEDIATION["network_process_correlation"]
            )

        return gaps

    @staticmethod
    def infer_completed(raw_output: str) -> list[str]:
        """
        Heuristically infer which analysis steps were completed by scanning
        Claude's raw output for tool invocations and result keywords.
        """
        completed: list[str] = []
        text = raw_output.lower()

        tool_map: list[tuple[str, list[str]]] = [
            ("mft_parsed",              ["mftecmd", "analyzemft", "mft parsed", "mft entries"]),
            ("registry_parsed",         ["recmd", "regripper", "registry parsed", "run keys"]),
            ("event_logs_parsed",       ["evtx_dump", "event log", "evtx", "event id 4624"]),
            ("shimcache_parsed",        ["shimcache", "appcompatcache", "amcache"]),
            ("yara_run",                ["yara", "yar match", "yara rule"]),
            ("pslist_run",              ["pslist", "process list", "windows.pslist"]),
            ("psscan_run",              ["psscan", "windows.psscan"]),
            ("cmdline_run",             ["cmdline", "windows.cmdline", "command line"]),
            ("netscan_run",             ["netscan", "windows.netscan", "network scan"]),
            ("malfind_run",             ["malfind", "windows.malfind"]),
            ("svcscan_run",             ["svcscan", "windows.svcscan", "service scan"]),
            ("protocol_distribution",   ["protocol distribution", "io,phs", "capinfos"]),
            ("dns_analysis",            ["dns query", "dns analysis", "tshark -y dns"]),
            ("http_analysis",           ["http analysis", "user-agent", "http stream"]),
            ("c2_beacon_check",         ["beacon", "c2 pattern", "inter-arrival"]),
            ("auth_events_parsed",      ["auth event", "logon event", "authentication"]),
            ("lateral_movement_checked", ["lateral movement", "pass-the-hash", "psexec"]),
            ("privilege_escalation_checked", ["privilege escalation", "sudo", "uac bypass"]),
            ("directory_enumerated",    ["directory listing", "find .", "ls -la"]),
            ("hashes_computed",         ["sha256", "md5sum", "hashdeep", "get-filehash"]),
            ("disk_memory_correlation", ["disk and memory", "cross-reference", "on-disk hash"]),
            ("persistence_checked",     ["persistence", "run key", "scheduled task", "startup"]),
            ("timeline_generated",      ["timeline", "log2timeline", "mactime", "super-timeline"]),
            ("ioc_enrichment",          ["virustotal", "threat intel", "abuse.ch", "enrichment"]),
            ("network_process_correlation", ["process.*connection", "network.*process", "responsible process"]),
        ]

        for step, keywords in tool_map:
            if any(kw in text for kw in keywords):
                completed.append(step)

        return completed


# ---------------------------------------------------------------------------
# Execution logger
# ---------------------------------------------------------------------------

class ExecutionLogger:
    """
    Writes a JSONL audit trail to ./analysis/execution_log.jsonl.
    Each line is a self-contained JSON event record.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._iteration: int = 0

    def set_iteration(self, iteration: int) -> None:
        self._iteration = iteration

    # ------------------------------------------------------------------
    def _write(self, event: str, data: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iteration": self._iteration,
            "event": event,
            "data": data,
        }
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    # ------------------------------------------------------------------
    def log_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | list[Any] | str,
        output_preview: str,
        duration_s: float,
    ) -> None:
        self._write(
            "tool_end",
            {
                "tool": tool_name,
                "args": args,
                "output_preview": output_preview[:500],
                "duration_s": round(duration_s, 3),
            },
        )

    def log_llm_start(self, prompt_preview: str) -> None:
        self._write("llm_start", {"prompt_preview": prompt_preview[:300]})

    def log_llm_interaction(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        model: str,
    ) -> None:
        self._write(
            "llm_end",
            {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "model": model,
            },
        )

    def log_finding(self, finding: Finding) -> None:
        self._write("finding", finding.to_dict())

    def log_gap(self, gap: str) -> None:
        self._write("gap", {"gap": gap})

    def log_correction(self, original: str, corrected: str, reason: str) -> None:
        self._write(
            "correction",
            {"original": original, "corrected": corrected, "reason": reason},
        )

    def log_quality(self, score: float, details: dict[str, Any]) -> None:
        self._write("quality_score", {"score": score, **details})

    def log_error(self, message: str, context: dict[str, Any] | None = None) -> None:
        self._write("error", {"message": message, "context": context or {}})


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _format_evidence_list(evidence_items: list[tuple[str, str]]) -> str:
    return "\n".join(f"  - {ev_type.upper()}: {path}" for ev_type, path in evidence_items)


def _build_sequence_block(evidence_types: list[str]) -> str:
    lines: list[str] = []
    # Deduplicate while preserving order
    seen: set[str] = set()
    for ev_type in evidence_types:
        if ev_type in seen:
            continue
        seen.add(ev_type)
        seq = TRIAGE_SEQUENCES.get(ev_type)
        if seq:
            lines.append(f"\n=== {ev_type.upper()} ANALYSIS SEQUENCE ===")
            lines.extend(seq)

    # Add combined sequence if both disk and memory present
    if "disk" in evidence_types and "memory" in evidence_types:
        lines.append("\n=== DISK + MEMORY CORRELATION ===")
        lines.extend(TRIAGE_SEQUENCES.get("disk+memory", []))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------

class TriageOrchestrator:
    """
    Drives the autonomous DFIR triage loop.

    The loop runs up to max_iterations of Claude Code execution. After each
    iteration it evaluates output quality, detects hallucinations, identifies
    analytical gaps, and — if quality is insufficient — constructs a refined
    prompt for the next pass.
    """

    QUALITY_THRESHOLD = 0.65   # minimum quality score to skip further iterations
    HALLUCINATION_THRESHOLD = 0.4  # halt and flag if above this

    def __init__(
        self,
        case_dir: Path,
        evidence_items: list[tuple[str, str]],  # [(type, path), …]
        max_iterations: int,
        output_dir: Path,
    ) -> None:
        self.case_dir = case_dir
        self.evidence_items = evidence_items
        self.evidence_types = list({ev_type for ev_type, _ in evidence_items})
        self.max_iterations = max_iterations
        self.output_dir = output_dir
        self.analysis_dir = output_dir / "analysis"
        self.analysis_dir.mkdir(parents=True, exist_ok=True)

        self.logger = ExecutionLogger(self.analysis_dir / "execution_log.jsonl")
        self.hallucination_detector = HallucinationDetector()
        self.gap_analyzer = GapAnalyzer()

        self.all_findings: list[Finding] = []
        self.all_iterations: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> Path:
        """
        Execute the full triage loop.
        Returns the path to the final HTML report.
        """
        _stderr(f"[ORCHESTRATOR] Starting autonomous triage — {len(self.evidence_items)} evidence item(s), "
                f"max {self.max_iterations} iteration(s)")
        _stderr(f"[ORCHESTRATOR] Evidence types: {self.evidence_types}")

        previous_findings: list[Finding] = []
        gaps: list[str] = []
        quality_score = 0.0

        for iteration in range(1, self.max_iterations + 1):
            _stderr(f"\n[ITERATION {iteration}/{self.max_iterations}] Building prompt …")
            self.logger.set_iteration(iteration)

            prompt = self._build_claude_prompt(iteration, previous_findings, gaps)
            self._log_iteration_start(iteration, prompt)

            _stderr(f"[ITERATION {iteration}] Running Claude Code …")
            t0 = time.monotonic()
            raw_output, stderr_output = self._run_claude_code(prompt, self.output_dir)
            duration = time.monotonic() - t0
            _stderr(f"[ITERATION {iteration}] Claude returned in {duration:.1f}s "
                    f"({len(raw_output)} chars)")

            self.logger.log_tool_call(
                "claude_code",
                {"prompt_length": len(prompt)},
                raw_output[:500],
                duration,
            )

            # Evaluate output
            findings = self._extract_findings(raw_output)
            quality_score, quality_detail = self._evaluate_findings(raw_output, findings, iteration)
            gaps = self._detect_gaps(findings, raw_output)

            _stderr(f"[ITERATION {iteration}] Quality score: {quality_score:.2f} | "
                    f"Findings: {len(findings)} | Gaps: {len(gaps)}")

            self._log_iteration(iteration, prompt, raw_output, findings, gaps, quality_score)

            self.all_findings.extend(findings)
            previous_findings = findings

            for gap in gaps:
                self.logger.log_gap(gap)
                _stderr(f"  GAP: {gap}")

            self.logger.log_quality(quality_score, quality_detail)

            # Early exit if quality is sufficient and no gaps remain
            if quality_score >= self.QUALITY_THRESHOLD and not gaps:
                _stderr(f"[ORCHESTRATOR] Quality threshold met — stopping at iteration {iteration}")
                break

            # Halt on extreme hallucination risk
            h_score = quality_detail.get("hallucination_score", 0.0)
            if h_score > self.HALLUCINATION_THRESHOLD and iteration == self.max_iterations:
                _stderr(f"[WARNING] High hallucination risk ({h_score:.2f}) in final iteration — "
                        "report findings marked unverified")

        # Synthesize final report
        _stderr("\n[ORCHESTRATOR] Generating final report …")
        report_path = self._generate_final_report()
        _stderr(f"[ORCHESTRATOR] Done. Report: {report_path}")
        return report_path

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_claude_prompt(
        self,
        iteration: int,
        previous_findings: list[Finding],
        gaps: list[str],
    ) -> str:
        evidence_block = _format_evidence_list(self.evidence_items)
        analysis_dir = str(self.analysis_dir)

        if iteration == 1:
            sequence_block = _build_sequence_block(self.evidence_types)
            heuristics_block = self._format_heuristics()

            prompt = textwrap.dedent(f"""
                You are an autonomous DFIR analyst executing an incident response triage.
                Your task is to investigate the following evidence and produce structured findings.

                EVIDENCE:
                {evidence_block}

                ANALYSIS OUTPUT DIRECTORY: {analysis_dir}

                MANDATORY RULES:
                1. For EVERY finding, you MUST cite the exact command or tool output that produced it.
                   Do NOT state anything as fact unless you can reference a specific tool run.
                2. Write all findings to {analysis_dir}/findings_{iteration}.json as a JSON array.
                   Each object must have: artifact_type, description, confidence, tool_evidence (list),
                   ioc (or null), timestamp_utc (or null).
                3. Confidence levels: "confirmed" (tool ran, clear evidence), "probable" (strong
                   indicators but not definitive), "possible" (circumstantial), "unverified" (suspected
                   but no tool run yet).
                4. If you cannot run a tool due to environment constraints, record the gap explicitly
                   in the findings file with confidence "unverified" and tool_evidence: [].
                5. At the end, write a summary to {analysis_dir}/summary_{iteration}.md.

                ANALYSIS SEQUENCE:
                {sequence_block}

                RED FLAGS TO CHECK:
                {heuristics_block}

                Begin analysis now. Think step-by-step. Run tools in the sequence above.
                Record findings as you go — do not wait until the end.
            """).strip()

        elif iteration < self.max_iterations:
            prev_summary = self._summarize_findings(previous_findings)
            gap_block = "\n".join(f"  - {g}" for g in gaps) if gaps else "  None identified."
            correction_instructions = self._build_correction_instructions(previous_findings)

            prompt = textwrap.dedent(f"""
                You are an autonomous DFIR analyst continuing an incident investigation.
                This is iteration {iteration} of {self.max_iterations}.

                EVIDENCE:
                {evidence_block}

                ANALYSIS OUTPUT DIRECTORY: {analysis_dir}

                PREVIOUS ITERATION FINDINGS SUMMARY:
                {prev_summary}

                IDENTIFIED GAPS THAT NEED INVESTIGATION:
                {gap_block}

                SELF-CORRECTION REQUIRED:
                {correction_instructions}

                INSTRUCTIONS:
                1. Re-investigate the identified gaps with deeper analysis.
                2. For any previous finding marked "unverified" or "possible", attempt to upgrade
                   confidence by running the appropriate tool and adding it to tool_evidence.
                3. For any previous finding with empty tool_evidence, either confirm it with a tool
                   or downgrade it to "unverified" and flag it clearly.
                4. Write updated findings to {analysis_dir}/findings_{iteration}.json.
                   Include ALL findings (not just new ones) with updated confidence levels.
                5. Append a correction log to {analysis_dir}/corrections_{iteration}.json listing
                   any finding descriptions or confidence levels you changed and why.

                MANDATORY RULES:
                - Every claim must have tool_evidence. No exceptions.
                - If a tool is unavailable, mark the finding "unverified" and explain.
                - Be precise: cite exact commands, not generic references.

                Begin deeper analysis now.
            """).strip()

        else:
            # Final synthesis iteration
            all_summary = self._summarize_all_iterations()
            gap_block = "\n".join(f"  - {g}" for g in gaps) if gaps else "  None remaining."

            prompt = textwrap.dedent(f"""
                You are an autonomous DFIR analyst completing a {self.max_iterations}-iteration
                incident investigation. This is the FINAL synthesis iteration.

                EVIDENCE:
                {evidence_block}

                ANALYSIS OUTPUT DIRECTORY: {analysis_dir}

                FULL INVESTIGATION SUMMARY ACROSS ALL ITERATIONS:
                {all_summary}

                REMAINING GAPS (address if time permits):
                {gap_block}

                FINAL SYNTHESIS INSTRUCTIONS:
                1. Consolidate all confirmed and probable findings into a single definitive finding set.
                2. Remove or downgrade any finding that still lacks tool_evidence.
                3. Build the complete IOC list: all IPs, hashes, filenames, domains, usernames.
                4. Establish the attack timeline with timestamps where available.
                5. Identify the likely attacker TTPs mapped to MITRE ATT&CK framework.
                6. Write the consolidated findings to {analysis_dir}/findings_final.json.
                7. Write the full narrative report to {analysis_dir}/report_narrative.md with sections:
                   - Executive Summary
                   - Attack Timeline
                   - Technical Findings (by artifact type)
                   - Indicators of Compromise
                   - MITRE ATT&CK Mapping
                   - Evidence Chain
                   - Recommendations

                MANDATORY RULES:
                - Every IOC must be traceable to a specific finding in findings_final.json.
                - Every finding must have non-empty tool_evidence.
                - Mark any uncertain items "possible" or "unverified" — do NOT fabricate certainty.

                Complete the synthesis now.
            """).strip()

        return prompt

    # ------------------------------------------------------------------
    # Claude Code execution
    # ------------------------------------------------------------------

    def _run_claude_code(
        self,
        prompt: str,
        working_dir: Path,
    ) -> tuple[str, str]:
        """
        Execute `claude --print "<prompt>"` in a subprocess.
        Returns (stdout, stderr). Timeout: 600s.
        """
        self.logger.log_llm_start(prompt[:300])

        cmd = ["claude", "--print", prompt]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(working_dir),
                env={**os.environ, "FORCE_COLOR": "0"},
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""

            if result.returncode != 0 and not stdout.strip():
                _stderr(f"[WARNING] claude exited with code {result.returncode}")
                _stderr(f"[WARNING] stderr: {stderr[:500]}")
                return (
                    f"[CLAUDE ERROR] Exit code {result.returncode}\nSTDERR: {stderr[:2000]}",
                    stderr,
                )

            # Estimate token counts from character counts (rough: 1 token ≈ 4 chars)
            self.logger.log_llm_interaction(
                prompt_tokens=len(prompt) // 4,
                completion_tokens=len(stdout) // 4,
                model="claude-code",
            )
            return stdout, stderr

        except subprocess.TimeoutExpired:
            _stderr("[ERROR] Claude Code timed out after 600s")
            self.logger.log_error("Claude Code timeout", {"timeout_s": 600})
            return "[TIMEOUT] Claude Code execution exceeded 600 seconds.", ""

        except FileNotFoundError:
            msg = (
                "[ERROR] 'claude' binary not found in PATH. "
                "Ensure Claude Code CLI is installed and accessible."
            )
            _stderr(msg)
            self.logger.log_error(msg)
            return msg, ""

        except Exception as exc:  # noqa: BLE001
            msg = f"[ERROR] Unexpected error running Claude Code: {exc}"
            _stderr(msg)
            self.logger.log_error(msg, {"exception": str(exc)})
            return msg, ""

    # ------------------------------------------------------------------
    # Output evaluation
    # ------------------------------------------------------------------

    def _evaluate_findings(
        self,
        raw_output: str,
        findings: list[Finding],
        iteration: int,
    ) -> tuple[float, dict[str, Any]]:
        """
        Score the quality of this iteration's output.
        Returns (quality_score 0.0–1.0, detail_dict).
        """
        tool_log = self._extract_tool_log(raw_output)
        h_score = self.hallucination_detector.score(raw_output, tool_log)
        h_report = self.hallucination_detector.report()

        # Mark individual findings as potential hallucinations
        for finding in findings:
            finding_text = f"{finding.description} {' '.join(finding.tool_evidence)}"
            local_score = self.hallucination_detector.score(
                finding_text, finding.tool_evidence
            )
            if local_score > 0.6 or not finding.tool_evidence:
                finding.is_hallucination = True
                self.logger.log_correction(
                    finding.description,
                    finding.description,
                    f"Marked as potential hallucination (score={local_score:.2f}, "
                    f"tool_evidence={finding.tool_evidence})",
                )

        confirmed_count = sum(1 for f in findings if f.confidence == "confirmed")
        probable_count  = sum(1 for f in findings if f.confidence == "probable")
        hallucinated    = sum(1 for f in findings if f.is_hallucination)
        evidenced       = sum(1 for f in findings if f.tool_evidence and not f.is_hallucination)

        # Base quality scoring
        finding_quality = evidenced / max(len(findings), 1)
        hallucination_penalty = h_score * 0.4
        confidence_bonus = (confirmed_count * 0.1 + probable_count * 0.05) / max(len(findings), 1)
        length_factor = min(1.0, len(raw_output) / 2000)  # reward substantive output

        quality_score = max(
            0.0,
            min(
                1.0,
                (finding_quality * 0.5)
                + (confidence_bonus * 0.2)
                + (length_factor * 0.1)
                - hallucination_penalty
                + (0.2 if findings else 0.0),
            ),
        )

        detail = {
            "total_findings": len(findings),
            "confirmed": confirmed_count,
            "probable": probable_count,
            "hallucinated": hallucinated,
            "evidenced": evidenced,
            "hallucination_score": h_score,
            "hallucination_report": h_report,
            "output_length": len(raw_output),
            "quality_score": quality_score,
        }
        return quality_score, detail

    # ------------------------------------------------------------------
    # Gap detection
    # ------------------------------------------------------------------

    def _detect_gaps(
        self,
        findings: list[Finding],
        raw_output: str,
    ) -> list[str]:
        """Identify what was NOT analysed given the available evidence."""
        completed = GapAnalyzer.infer_completed(raw_output)
        # Also infer from finding tool_evidence
        for f in findings:
            for te in f.tool_evidence:
                completed.extend(GapAnalyzer.infer_completed(te))
        completed = list(set(completed))
        return self.gap_analyzer.find_gaps(self.evidence_types, completed)

    # ------------------------------------------------------------------
    # Finding extraction
    # ------------------------------------------------------------------

    def _extract_findings(self, raw_output: str) -> list[Finding]:
        """
        Attempt to parse structured findings from Claude's output.

        Strategy (in priority order):
        1. Look for a JSON array in the output.
        2. Look for JSON code blocks.
        3. Fall back to heuristic extraction from prose.
        """
        findings: list[Finding] = []

        # Strategy 1: inline JSON array
        findings = self._try_parse_json_array(raw_output)
        if findings:
            return findings

        # Strategy 2: JSON code block
        code_block_re = re.compile(r"```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL | re.I)
        for match in code_block_re.finditer(raw_output):
            findings = self._parse_json_findings(match.group(1))
            if findings:
                return findings

        # Strategy 3: heuristic prose extraction
        findings = self._heuristic_extract(raw_output)
        return findings

    def _try_parse_json_array(self, text: str) -> list[Finding]:
        """Look for the first top-level JSON array in text."""
        start = text.find("[")
        if start == -1:
            return []
        # Walk forward to find balanced closing bracket
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    try:
                        data = json.loads(text[start : i + 1])
                        return self._parse_json_findings(data)
                    except (json.JSONDecodeError, TypeError):
                        return []
        return []

    def _parse_json_findings(self, data: list[dict] | str) -> list[Finding]:
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                return []
        findings: list[Finding] = []
        if not isinstance(data, list):
            return []
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                f = Finding(
                    artifact_type  = str(item.get("artifact_type", "unknown")),
                    description    = str(item.get("description", "")),
                    confidence     = str(item.get("confidence", "unverified")),
                    tool_evidence  = list(item.get("tool_evidence", [])),
                    ioc            = item.get("ioc"),
                    timestamp_utc  = item.get("timestamp_utc"),
                    is_hallucination = bool(item.get("is_hallucination", False)),
                )
                if f.confidence not in CONFIDENCE_LEVELS:
                    f.confidence = "unverified"
                findings.append(f)
            except Exception:  # noqa: BLE001
                continue
        return findings

    def _heuristic_extract(self, text: str) -> list[Finding]:
        """
        Fall-back parser: extract findings from bullet-point / numbered prose.
        Creates 'possible' confidence findings with empty tool_evidence (flagged for correction).
        """
        findings: list[Finding] = []
        # Match lines that look like findings
        finding_re = re.compile(
            r"(?:FINDING[:\s]|Finding[:\s]|•|-|\*|\d+\.)\s*(.{20,300})", re.MULTILINE
        )
        ioc_re = re.compile(
            r"(?:IP[:\s]+|hash[:\s]+|file[:\s]+|domain[:\s]+|username[:\s]+)"
            r"([^\s,;]{5,80})",
            re.I,
        )
        for match in finding_re.finditer(text):
            desc = match.group(1).strip()
            if len(desc) < 20:
                continue
            ioc_match = ioc_re.search(desc)
            findings.append(
                Finding(
                    artifact_type = "unknown",
                    description   = desc,
                    confidence    = "unverified",
                    tool_evidence = [],
                    ioc           = ioc_match.group(1) if ioc_match else None,
                    timestamp_utc = None,
                    is_hallucination = True,  # no tool evidence — flag for review
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Iteration logging
    # ------------------------------------------------------------------

    def _log_iteration_start(self, iteration: int, prompt: str) -> None:
        path = self.analysis_dir / f"prompt_{iteration}.txt"
        path.write_text(prompt, encoding="utf-8")

    def _log_iteration(
        self,
        iteration: int,
        prompt: str,
        raw_output: str,
        findings: list[Finding],
        gaps: list[str],
        quality_score: float,
    ) -> None:
        """Write full iteration record to JSON."""
        record = {
            "iteration": iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt_length": len(prompt),
            "output_length": len(raw_output),
            "quality_score": quality_score,
            "findings_count": len(findings),
            "gaps": gaps,
            "findings": [f.to_dict() for f in findings],
            "raw_output_preview": raw_output[:2000],
        }
        path = self.analysis_dir / f"iteration_{iteration}.json"
        path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        self.all_iterations.append(record)

        # Also write findings to the expected location
        findings_path = self.analysis_dir / f"findings_{iteration}.json"
        if not findings_path.exists():
            findings_path.write_text(
                json.dumps([f.to_dict() for f in findings], indent=2),
                encoding="utf-8",
            )

        for f in findings:
            self.logger.log_finding(f)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tool_log(raw_output: str) -> list[str]:
        """Extract lines that look like shell commands from raw output."""
        lines: list[str] = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if stripped.startswith(("$", "#", ">", ">>")) or re.match(
                r"^(vol|python3|volatility|tshark|ewf|log2timeline|mftecmd|recmd|"
                r"evtx_dump|yara|md5sum|sha256|fls|ils|icat|mmls|fdisk|mount|"
                r"strings|xxd|certutil|bitsadmin|powershell|cmd|net |tasklist)",
                stripped,
                re.I,
            ):
                lines.append(stripped)
        return lines

    def _summarize_findings(self, findings: list[Finding]) -> str:
        if not findings:
            return "No structured findings were extracted from the previous iteration."
        lines = [f"Total findings: {len(findings)}", ""]
        for f in findings:
            badge = "[HALLUCINATION?]" if f.is_hallucination else f"[{f.confidence.upper()}]"
            ioc_note = f" | IOC: {f.ioc}" if f.ioc else ""
            lines.append(f"  {badge} [{f.artifact_type}] {f.description[:120]}{ioc_note}")
        return "\n".join(lines)

    def _summarize_all_iterations(self) -> str:
        if not self.all_iterations:
            return "No iteration records available."
        lines: list[str] = []
        total_findings = len(self.all_findings)
        lines.append(f"Total findings across all iterations: {total_findings}")
        for rec in self.all_iterations:
            lines.append(
                f"\nIteration {rec['iteration']}: "
                f"quality={rec['quality_score']:.2f}, "
                f"findings={rec['findings_count']}, "
                f"gaps={len(rec['gaps'])}"
            )
            for gap in rec["gaps"][:5]:
                lines.append(f"  GAP: {gap}")
        return "\n".join(lines)

    def _build_correction_instructions(self, previous_findings: list[Finding]) -> str:
        unverified = [f for f in previous_findings if f.confidence in ("unverified", "possible")]
        hallucinated = [f for f in previous_findings if f.is_hallucination]
        empty_evidence = [f for f in previous_findings if not f.tool_evidence]

        lines: list[str] = []
        if hallucinated:
            lines.append(f"  - {len(hallucinated)} finding(s) flagged as potential hallucinations — "
                         "confirm with tool runs or remove.")
        if empty_evidence:
            lines.append(f"  - {len(empty_evidence)} finding(s) have NO tool_evidence — "
                         "run appropriate tools or mark 'unverified'.")
        if unverified:
            lines.append(f"  - {len(unverified)} finding(s) at 'unverified'/'possible' confidence — "
                         "attempt to upgrade with deeper analysis.")
        if not lines:
            lines.append("  - No specific corrections required; continue with gap analysis.")
        return "\n".join(lines)

    def _format_heuristics(self) -> str:
        lines: list[str] = []
        for category, items in ANALYST_HEURISTICS.items():
            lines.append(f"\n{category.replace('_', ' ').upper()}:")
            for item in items[:6]:  # cap to keep prompt manageable
                lines.append(f"  - {item}")
        return "\n".join(lines)

    def _generate_final_report(self) -> Path:
        """
        Consolidate all iteration findings and invoke ReportGenerator.
        """
        # Merge and deduplicate findings
        seen_descs: set[str] = set()
        unique_findings: list[Finding] = []
        for f in self.all_findings:
            key = f.description[:80].lower().strip()
            if key not in seen_descs:
                seen_descs.add(key)
                unique_findings.append(f)

        # Write consolidated findings JSON
        consolidated_path = self.analysis_dir / "findings_final.json"
        if not consolidated_path.exists():
            consolidated_path.write_text(
                json.dumps([f.to_dict() for f in unique_findings], indent=2),
                encoding="utf-8",
            )

        case_info = {
            "case_dir": str(self.case_dir),
            "evidence_items": [
                {"type": t, "path": p} for t, p in self.evidence_items
            ],
            "max_iterations": self.max_iterations,
            "completed_iterations": len(self.all_iterations),
            "analysis_dir": str(self.analysis_dir),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Dynamic import to allow report_generator to be optional
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from report_generator import ReportGenerator
            rg = ReportGenerator()
            html = rg.generate(unique_findings, self.all_iterations, case_info)
            report_path = self.output_dir / "report.html"
            report_path.write_text(html, encoding="utf-8")
            return report_path
        except ImportError:
            # Fallback: write a plain-text summary
            report_path = self.output_dir / "report.txt"
            self._write_text_report(report_path, unique_findings, case_info)
            return report_path

    def _write_text_report(
        self,
        path: Path,
        findings: list[Finding],
        case_info: dict[str, Any],
    ) -> None:
        lines = [
            "=" * 72,
            "SIFT AUTONOMOUS DFIR AGENT — FINAL REPORT",
            "=" * 72,
            "",
            f"Case Directory : {case_info['case_dir']}",
            f"Generated      : {case_info['generated_at']}",
            f"Iterations     : {case_info['completed_iterations']}",
            "",
            "EVIDENCE ITEMS:",
        ]
        for ev in case_info["evidence_items"]:
            lines.append(f"  [{ev['type'].upper()}] {ev['path']}")

        confirmed = [f for f in findings if f.confidence == "confirmed"]
        probable  = [f for f in findings if f.confidence == "probable"]
        iocs      = [f for f in findings if f.ioc]

        lines += [
            "",
            "FINDINGS SUMMARY:",
            f"  Total    : {len(findings)}",
            f"  Confirmed: {len(confirmed)}",
            f"  Probable : {len(probable)}",
            "",
            "HIGH-CONFIDENCE FINDINGS:",
        ]
        for f in confirmed + probable:
            lines.append(f"  [{f.confidence.upper()}] [{f.artifact_type}] {f.description}")
            for te in f.tool_evidence:
                lines.append(f"    Evidence: {te}")

        lines += ["", "INDICATORS OF COMPROMISE:"]
        for f in iocs:
            lines.append(f"  [{f.artifact_type}] {f.ioc} — {f.description[:80]}")

        path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_evidence(raw: str) -> tuple[str, str]:
    """Parse 'type:path' evidence argument."""
    parts = raw.split(":", 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            f"Evidence must be in format TYPE:PATH (got '{raw}'). "
            "Valid types: disk, memory, pcap, logs, dir"
        )
    ev_type, path = parts
    ev_type = ev_type.strip().lower()
    valid_types = {"disk", "memory", "pcap", "logs", "dir"}
    if ev_type not in valid_types:
        raise argparse.ArgumentTypeError(
            f"Unknown evidence type '{ev_type}'. Valid types: {', '.join(sorted(valid_types))}"
        )
    return ev_type, path.strip()


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description=(
            "SIFT Autonomous DFIR Agent — self-correcting incident response "
            "orchestrator for the SANS 'Find Evil!' hackathon."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python orchestrator.py \\
                  --case-dir /cases/srl \\
                  --evidence disk:/cases/srl/rd01.E01 \\
                  --output-dir /cases/srl/analysis

              python orchestrator.py \\
                  --case-dir /cases/incident42 \\
                  --evidence disk:/cases/disk.E01 memory:/cases/mem.img pcap:/cases/capture.pcap \\
                  --max-iterations 5 \\
                  --output-dir /cases/incident42/output
        """),
    )
    parser.add_argument(
        "--case-dir",
        required=True,
        type=Path,
        metavar="PATH",
        help="Root directory of the case (must exist)",
    )
    parser.add_argument(
        "--evidence",
        required=True,
        nargs="+",
        type=_parse_evidence,
        metavar="TYPE:PATH",
        help="Evidence items as TYPE:PATH pairs. Valid types: disk, memory, pcap, logs, dir.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        metavar="INT",
        help="Maximum triage iterations (default: 3). Hard cap prevents runaway loops.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        metavar="PATH",
        help="Output directory for reports and analysis artifacts. "
             "Defaults to <case-dir>/analysis.",
    )

    args = parser.parse_args()

    # Validate case dir
    if not args.case_dir.exists():
        _stderr(f"[ERROR] case-dir does not exist: {args.case_dir}")
        sys.exit(1)

    # Default output dir
    output_dir = args.output_dir or (args.case_dir / "analysis")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Enforce iteration cap
    if args.max_iterations < 1:
        _stderr("[ERROR] --max-iterations must be >= 1")
        sys.exit(1)
    if args.max_iterations > 10:
        _stderr("[WARNING] --max-iterations > 10 — capping at 10 to prevent runaway loops")
        args.max_iterations = 10

    orchestrator = TriageOrchestrator(
        case_dir       = args.case_dir,
        evidence_items = args.evidence,
        max_iterations = args.max_iterations,
        output_dir     = output_dir,
    )

    report_path = orchestrator.run()

    # Final report path to stdout (machine-readable)
    print(str(report_path))


if __name__ == "__main__":
    main()
