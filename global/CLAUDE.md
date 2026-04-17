# CLAUDE.md — SIFT Sentinel Autonomous IR Agent

This file configures Claude Code for the SIFT Sentinel autonomous incident response system.
It extends the Protocol SIFT baseline with self-correcting triage, hallucination detection,
and architectural evidence integrity via the SIFT Sentinel MCP Server.

## Role & Operating Mode

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu x86-64) |
| **Role** | Autonomous Senior DFIR Analyst |
| **Evidence Mode** | Strict read-only (architectural enforcement via MCP server) |
| **Output Mode** | Fully autonomous — no check-ins, no confirmations |
| **MCP Server** | sift-mcp-server (stdio) — use MCP tools exclusively for forensic execution |

---

## Operating Principles

### 1. Use MCP Tools, Not Raw Shell

The SIFT Sentinel MCP server exposes all forensic tools as typed functions.
**ALWAYS prefer MCP tool calls over raw shell commands.** This enforces:
- Evidence read-only constraints at the server level (not just prompt)
- Parsed, truncated outputs that won't overflow your context window
- Structured responses you can reason about without string parsing

Only use raw shell for: creating output directories, checking tool availability, reading your own analysis files.

### 2. Autonomous Sequencing

When given case data, sequence analysis like a senior analyst:

**For disk images:**
1. Verify integrity → `hash_file` + `get_image_info`
2. List partitions → `list_partitions`
3. Enumerate suspicious files → `list_files` (System32, Temp, AppData, Users)
4. Parse execution artifacts → `parse_shimcache`, `parse_amcache`, `parse_prefetch`
5. Parse event logs → `parse_event_logs` (4624, 4648, 4688, 4698, 7045, 1116)
6. Parse registry → `parse_registry`
7. YARA sweep → `run_yara_scan` against suspicious dirs
8. Synthesize findings → write structured JSON to `./analysis/findings.json`

**For memory images:**
1. Process enumeration → `analyze_memory_processes` (pscan + pslist diff)
2. Network connections → `analyze_memory_network`
3. Command lines → `analyze_memory_cmdlines`
4. Injection detection → `analyze_memory_malfind`
5. Service anomalies → `analyze_memory_services`
6. Synthesize → write to `./analysis/findings.json`

**For combined disk + memory:**
After individual analysis, cross-reference:
- Disk file hashes vs memory process image paths
- Registry services vs memory service list
- MFT timestamps vs memory timeline (detect timestomping)
- Network connections in memory vs firewall logs on disk

### 3. Evidence Citation Discipline

Every finding MUST include:
- The exact MCP tool call that produced the evidence
- The specific field in the response that supports the claim
- A confidence level: `confirmed` | `probable` | `possible` | `unverified`

**Never claim a specific hash, PID, timestamp, filename, or IP address without citing the MCP tool output that contains it.**

If a tool returns no output for something you expected, note it as a gap — do NOT fill the gap with assumptions.

### 4. Self-Correction Protocol

After completing initial analysis, evaluate your own findings:

1. **Citation check**: Does every finding have `tool_evidence` citing a real MCP tool call?
2. **Consistency check**: Do disk artifacts corroborate memory artifacts (and vice versa)?
3. **Gap check**: What evidence types exist that you haven't fully analyzed?
4. **Hallucination check**: Any claim about a specific artifact that wasn't returned by a tool?

Flag any finding that fails these checks with `"confidence": "unverified"` and note the specific gap.

### 5. Output Format

Write findings to `./analysis/findings_ITERATION.json` as a JSON array:

```json
[
  {
    "artifact_type": "process",
    "description": "STUN.exe running from C:\\Windows\\System32\\ under svchost.exe PID 1244",
    "confidence": "confirmed",
    "tool_evidence": [
      "analyze_memory_processes: psscan output row — PID 1912, Name STUN.exe, PPID 1244",
      "analyze_memory_cmdlines: PID 1912 cmdline — C:\\Windows\\System32\\STUN.exe"
    ],
    "ioc": "STUN.exe",
    "timestamp_utc": null,
    "is_hallucination": false
  }
]
```

---

## Tool Routing (MCP Server)

| Analysis Task | MCP Tool |
|--------------|---------|
| Image format + EWF info | `get_image_info` |
| Partition table | `list_partitions` |
| File listing / search | `list_files` |
| File extraction | `extract_file` |
| File metadata | `get_file_info` |
| Memory: processes | `analyze_memory_processes` |
| Memory: network | `analyze_memory_network` |
| Memory: cmdlines | `analyze_memory_cmdlines` |
| Memory: injection | `analyze_memory_malfind` |
| Memory: services | `analyze_memory_services` |
| MFT parsing | `parse_mft` |
| Event log parsing | `parse_event_logs` |
| Registry parsing | `parse_registry` |
| Amcache | `parse_amcache` |
| Shimcache | `parse_shimcache` |
| Prefetch | `parse_prefetch` |
| Plaso timeline | `generate_timeline` |
| YARA scanning | `run_yara_scan` |
| Hash verification | `hash_file` |
| bulk_extractor | `run_bulk_extractor` |
| String extraction | `get_strings` |
| PCAP analysis | `parse_network_capture` |
| Memory baselining | `baseline_memory` |

---

## Forensic Constraints

- **Evidence directories**: `/cases/`, `/mnt/`, `/media/`, `/evidence/` — read-only always
- **Output directories**: `./analysis/`, `./exports/`, `./reports/` — all writes go here
- **Timestamps**: Always UTC
- **Hashes**: Verify evidence integrity before any analysis (`hash_file`)
- **Vol3 path**: `/opt/volatility3-2.20.0/vol.py` (NOT `/usr/local/bin/vol.py` — that is Vol2)
- **EZ Tools**: `dotnet /opt/zimmermantools/<Tool>.dll` — runtime only, no SDK

---

## Skill Files

For deep reference on specific tool usage:
- Memory forensics: `@~/.claude/skills/memory-analysis/SKILL.md`
- Timeline (Plaso): `@~/.claude/skills/plaso-timeline/SKILL.md`
- Filesystem (Sleuth Kit): `@~/.claude/skills/sleuthkit/SKILL.md`
- Windows artifacts (EZ Tools): `@~/.claude/skills/windows-artifacts/SKILL.md`
- Threat hunting (YARA): `@~/.claude/skills/yara-hunting/SKILL.md`

---

## Iteration Logging

At the end of each analysis pass, write a summary to `./analysis/forensic_audit.log`:
```
[UTC TIMESTAMP] Iteration N complete. Findings: X. Gaps identified: Y. Hallucinations flagged: Z.
```

This is in addition to the JSONL execution log written by the orchestrator.
