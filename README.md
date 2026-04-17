# SIFT Sentinel — Autonomous Incident Response Agent

**SANS Find Evil! Hackathon Submission** | April–June 2026 | [findevil.devpost.com](https://findevil.devpost.com)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/Protocol-MCP-green.svg)](https://modelcontextprotocol.io)

---

## What This Is

SIFT Sentinel makes Protocol SIFT fully autonomous by combining two components:

1. **A Custom MCP Server** — Wraps the SIFT Workstation's 200+ forensic tools as typed, structured functions. The agent physically cannot run `rm`, `dd`, `wget`, `curl`, or `ssh` because the server simply doesn't expose them. All outputs are parsed and truncated before returning to the LLM, preventing context window overload.

2. **A Self-Correcting Triage Orchestrator** — Drives Claude Code through an autonomous DFIR analysis loop with hallucination detection, gap analysis, and iterative self-correction — all with a hard `--max-iterations` cap to prevent runaway loops.

> **Architectural approach**: Custom MCP Server + Self-Correcting Agent Loop  
> **Evidence integrity**: Enforced architecturally (no destructive tools in MCP server) + OS-level (read-only mounts)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SIFT Sentinel                                │
│                                                                       │
│  ┌─────────────────┐   stdio/MCP   ┌──────────────────────────────┐ │
│  │  Claude Code    │ ◄──────────── │   SIFT Sentinel MCP Server    │ │
│  │  (AI backbone)  │               │   mcp_server/server.py        │ │
│  └────────┬────────┘               │                               │ │
│           │                        │  23 typed forensic functions  │ │
│  ┌────────▼────────┐               │  Path validation              │ │
│  │  Orchestrator   │               │  Output parsing + truncation  │ │
│  │  orchestrator.py│               └──────────┬───────────────────┘ │
│  │                 │                          │ read-only subprocess │
│  │  • HalluciDet   │               ┌──────────▼───────────────────┐ │
│  │  • GapAnalyzer  │               │   SIFT Tool Suite             │ │
│  │  • ExecLogger   │               │   Vol3 / EZ Tools / TSK       │ │
│  └─────────────────┘               │   Plaso / YARA / bulk_extractor│ │
│                                    └──────────┬───────────────────┘ │
│  ╔══════════════════╗                         │                      │
│  ║ ARCHITECTURAL    ║              ┌──────────▼───────────────────┐ │
│  ║ BOUNDARY:        ║              │  Evidence (READ-ONLY)         │ │
│  ║ No rm/dd/wget/   ║              │  /cases/ /mnt/ /media/        │ │
│  ║ curl/ssh in MCP  ║              └───────────────────────────────┘ │
│  ╚══════════════════╝                                                 │
│  ╔══════════════════╗              ┌───────────────────────────────┐ │
│  ║ OS BOUNDARY:     ║              │  Analysis Output (WRITE)      │ │
│  ║ -o ro,noatime    ║              │  ./analysis/ ./exports/        │ │
│  ║ mounts           ║              │  ./reports/                   │ │
│  ╚══════════════════╝              └───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

**Security boundaries** (full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

| Guardrail | Type | Mechanism |
|-----------|------|-----------|
| No destructive commands | **Architectural** | MCP server does not expose rm, dd, wget, curl, ssh |
| Evidence read-only | **Architectural** | Path validator rejects writes to /cases/, /mnt/, /media/ |
| Evidence read-only | **OS-level** | `mount -o ro,noatime` for all evidence mounts |
| Output path scoping | **Architectural** | Output validator accepts only ./analysis/, ./exports/, ./reports/ |
| Context window protection | **Architectural** | All tool outputs truncated to 8,000 chars before LLM sees them |
| Iteration cap | **Architectural** | Hard `--max-iterations` flag; orchestrator exits on cap |

---

## Installation

### Prerequisites

- [SANS SIFT Workstation OVA](https://www.sans.org/tools/sift-workstation/) (Ubuntu x86-64)
- [Claude Code CLI](https://claude.ai/code): `npm install -g @anthropic-ai/claude-code`
- Anthropic API key
- Python 3.10+

### Install

```bash
# 1. Clone this repo inside the SIFT VM
git clone https://github.com/marez8505/sift-sentinel.git
cd sift-sentinel

# 2. Install (also installs Protocol SIFT baseline skills if protocol-sift is alongside)
bash install.sh

# 3. Set API key on first Claude Code run
claude   # follow the interactive setup
```

### Optional: Install Protocol SIFT alongside

```bash
# Install Protocol SIFT baseline first (recommended)
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# Then install SIFT Sentinel on top
bash install.sh
```

---

## Usage

### Autonomous Triage (Recommended)

```bash
# Disk image only
python3 ~/.claude/agent/orchestrator.py \
    --case-dir /cases/srl \
    --evidence disk:/cases/srl/base-rd01-cdrive.E01 \
    --max-iterations 3

# Disk + Memory (enables cross-source correlation)
python3 ~/.claude/agent/orchestrator.py \
    --case-dir /cases/srl \
    --evidence disk:/cases/srl/base-rd01-cdrive.E01 \
                memory:/cases/memory/rd01-memory.img \
    --max-iterations 3

# PCAP + Logs
python3 ~/.claude/agent/orchestrator.py \
    --case-dir /cases/incident \
    --evidence pcap:/cases/incident/capture.pcap logs:/cases/incident/auth.log \
    --max-iterations 2
```

**What it does:**
1. **Iteration 1** — Full initial triage per evidence type using senior analyst playbooks
2. **Iteration 2** — Gap analysis: identifies unchecked artifacts and re-analyzes
3. **Iteration 3** — Synthesis: cross-references all findings, flags hallucinations, generates final report

Output files:
```
./analysis/
├── findings_1.json          # Iteration 1 structured findings
├── findings_2.json          # Iteration 2 gap-fill findings
├── findings_final.json      # Synthesized, deduplicated final findings
├── execution_log.jsonl      # Full JSONL audit trail (timestamps, tool calls, token usage)
└── forensic_audit.log       # Human-readable session log
./reports/
└── final_report.html        # Full HTML report with evidence chain
```

### Interactive (Claude Code)

```bash
# Copy and customize the case template
cp ~/.claude/case-templates/CLAUDE.md /cases/mycase/CLAUDE.md
# Edit /cases/mycase/CLAUDE.md with your case details

# Start Claude Code — it reads CLAUDE.md automatically
cd /cases/mycase
claude
```

Claude Code will have access to all 23 MCP tools via the SIFT Sentinel MCP server.

### MCP Server Standalone

```bash
# Start the MCP server directly (for use with any MCP-compatible client)
python3 ~/.claude/mcp_server/server.py   # stdio transport
```

---

## MCP Tool Reference

| Tool | Description |
|------|-------------|
| `get_image_info` | Disk image format + EWF metadata |
| `list_partitions` | Partition table with offsets |
| `list_files` | Filesystem enumeration (fls) |
| `extract_file` | File extraction by inode (icat) |
| `get_file_info` | File metadata (istat) |
| `analyze_memory_processes` | psscan + pslist diff → hidden process detection |
| `analyze_memory_network` | netscan + netstat → unique external IPs |
| `analyze_memory_cmdlines` | All process command lines (PID-keyed dict) |
| `analyze_memory_malfind` | Code injection detection (RWX region scan) |
| `analyze_memory_services` | Service anomaly detection |
| `parse_mft` | MFT parsing with recent file summary |
| `parse_event_logs` | EVTX parsing with date/EventID filters |
| `parse_registry` | Registry batch or targeted key query |
| `parse_amcache` | Execution evidence with SHA1 hashes |
| `parse_shimcache` | File presence/execution evidence |
| `parse_prefetch` | Execution timestamps (last 8 runs) |
| `generate_timeline` | Plaso super-timeline |
| `run_yara_scan` | YARA rule sweep |
| `hash_file` | Evidence integrity (MD5/SHA1/SHA256) |
| `run_bulk_extractor` | Feature extraction (URLs, email, domains) |
| `get_strings` | String extraction with IOC pattern matching |
| `parse_network_capture` | PCAP analysis (tshark) |
| `baseline_memory` | Memory baseliner diff against known-good JSON |

---

## Submission Documents

| Document | Path |
|----------|------|
| Project Description | [docs/PROJECT_DESCRIPTION.md](docs/PROJECT_DESCRIPTION.md) |
| Architecture Diagram | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Accuracy Report | [docs/ACCURACY_REPORT.md](docs/ACCURACY_REPORT.md) |
| Dataset Documentation | [docs/DATASET_DOCUMENTATION.md](docs/DATASET_DOCUMENTATION.md) |
| Try-It-Out Instructions | [docs/TRY_IT_OUT.md](docs/TRY_IT_OUT.md) |

---

## Running Tests

```bash
cd sift-sentinel
python3 -m pytest tests/ -v

# Security tests only
python3 -m pytest tests/test_mcp_security.py -v
```

---

## License

MIT License — see [LICENSE](LICENSE) file.

---

## Author

Edward Marez — [@marez8505](https://github.com/marez8505)  
Cybersecurity student, Austin Community College BAS program  
Aspiring digital forensics analyst

*Built for the SANS Find Evil! Hackathon 2026*
