# SIFT Sentinel — Try It Out

**For judges evaluating the SANS "Find Evil!" hackathon submission**

This document provides step-by-step instructions to run SIFT Sentinel on the SANS FOR508 SRL case data (or the NIST CFReDS public dataset if FOR508 data is unavailable). Expected run time: approximately 25–40 minutes for a full 3-iteration run on the SRL dataset.

---

## 1. Prerequisites

### 1.1 Required Software

| Component | Version | Download |
|---|---|---|
| SIFT Workstation OVA | 3.0+ | [sans.org/tools/sift-workstation](https://www.sans.org/tools/sift-workstation/) |
| VMware Workstation Pro / Fusion | Any recent | vmware.com |
| VirtualBox (alternative to VMware) | 7.0+ | virtualbox.org |
| Protocol SIFT | Latest (main branch) | Installed via curl (see below) |
| Claude Code CLI | Latest | Installed via npm (see below) |
| Python | 3.10+ | Pre-installed in SIFT |

### 1.2 Required Credentials

- **Anthropic API key** with access to Claude 3.5 Sonnet or later. Set as environment variable `ANTHROPIC_API_KEY`. The agent makes multiple API calls per iteration; expect approximately $0.40–$1.20 in API costs for a 3-iteration run against the SRL dataset.

### 1.3 Hardware Minimums

| Resource | Minimum | Recommended |
|---|---|---|
| RAM allocated to VM | 8 GB | 16 GB |
| Disk space (evidence + outputs) | 60 GB free | 100 GB free |
| CPU cores | 4 | 8 |

---

## 2. Installation

### Step 1: Set up SIFT Workstation

Import the SIFT OVA into VMware or VirtualBox. Boot the VM. Default credentials: `sansforensics` / `forensics`.

### Step 2: Install Protocol SIFT

```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
source ~/.bashrc
```

Verify installation:
```bash
protocol-sift --version
```

### Step 3: Install Claude Code CLI

```bash
npm install -g @anthropic-ai/claude-code
claude --version
```

### Step 4: Clone SIFT Sentinel

```bash
git clone https://github.com/marez8505/sift-sentinel.git
cd sift-sentinel
```

### Step 5: Run the install script

```bash
bash install.sh
```

`install.sh` performs the following actions:
1. Installs Python dependencies (`pip install -r requirements.txt`)
2. Writes the MCP server configuration to `sift_mcp.json`
3. Creates output directories (`./analysis/`, `./reports/`, `./exports/`)
4. Downloads Volatility 3 symbol tables for Windows 10 22H2 and Windows Server 2019
5. Runs a dry-run self-test that verifies all SIFT tools are accessible

Expected output from `install.sh`:
```
[OK] Python dependencies installed
[OK] MCP server configuration written to sift_mcp.json
[OK] Output directories created
[OK] Vol3 symbols: windows.10.0.19045 downloaded
[OK] Vol3 symbols: windows.10.0.17763 downloaded
[OK] Self-test passed: 35/35 MCP functions registered
[OK] SIFT Sentinel ready
```

### Step 6: Set API key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Add to `~/.bashrc` to persist across sessions:
```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc
```

---

## 3. Preparing Evidence

### 3.1 Copy evidence files to the case directory

```bash
sudo mkdir -p /cases/srl/disk /cases/srl/memory
# Copy your FOR508 SRL evidence files:
cp /path/to/base-dc-cdrive.E01 /cases/srl/disk/
cp /path/to/base-rd01-cdrive.E01 /cases/srl/disk/
cp /path/to/rd01-memory.img /cases/srl/memory/
cp /path/to/base-dc_memory.img /cases/srl/memory/
```

### 3.2 Mount evidence read-only (required for evidence integrity)

```bash
sudo ewfmount /cases/srl/disk/base-rd01-cdrive.E01 /mnt/rd01_disk
sudo mount -o ro,noatime /mnt/rd01_disk/ewf1 /mnt/rd01_cdrive

sudo ewfmount /cases/srl/disk/base-dc-cdrive.E01 /mnt/dc_disk
sudo mount -o ro,noatime /mnt/dc_disk/ewf1 /mnt/dc_cdrive
```

Verify mounts are read-only:
```bash
mount | grep ro
# Should show /mnt/rd01_cdrive and /mnt/dc_cdrive with (ro,...) flags
```

### 3.3 Verify evidence integrity hashes (optional but recommended)

```bash
python3 tools/verify_hashes.py /cases/srl/
# Computes and logs SHA-256 hashes for all evidence files
# These are recorded in execution_log.jsonl for the audit trail
```

---

## 4. Running the Agent

### Full SRL case run (recommended for evaluation):

```bash
python3 agent/orchestrator.py \
  --case-dir /cases/srl \
  --evidence disk:/cases/srl/disk/base-rd01-cdrive.E01 \
             disk:/cases/srl/disk/base-dc-cdrive.E01 \
             memory:/cases/srl/memory/rd01-memory.img \
             memory:/cases/srl/memory/base-dc_memory.img \
  --max-iterations 3 \
  --output-dir ./analysis/srl_run_$(date +%Y%m%d_%H%M%S)
```

### Memory-only run (faster, ~10 minutes):

```bash
python3 agent/orchestrator.py \
  --case-dir /cases/srl \
  --evidence memory:/cases/srl/memory/rd01-memory.img \
  --max-iterations 2 \
  --output-dir ./analysis/srl_memory_only
```

### Using the MCP server standalone with Claude Code (interactive mode):

```bash
claude --mcp-config sift_mcp.json
# At the Claude prompt:
# > Analyze the memory image at /cases/srl/memory/rd01-memory.img for signs of compromise
```

---

## 5. What to Expect

### 5.1 Runtime estimates

| Evidence scope | Iterations | Estimated time |
|---|---|---|
| RD01 memory only | 2 | 10–15 minutes |
| RD01 disk only | 2 | 15–20 minutes |
| RD01 disk + memory | 3 | 25–35 minutes |
| Full SRL (both systems, disk + memory) | 3 | 40–60 minutes |

Most time is spent in SIFT tool execution (Vol3, Plaso log2timeline), not in API calls.

### 5.2 Console output during run

You will see output like:
```
[2026-05-12 14:19:22] Iteration 1/3 starting
[2026-05-12 14:19:22] Tool call: vol3_pslist (rd01-memory.img)
[2026-05-12 14:19:30] Tool call: vol3_pstree (rd01-memory.img)
[2026-05-12 14:20:01] Tool call: vol3_malfind (rd01-memory.img)
...
[2026-05-12 14:31:44] Hallucination check: 4 claims flagged as [UNVERIFIED]
[2026-05-12 14:31:45] Gap analysis: coverage 47% — below threshold (60%)
[2026-05-12 14:31:45] Iteration 2/3 starting — gap mandate: prefetch, shellbags, svcscan
...
[2026-05-12 14:48:12] Iteration 3/3 starting — gap mandate: refine unverified claims
...
[2026-05-12 14:55:33] Run complete. Writing findings.
[2026-05-12 14:55:34] Report: ./analysis/srl_run_20260512_141922/report.html
```

---

## 6. Reviewing Results

### 6.1 Output directory structure

After a completed run, the output directory contains:

```
./analysis/srl_run_20260512_141922/
├── execution_log.jsonl          # Full JSONL audit log (every tool call, timestamp, tokens)
├── findings.json                # Structured findings with evidence chains
├── report.html                  # Human-readable HTML report
├── iteration_1_analysis.txt     # Raw LLM output for iteration 1
├── iteration_2_analysis.txt     # Raw LLM output for iteration 2
├── iteration_3_analysis.txt     # Raw LLM output for iteration 3
└── hashes.txt                   # SHA-256 hashes of evidence files at run start
```

### 6.2 Reading the HTML report

Open `report.html` in a browser inside the SIFT VM:
```bash
firefox ./analysis/srl_run_*/report.html &
```

The report is organized as:
- **Executive Summary** — Top IOCs, overall confidence, coverage score
- **Memory Findings** — Per-process analysis, injection indicators, network connections
- **Disk Findings** — Timeline anomalies, persistence mechanisms, lateral movement artifacts
- **Unverified Claims** — Claims flagged `[UNVERIFIED]` by hallucination checker
- **Evidence Chain Appendix** — Every finding linked to exact tool call + timestamp

### 6.3 Reading the execution log

The JSONL log is the primary audit artifact. Each line is one tool call:
```bash
# View all tool calls in order
cat execution_log.jsonl | python3 -m json.tool | less

# Count tool calls per iteration
cat execution_log.jsonl | python3 -c "
import sys, json
from collections import Counter
calls = [json.loads(l) for l in sys.stdin]
c = Counter(r['iteration'] for r in calls if 'tool_name' in r)
print(c)
"

# Find the hallucination check results
grep '"turn_type":"hallucination_check"' execution_log.jsonl | python3 -m json.tool
```

### 6.4 Reading findings.json

```bash
# Show all high-confidence findings
python3 -c "
import json
with open('findings.json') as f:
    findings = json.load(f)
for f in findings['confirmed']:
    print(f['title'], '-', f['confidence'])
"
```

---

## 7. Troubleshooting

### "Vol3: Symbol file not found"

Volatility cannot find the ISF profile for the target OS. Resolution:
```bash
python3 tools/download_symbols.py --auto-detect /cases/srl/memory/rd01-memory.img
# Detects OS version and downloads appropriate symbol table
```

### "MCP server not found / connection refused"

The MCP server is started automatically by the orchestrator. If it fails:
```bash
# Test MCP server standalone
python3 sift_mcp_server.py --test
# Should output: "SIFT MCP Server self-test: 35/35 functions OK"
```

If tools are missing:
```bash
which vol3 volatility3 fls mmls istat
# All should return paths within /usr/local/bin or /opt/
```

If any are missing, re-run the SIFT Workstation setup:
```bash
sudo apt-get install -y volatility3 sleuthkit ewf-tools
```

### "ANTHROPIC_API_KEY not set"

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# Or add to ~/.bashrc and source it:
source ~/.bashrc
```

### "ewfmount: command not found"

```bash
sudo apt-get install -y libewf-dev ewf-tools
```

### Agent exits after iteration 1 with status: MAX_ITERATIONS_REACHED

This happens if `--max-iterations 1` was set or the default was overridden. Use `--max-iterations 3` for the full evaluation run.

### HTML report not generating

```bash
# Generate report manually from findings.json
python3 tools/generate_report.py ./analysis/srl_run_*/findings.json
```

### High API cost warning

If a single run is consuming more than $2.00 in API costs, the MCP output parser may not be truncating tool outputs correctly. Check:
```bash
# Review token usage per turn
cat execution_log.jsonl | python3 -c "
import sys, json
calls = [json.loads(l) for l in sys.stdin if 'tokens_in' in l]
calls = [json.loads(l) for l in open('execution_log.jsonl') if l.strip()]
for c in [x for x in calls if x.get('tokens_in', 0) > 5000]:
    print(c.get('tool_name'), c.get('tokens_in'))
"
```

Tool calls with >5,000 input tokens indicate the output parser is not truncating. File a bug at [github.com/marez8505/sift-sentinel/issues](https://github.com/marez8505/sift-sentinel/issues).

---

## 8. MCP Server Standalone Usage with Claude Code

For interactive forensic analysis (not automated triage), use the MCP server directly with Claude Code:

```bash
# Start interactive session with MCP server connected
claude --mcp-config sift_mcp.json

# Example prompts:
# > List all running processes from the memory image at /cases/srl/memory/rd01-memory.img
# > Show me suspicious malfind results, excluding JIT/CLR false positives
# > What network connections were active at the time of memory capture?
# > Search for YARA signatures matching common RAT families in the RD01 memory
```

The MCP server enforces the same guardrails in interactive mode — no destructive functions, read-only evidence access, parsed output.

To see all available MCP functions:
```bash
python3 sift_mcp_server.py --list-tools
```
