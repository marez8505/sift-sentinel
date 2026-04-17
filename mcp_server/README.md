# SIFT MCP Server

A production-quality Python [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that wraps SANS SIFT workstation forensic tools as typed, structured functions.

Built for the **"Find Evil!"** SANS hackathon.

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Read-only evidence** | Input paths are validated against `EVIDENCE_DIRS` at the server level — not just in prompts |
| **Safe output only** | Any tool that writes files validates `output_path` starts with `SAFE_OUTPUT_DIRS` |
| **No destructive surface** | `rm`, `dd`, `wget`, `curl`, `ssh` are never exposed |
| **Structured responses** | Every tool returns a consistent dict: `tool`, `cmd`, `stdout_preview`, `stderr_preview`, `returncode`, `duration_s`, `timestamp_utc`, `truncated` |
| **Output size cap** | All stdout truncated to 8,000 characters before returning to the LLM |
| **Explicit subprocess** | All subprocess calls use `shell=False` with explicit argument lists |
| **Timeouts** | Every subprocess call enforces a configurable timeout (default 120 s) |

---

## Security Constraints

```python
EVIDENCE_DIRS  = ["/cases/", "/mnt/", "/media/", "/evidence/"]
SAFE_OUTPUT_DIRS = ["./analysis/", "./exports/", "./reports/"]
```

- Evidence paths are validated with `os.path.abspath()` to prevent directory traversal.
- Attempting to pass a path outside these directories raises `ValueError` immediately — the subprocess is never spawned.

---

## Tools (23 total)

### Disk Image Tools
| Tool | Wraps | Description |
|------|-------|-------------|
| `get_image_info` | `file`, `ewfinfo` | Image format and EWF metadata |
| `list_partitions` | `mmls` | Partition table with parsed offsets |
| `list_files` | `fls` | Recursive file listing with optional path filter (max 200 lines) |
| `extract_file` | `icat` | Extract file by inode to safe output path |
| `get_file_info` | `istat` | Inode metadata: timestamps, size, blocks |

### Memory Analysis (Volatility3)
| Tool | Plugin(s) | Description |
|------|-----------|-------------|
| `analyze_memory_processes` | `windows.pslist` + `windows.psscan` | Diff both lists; surfaces hidden processes |
| `analyze_memory_network` | `windows.netscan` + `windows.netstat` | Deduplicated remote IPs + connection table (max 100 rows) |
| `analyze_memory_cmdlines` | `windows.cmdline` | Per-PID command line dict |
| `analyze_memory_malfind` | `windows.malfind` | Suspicious memory regions; optional region dump |
| `analyze_memory_services` | `windows.svcscan` | Service list; flags non-System32/ProgramFiles binaries |

### Eric Zimmerman Tools
| Tool | Wraps | Description |
|------|-------|-------------|
| `parse_mft` | `MFTECmd.dll` | MFT summary + top 20 recently modified entries |
| `parse_event_logs` | `EvtxECmd.dll` | Event counts by ID + top 50 security-relevant events |
| `parse_registry` | `RECmd.dll` + Kroll_Batch.reb | Full batch or targeted key query |
| `parse_amcache` | `AmcacheParser.dll` | Executed programs with SHA1 hashes |
| `parse_shimcache` | `AppCompatCacheParser.dll` | Shimcache entries sorted by last modified |
| `parse_prefetch` | `PECmd.dll` | Prefetch execution table with run counts |

### Timeline
| Tool | Wraps | Description |
|------|-------|-------------|
| `generate_timeline` | `log2timeline.py` + `psort.py` | Super-timeline with event count and date range |

### Other Forensic Tools
| Tool | Wraps | Description |
|------|-------|-------------|
| `run_yara_scan` | `yara` | YARA rule scan; returns match list |
| `hash_file` | `sha256sum` / `sha1sum` / `md5sum` | Hash + file size |
| `run_bulk_extractor` | `bulk_extractor` | Feature extraction (email, url, domain, credit_card, telephone) |
| `get_strings` | `strings` | ASCII + Unicode strings with IOC pattern extraction |
| `parse_network_capture` | `tshark` | Top talkers + protocol distribution |
| `baseline_memory` | `memory-baseliner` | Diff memory image against known-good baseline |

---

## Tool Binary Paths

| Tool | Path |
|------|------|
| Volatility3 | `python3 /opt/volatility3-2.20.0/vol.py` |
| MFTECmd | `dotnet /opt/zimmermantools/MFTECmd.dll` |
| EvtxECmd | `dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll` |
| RECmd | `dotnet /opt/zimmermantools/RECmd/RECmd.dll` |
| AmcacheParser | `dotnet /opt/zimmermantools/AmcacheParser.dll` |
| AppCompatCacheParser | `dotnet /opt/zimmermantools/AppCompatCacheParser.dll` |
| PECmd | `dotnet /opt/zimmermantools/PECmd.dll` |
| YARA | `/usr/local/bin/yara` |
| bulk_extractor | `bulk_extractor` (system PATH) |
| tshark | `tshark` (system PATH) |
| Memory Baseliner | `python3 /opt/memory-baseliner/baseline.py` |

---

## Installation

```bash
pip install -r requirements.txt
```

**Requirements:**
- `mcp[cli] >= 1.0.0`
- `typing-extensions >= 4.0.0`

---

## Running the Server

```bash
python server.py
```

The server uses **stdio transport** — connect your MCP client (e.g., Claude Desktop, any MCP-compatible agent) via stdin/stdout.

### MCP Client Config (Claude Desktop example)

```json
{
  "mcpServers": {
    "sift": {
      "command": "python",
      "args": ["/path/to/mcp_server/server.py"]
    }
  }
}
```

---

## Response Schema

Every tool returns a dict matching this schema:

```json
{
  "tool": "tool_name",
  "cmd": "exact command string executed",
  "stdout_preview": "first 8000 chars of stdout",
  "stderr_preview": "first 2000 chars of stderr",
  "returncode": 0,
  "duration_s": 1.234,
  "timestamp_utc": "2024-01-01T12:00:00+00:00",
  "truncated": false,
  "...tool_specific_fields": "..."
}
```

---

## File Structure

```
mcp_server/
├── server.py          # MCP server — all 23 tool functions (~1450 lines)
├── __init__.py        # Package marker
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## Example Usage

```python
# List partitions in a disk image
list_partitions("/cases/suspect_drive.E01")

# Analyze running processes in a memory dump
analyze_memory_processes("/evidence/mem.raw")

# Scan exported files with YARA rules
run_yara_scan(
    rules_path="/opt/yara-rules/malware.yar",
    target_path="./exports/extracted_binaries/"
)

# Parse Windows Event Logs for lateral movement indicators
parse_event_logs(
    evtx_dir="/cases/evtx/",
    event_ids=[4624, 4648, 4688],
    start_date="2024-01-01",
    end_date="2024-01-31"
)
```
