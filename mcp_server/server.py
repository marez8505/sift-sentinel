"""
SIFT Workstation MCP Server
============================
Wraps SANS SIFT forensic tools as typed, structured MCP tool functions.

Security principles:
  - Read-only evidence enforcement: input paths must be under EVIDENCE_DIRS
  - Safe output enforcement: any written output must be under SAFE_OUTPUT_DIRS
  - No destructive commands exposed (no rm, dd, wget, curl, ssh, etc.)
  - All subprocess calls use shell=False with explicit argument lists
  - All outputs parsed/truncated to MAX_OUTPUT_CHARS before returning
  - Timeout enforced on every subprocess call

Run:
    python server.py   (stdio transport, connect via MCP client)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Server instantiation
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="sift-mcp-server",
    instructions="MCP server wrapping SANS SIFT forensic tools with structured, parsed outputs. "
                 "All inputs are validated against allowed evidence directories. "
                 "All outputs are parsed and truncated to prevent context window overload.",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_OUTPUT_CHARS: int = 8_000
DEFAULT_TIMEOUT: int = 120

EVIDENCE_DIRS: list[str] = ["/cases/", "/mnt/", "/media/", "/evidence/"]
SAFE_OUTPUT_DIRS: list[str] = ["./analysis/", "./exports/", "./reports/"]

# Tool binary paths
VOL3: str = "python3 /opt/volatility3-2.20.0/vol.py"
MFTECMD: str = "dotnet /opt/zimmermantools/MFTECmd.dll"
EVTXECMD: str = "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"
RECMD: str = "dotnet /opt/zimmermantools/RECmd/RECmd.dll"
RECMD_BATCH: str = "/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"
AMCACHEPARSER: str = "dotnet /opt/zimmermantools/AmcacheParser.dll"
APPCOMPATPARSER: str = "dotnet /opt/zimmermantools/AppCompatCacheParser.dll"
PECMD: str = "dotnet /opt/zimmermantools/PECmd.dll"
YARA_BIN: str = "/usr/local/bin/yara"
BULK_EXTRACTOR: str = "bulk_extractor"
TSHARK: str = "tshark"
MEMORY_BASELINER: str = "python3 /opt/memory-baseliner/baseline.py"

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _is_evidence_path(path: str) -> bool:
    """Return True if path starts with one of the allowed evidence directories.

    Checks both the raw path string (for Linux absolute paths like /cases/)
    and the OS-resolved abspath (for relative paths and symlinks). The raw
    string check is necessary because on Windows os.path.abspath('/cases/x')
    resolves to 'C:\\cases\\x', which would otherwise fail the prefix test
    even though the intent is correct for SIFT (Linux) deployment.
    """
    # Normalize separators for cross-platform comparison
    norm_path = path.replace("\\", "/")
    abs_path = os.path.abspath(path).replace("\\", "/")
    for d in EVIDENCE_DIRS:
        prefix = d.rstrip("/")
        if norm_path.startswith(prefix) or abs_path.startswith(prefix):
            return True
    return False


def _is_safe_output_path(path: str) -> bool:
    """Return True if path starts with one of the allowed safe output directories."""
    norm = os.path.normpath(path)
    for d in SAFE_OUTPUT_DIRS:
        if norm.startswith(os.path.normpath(d)):
            return True
    return False


def _validate_evidence(path: str) -> None:
    """Raise ValueError if path is not in an allowed evidence directory."""
    if not _is_evidence_path(path):
        raise ValueError(
            f"Path '{path}' is not inside an allowed evidence directory "
            f"({', '.join(EVIDENCE_DIRS)}). Access denied."
        )


def _validate_output(path: str) -> None:
    """Raise ValueError if output path is not in a safe output directory."""
    if not _is_safe_output_path(path):
        raise ValueError(
            f"Output path '{path}' is not inside a safe output directory "
            f"({', '.join(SAFE_OUTPUT_DIRS)}). Write denied."
        )


def _path_exists(path: str) -> None:
    """Raise FileNotFoundError if path does not exist."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")


# ---------------------------------------------------------------------------
# Subprocess + response helpers
# ---------------------------------------------------------------------------

def _run(
    cmd: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    capture_stderr: bool = True,
) -> tuple[str, str, int, float]:
    """
    Execute cmd (list of strings, shell=False).
    Returns (stdout, stderr, returncode, duration_seconds).
    """
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            timeout=timeout,
            shell=False,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace") if capture_stderr else ""
        rc = result.returncode
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = f"[TIMEOUT] Command exceeded {timeout}s limit."
        rc = -1
    except FileNotFoundError as exc:
        stdout = ""
        stderr = f"[BINARY NOT FOUND] {exc}"
        rc = -1
    duration = time.monotonic() - start
    return stdout, stderr, rc, duration


def _build_response(
    tool: str,
    cmd: list[str],
    stdout: str,
    stderr: str,
    returncode: int,
    duration: float,
    extra: Optional[dict] = None,
) -> dict:
    """Build the standard structured response dict, truncating outputs."""
    stdout_trunc = stdout[:MAX_OUTPUT_CHARS]
    stderr_trunc = stderr[:2000]
    truncated = len(stdout) > MAX_OUTPUT_CHARS

    resp = {
        "tool": tool,
        "cmd": " ".join(cmd),
        "stdout_preview": stdout_trunc,
        "stderr_preview": stderr_trunc,
        "returncode": returncode,
        "duration_s": round(duration, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": truncated,
    }
    if extra:
        resp.update(extra)
    return resp


def _lines(text: str) -> list[str]:
    """Split text into non-empty stripped lines."""
    return [line for line in text.splitlines() if line.strip()]


def _truncate_lines(lines: list[str], max_lines: int) -> tuple[list[str], bool]:
    """Return up to max_lines lines and a truncated flag."""
    return lines[:max_lines], len(lines) > max_lines


# ---------------------------------------------------------------------------
# Tool: 1 — get_image_info
# ---------------------------------------------------------------------------

@mcp.tool()
def get_image_info(image_path: str) -> dict:
    """
    Get metadata about a forensic disk image.
    Runs `file` on any image; additionally runs `ewfinfo` for .E01 images.
    Returns: tool, cmd, stdout_preview, stderr_preview, returncode, duration_s,
             timestamp_utc, truncated, image_type, ewf_info (if applicable).
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    # Run `file`
    file_cmd = ["file", image_path]
    file_out, file_err, file_rc, file_dur = _run(file_cmd)

    result = _build_response("get_image_info", file_cmd, file_out, file_err, file_rc, file_dur)
    result["image_type"] = file_out.strip()

    # If .E01, also run ewfinfo
    if image_path.lower().endswith(".e01"):
        ewf_cmd = ["ewfinfo", image_path]
        ewf_out, ewf_err, ewf_rc, ewf_dur = _run(ewf_cmd)
        result["ewf_info"] = ewf_out[:MAX_OUTPUT_CHARS]
        result["ewf_returncode"] = ewf_rc
        if len(ewf_out) > MAX_OUTPUT_CHARS:
            result["truncated"] = True

    return result


# ---------------------------------------------------------------------------
# Tool: 2 — list_partitions
# ---------------------------------------------------------------------------

@mcp.tool()
def list_partitions(image_path: str) -> dict:
    """
    List partition table of a forensic disk image using `mmls`.
    Returns parsed partition entries with slot, start, end, length, description.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = ["mmls", image_path]
    stdout, stderr, rc, dur = _run(cmd)

    result = _build_response("list_partitions", cmd, stdout, stderr, rc, dur)

    # Parse mmls output into structured partition list
    partitions: list[dict] = []
    for line in _lines(stdout):
        # mmls format: "00:  -----  0000000000     0000002047     0000002048   Unallocated"
        # or           "02:  000    0000002048     0000206847     0000204800   Linux (0x83)"
        m = re.match(
            r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)", line
        )
        if m:
            partitions.append({
                "slot": m.group(1),
                "tag": m.group(2),
                "start": int(m.group(3)),
                "end": int(m.group(4)),
                "length": int(m.group(5)),
                "description": m.group(6).strip(),
            })

    result["partitions"] = partitions
    result["partition_count"] = len(partitions)
    return result


# ---------------------------------------------------------------------------
# Tool: 3 — list_files
# ---------------------------------------------------------------------------

@mcp.tool()
def list_files(image_path: str, offset: int, path_filter: str = "") -> dict:
    """
    Recursively list files in a partition using `fls`.
    Args:
        image_path: Path to disk image (must be in evidence dir).
        offset: Partition start offset (from mmls).
        path_filter: Optional substring filter on file paths returned.
    Returns up to 200 lines of file listing.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = ["fls", "-r", "-o", str(offset), image_path]
    stdout, stderr, rc, dur = _run(cmd)

    result = _build_response("list_files", cmd, stdout, stderr, rc, dur)

    lines = _lines(stdout)
    if path_filter:
        lines = [l for l in lines if path_filter.lower() in l.lower()]

    lines, trunc = _truncate_lines(lines, 200)
    result["files"] = lines
    result["file_count"] = len(lines)
    result["filtered_by"] = path_filter or None
    result["truncated"] = trunc
    return result


# ---------------------------------------------------------------------------
# Tool: 4 — extract_file
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_file(image_path: str, offset: int, inode: int, output_path: str) -> dict:
    """
    Extract a file from a disk image by inode using `icat`.
    output_path MUST be inside ./exports/ or ./analysis/.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)
    _validate_output(output_path)

    # Ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    cmd = ["icat", "-o", str(offset), image_path, str(inode)]
    start = time.monotonic()
    try:
        with open(output_path, "wb") as fout:
            result_proc = subprocess.run(
                cmd,
                stdout=fout,
                stderr=subprocess.PIPE,
                timeout=DEFAULT_TIMEOUT,
                shell=False,
            )
        stderr = result_proc.stderr.decode("utf-8", errors="replace")
        rc = result_proc.returncode
    except subprocess.TimeoutExpired:
        stderr = f"[TIMEOUT] icat exceeded {DEFAULT_TIMEOUT}s."
        rc = -1
    except FileNotFoundError as exc:
        stderr = f"[BINARY NOT FOUND] {exc}"
        rc = -1
    dur = time.monotonic() - start

    file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0

    return {
        "tool": "extract_file",
        "cmd": " ".join(cmd),
        "stdout_preview": f"File written to {output_path}",
        "stderr_preview": stderr[:2000],
        "returncode": rc,
        "duration_s": round(dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": False,
        "output_path": output_path,
        "file_size_bytes": file_size,
    }


# ---------------------------------------------------------------------------
# Tool: 5 — get_file_info
# ---------------------------------------------------------------------------

@mcp.tool()
def get_file_info(image_path: str, offset: int, inode: int) -> dict:
    """
    Get metadata about a specific inode using `istat`.
    Returns timestamps, file size, allocated blocks, and other metadata.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = ["istat", "-o", str(offset), image_path, str(inode)]
    stdout, stderr, rc, dur = _run(cmd)

    result = _build_response("get_file_info", cmd, stdout, stderr, rc, dur)

    # Parse key fields from istat output
    metadata: dict = {}
    for line in _lines(stdout):
        if ":" in line:
            key, _, val = line.partition(":")
            metadata[key.strip()] = val.strip()
    result["metadata"] = metadata
    return result


# ---------------------------------------------------------------------------
# Tool: 6 — analyze_memory_processes
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_memory_processes(image_path: str) -> dict:
    """
    Analyze running processes in a memory image using Volatility3.
    Runs both windows.psscan and windows.pslist, then diffs them to highlight
    processes that appear in psscan but not pslist (potential hidden processes).
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    vol_base = VOL3.split()

    # Run pslist
    pslist_cmd = vol_base + ["-f", image_path, "windows.pslist"]
    pslist_out, pslist_err, pslist_rc, pslist_dur = _run(pslist_cmd, timeout=180)

    # Run psscan
    psscan_cmd = vol_base + ["-f", image_path, "windows.psscan"]
    psscan_out, psscan_err, psscan_rc, psscan_dur = _run(psscan_cmd, timeout=180)

    # Parse PIDs from each plugin
    def _parse_pids(text: str) -> set[int]:
        pids: set[int] = set()
        for line in _lines(text):
            m = re.search(r"\b(\d{1,6})\b", line)
            if m and not line.strip().startswith("#"):
                try:
                    pids.add(int(m.group(1)))
                except ValueError:
                    pass
        return pids

    pslist_pids = _parse_pids(pslist_out)
    psscan_pids = _parse_pids(psscan_out)
    hidden_pids = psscan_pids - pslist_pids

    # Build hidden process lines
    hidden_lines: list[str] = []
    for line in _lines(psscan_out):
        for pid in hidden_pids:
            if re.search(rf"\b{pid}\b", line):
                hidden_lines.append(f"[HIDDEN] {line}")
                break

    combined = pslist_out[:4000] + "\n--- psscan ---\n" + psscan_out[:4000]
    truncated = len(pslist_out) > 4000 or len(psscan_out) > 4000

    return {
        "tool": "analyze_memory_processes",
        "cmd": f"{' '.join(pslist_cmd)} | {' '.join(psscan_cmd)}",
        "stdout_preview": combined[:MAX_OUTPUT_CHARS],
        "stderr_preview": (pslist_err + psscan_err)[:2000],
        "returncode": max(pslist_rc, psscan_rc),
        "duration_s": round(pslist_dur + psscan_dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": truncated,
        "pslist_pid_count": len(pslist_pids),
        "psscan_pid_count": len(psscan_pids),
        "hidden_process_count": len(hidden_pids),
        "hidden_processes": hidden_lines[:20],
    }


# ---------------------------------------------------------------------------
# Tool: 7 — analyze_memory_network
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_memory_network(image_path: str) -> dict:
    """
    Analyze network connections in a memory image using Volatility3.
    Runs windows.netscan and windows.netstat, deduplicates unique remote IPs,
    and returns up to 100 rows of connection data.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    vol_base = VOL3.split()

    netscan_cmd = vol_base + ["-f", image_path, "windows.netscan"]
    netscan_out, netscan_err, netscan_rc, netscan_dur = _run(netscan_cmd, timeout=180)

    netstat_cmd = vol_base + ["-f", image_path, "windows.netstat"]
    netstat_out, netstat_err, netstat_rc, netstat_dur = _run(netstat_cmd, timeout=180)

    # Extract remote IPs (IPv4/IPv6)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{7,39}")
    all_ips: set[str] = set()
    all_lines: list[str] = _lines(netscan_out) + _lines(netstat_out)

    for line in all_lines:
        for ip in ip_re.findall(line):
            # Exclude obvious local/loopback
            if not ip.startswith("0.0.0.0") and not ip.startswith("127.") and ip != "::":
                all_ips.add(ip)

    conn_lines, trunc = _truncate_lines(all_lines, 100)
    combined = "\n".join(conn_lines)

    return {
        "tool": "analyze_memory_network",
        "cmd": f"{' '.join(netscan_cmd)} + {' '.join(netstat_cmd)}",
        "stdout_preview": combined[:MAX_OUTPUT_CHARS],
        "stderr_preview": (netscan_err + netstat_err)[:2000],
        "returncode": max(netscan_rc, netstat_rc),
        "duration_s": round(netscan_dur + netstat_dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": trunc,
        "unique_remote_ips": sorted(all_ips)[:200],
        "unique_ip_count": len(all_ips),
        "connection_row_count": len(conn_lines),
    }


# ---------------------------------------------------------------------------
# Tool: 8 — analyze_memory_cmdlines
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_memory_cmdlines(image_path: str) -> dict:
    """
    Extract command line arguments from memory processes using windows.cmdline.
    Returns a dict keyed by PID with process name and command line string.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = VOL3.split() + ["-f", image_path, "windows.cmdline"]
    stdout, stderr, rc, dur = _run(cmd, timeout=180)

    result = _build_response("analyze_memory_cmdlines", cmd, stdout, stderr, rc, dur)

    # Parse into {PID: {name, cmdline}} dict
    cmdlines: dict[str, dict] = {}
    current_pid: Optional[str] = None
    current_proc: Optional[str] = None

    for line in _lines(stdout):
        # Typical format: "PID\tProcess\tArgs"  (tab-separated header then rows)
        parts = line.split("\t")
        if len(parts) >= 3:
            pid_str = parts[0].strip()
            if pid_str.isdigit():
                current_pid = pid_str
                current_proc = parts[1].strip()
                cmdlines[current_pid] = {
                    "process": current_proc,
                    "cmdline": "\t".join(parts[2:]).strip(),
                }
        elif current_pid and line.strip():
            # Continuation line
            cmdlines[current_pid]["cmdline"] += " " + line.strip()

    result["cmdlines_by_pid"] = cmdlines
    result["process_count"] = len(cmdlines)
    return result


# ---------------------------------------------------------------------------
# Tool: 9 — analyze_memory_malfind
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_memory_malfind(image_path: str, dump: bool = False) -> dict:
    """
    Run windows.malfind to detect process memory regions with suspicious characteristics
    (executable, not backed by file, contains shellcode-like patterns).
    Returns hit count and top 10 hits with hex previews.
    If dump=True, dumps regions to ./exports/malfind/ (requires safe output path).
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = VOL3.split() + ["-f", image_path, "windows.malfind"]

    if dump:
        dump_dir = "./exports/malfind/"
        _validate_output(dump_dir)
        os.makedirs(dump_dir, exist_ok=True)
        cmd += ["--dump", "--output-dir", dump_dir]

    stdout, stderr, rc, dur = _run(cmd, timeout=300)
    result = _build_response("analyze_memory_malfind", cmd, stdout, stderr, rc, dur)

    # Parse hits — each hit block starts with a PID line
    hits: list[dict] = []
    current: Optional[dict] = None
    hex_lines: list[str] = []

    for line in _lines(stdout):
        pid_match = re.match(r"^(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)", line)
        if pid_match:
            if current:
                current["hex_preview"] = "\n".join(hex_lines[:4])
                hits.append(current)
            current = {
                "pid": pid_match.group(1),
                "process": pid_match.group(2),
                "start_va": pid_match.group(3),
                "protection": pid_match.group(4),
                "tag": pid_match.group(5),
            }
            hex_lines = []
        elif current and re.match(r"^[0-9a-fA-F]{4,}:", line):
            hex_lines.append(line)

    if current:
        current["hex_preview"] = "\n".join(hex_lines[:4])
        hits.append(current)

    result["hit_count"] = len(hits)
    result["top_hits"] = hits[:10]
    result["dump_enabled"] = dump
    if dump:
        result["dump_dir"] = dump_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 10 — analyze_memory_services
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_memory_services(image_path: str) -> dict:
    """
    List Windows services from a memory image using windows.svcscan.
    Flags services with binary paths NOT in System32, SysWOW64, or Program Files
    as potentially suspicious.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    cmd = VOL3.split() + ["-f", image_path, "windows.svcscan"]
    stdout, stderr, rc, dur = _run(cmd, timeout=180)

    result = _build_response("analyze_memory_services", cmd, stdout, stderr, rc, dur)

    # Define legitimate path prefixes (case-insensitive)
    LEGIT_PREFIXES = (
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
        "\\systemroot\\system32",
        "system32",
        "syswow64",
    )

    suspicious: list[dict] = []
    all_services: list[dict] = []

    for line in _lines(stdout):
        parts = line.split("\t")
        if len(parts) >= 3:
            svc_name = parts[0].strip()
            svc_state = parts[1].strip() if len(parts) > 1 else ""
            svc_binary = parts[-1].strip()
            entry = {
                "name": svc_name,
                "state": svc_state,
                "binary": svc_binary,
                "suspicious": False,
            }
            if svc_binary and not any(
                svc_binary.lower().startswith(p) for p in LEGIT_PREFIXES
            ):
                entry["suspicious"] = True
                suspicious.append(entry)
            all_services.append(entry)

    result["total_services"] = len(all_services)
    result["suspicious_services"] = suspicious
    result["suspicious_count"] = len(suspicious)
    return result


# ---------------------------------------------------------------------------
# Tool: 11 — parse_mft
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_mft(mft_path: str, output_dir: str = "./exports/mft/") -> dict:
    """
    Parse an NTFS Master File Table using MFTECmd.
    Returns summary: total entries, deleted entry count, and top 20 most
    recently modified entries.
    """
    _validate_evidence(mft_path)
    _path_exists(mft_path)
    _validate_output(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    cmd = MFTECMD.split() + ["-f", mft_path, "--csv", output_dir]
    stdout, stderr, rc, dur = _run(cmd, timeout=300)

    result = _build_response("parse_mft", cmd, stdout, stderr, rc, dur)

    # Parse summary stats from MFTECmd console output
    total_entries = 0
    deleted_count = 0

    for line in _lines(stdout):
        m_total = re.search(r"(\d[\d,]+)\s+entries", line, re.IGNORECASE)
        if m_total:
            total_entries = int(m_total.group(1).replace(",", ""))
        m_del = re.search(r"(\d[\d,]+)\s+deleted", line, re.IGNORECASE)
        if m_del:
            deleted_count = int(m_del.group(1).replace(",", ""))

    # Try to read generated CSV for top recently modified entries
    csv_entries: list[dict] = []
    for csv_file in Path(output_dir).glob("*.csv"):
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            # Sort by LastModified0x10 or SI_Modified
            date_col = next(
                (c for c in (rows[0].keys() if rows else [])
                 if "modified" in c.lower() or "changed" in c.lower()),
                None,
            )
            if date_col:
                rows.sort(key=lambda r: r.get(date_col, ""), reverse=True)
            csv_entries = [
                {k: v for k, v in row.items()} for row in rows[:20]
            ]
            if not total_entries:
                total_entries = len(rows)
        except Exception as e:
            result["csv_parse_error"] = str(e)
        break

    result["total_entries"] = total_entries
    result["deleted_count"] = deleted_count
    result["top_recently_modified"] = csv_entries
    result["output_dir"] = output_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 12 — parse_event_logs
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_event_logs(
    evtx_dir: str,
    event_ids: Optional[list[int]] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> dict:
    """
    Parse Windows Event Logs using EvtxECmd.
    Args:
        evtx_dir: Directory containing .evtx files (must be in evidence dir).
        event_ids: Optional list of Event IDs to filter.
        start_date: Optional ISO date string (YYYY-MM-DD) to filter events.
        end_date: Optional ISO date string (YYYY-MM-DD) to filter events.
    Returns count by EventID and top 50 most security-relevant event rows.
    """
    _validate_evidence(evtx_dir)
    _path_exists(evtx_dir)

    out_dir = "./exports/evtx/"
    _validate_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = EVTXECMD.split() + ["-d", evtx_dir, "--csv", out_dir]
    if start_date:
        cmd += ["--sd", start_date]
    if end_date:
        cmd += ["--ed", end_date]

    stdout, stderr, rc, dur = _run(cmd, timeout=300)
    result = _build_response("parse_event_logs", cmd, stdout, stderr, rc, dur)

    # Parse generated CSV
    event_id_counts: dict[str, int] = {}
    top_events: list[dict] = []

    # Security-relevant Event IDs (MITRE / SANS)
    SECURITY_EVENT_IDS = {
        4624, 4625, 4648, 4663, 4688, 4698, 4702, 4720, 4728, 4732,
        4740, 4768, 4769, 4776, 7045, 1102, 4657, 4670, 4672, 4697,
    }

    for csv_file in Path(out_dir).glob("*.csv"):
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            for row in rows:
                eid_raw = row.get("EventId") or row.get("EventID") or row.get("event_id", "")
                try:
                    eid = int(eid_raw)
                except (ValueError, TypeError):
                    continue

                # Apply event_ids filter if provided
                if event_ids and eid not in event_ids:
                    continue

                event_id_counts[str(eid)] = event_id_counts.get(str(eid), 0) + 1
                if eid in SECURITY_EVENT_IDS or (event_ids and eid in event_ids):
                    top_events.append(row)

            top_events = top_events[:50]
        except Exception as e:
            result["csv_parse_error"] = str(e)
        break

    result["event_id_counts"] = event_id_counts
    result["security_events"] = top_events
    result["security_event_count"] = len(top_events)
    result["output_dir"] = out_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 13 — parse_registry
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_registry(hive_path: str, key_path: Optional[str] = None) -> dict:
    """
    Parse a Windows Registry hive using RECmd.
    If key_path is provided, runs a targeted key query.
    Otherwise, runs the full Kroll_Batch.reb batch analysis.
    """
    _validate_evidence(hive_path)
    _path_exists(hive_path)

    out_dir = "./exports/registry/"
    _validate_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    if key_path:
        # Targeted key query
        cmd = RECMD.split() + ["-f", hive_path, "--kn", key_path, "--csv", out_dir]
    else:
        # Full batch analysis
        cmd = RECMD.split() + [
            "-f", hive_path,
            "--bn", RECMD_BATCH,
            "--csv", out_dir,
        ]

    stdout, stderr, rc, dur = _run(cmd, timeout=300)
    result = _build_response("parse_registry", cmd, stdout, stderr, rc, dur)

    # Try to summarize CSV output
    csv_entries: list[dict] = []
    for csv_file in sorted(Path(out_dir).glob("*.csv"))[:1]:
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                csv_entries = [row for _, row in zip(range(100), reader)]
        except Exception as e:
            result["csv_parse_error"] = str(e)

    result["output_dir"] = out_dir
    result["key_path_queried"] = key_path
    result["entries_preview"] = csv_entries[:50]
    result["entry_count"] = len(csv_entries)
    return result


# ---------------------------------------------------------------------------
# Tool: 14 — parse_amcache
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_amcache(amcache_path: str) -> dict:
    """
    Parse the Amcache.hve registry hive using AmcacheParser.
    Returns a list of executed/installed programs with SHA1 hashes.
    """
    _validate_evidence(amcache_path)
    _path_exists(amcache_path)

    out_dir = "./exports/amcache/"
    _validate_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = AMCACHEPARSER.split() + ["-f", amcache_path, "--csv", out_dir]
    stdout, stderr, rc, dur = _run(cmd, timeout=180)

    result = _build_response("parse_amcache", cmd, stdout, stderr, rc, dur)

    # Parse the Amcache entries CSV
    entries: list[dict] = []
    for csv_file in Path(out_dir).glob("*Entries*.csv"):
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = {
                        "sha1": row.get("SHA1", row.get("FileId", "")),
                        "name": row.get("Name", row.get("ApplicationName", "")),
                        "path": row.get("FullPath", row.get("Path", "")),
                        "size": row.get("FileSize", ""),
                        "compile_time": row.get("LinkDate", row.get("CompileTime", "")),
                        "key_last_write": row.get("KeyLastWriteTimestamp", ""),
                    }
                    entries.append(entry)
        except Exception as e:
            result["csv_parse_error"] = str(e)
        break

    result["executables"] = entries[:200]
    result["executable_count"] = len(entries)
    result["output_dir"] = out_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 15 — parse_shimcache
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_shimcache(system_hive_path: str) -> dict:
    """
    Parse Application Compatibility Cache (ShimCache) from SYSTEM hive
    using AppCompatCacheParser.
    Returns shimcache entries sorted by last modified time.
    """
    _validate_evidence(system_hive_path)
    _path_exists(system_hive_path)

    out_dir = "./exports/shimcache/"
    _validate_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = APPCOMPATPARSER.split() + ["-f", system_hive_path, "--csv", out_dir]
    stdout, stderr, rc, dur = _run(cmd, timeout=180)

    result = _build_response("parse_shimcache", cmd, stdout, stderr, rc, dur)

    entries: list[dict] = []
    for csv_file in Path(out_dir).glob("*.csv"):
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            # Sort by LastModifiedTimeUTC descending
            date_col = next(
                (c for c in (rows[0].keys() if rows else [])
                 if "modified" in c.lower() or "time" in c.lower()),
                None,
            )
            if date_col:
                rows.sort(key=lambda r: r.get(date_col, ""), reverse=True)
            entries = rows[:200]
        except Exception as e:
            result["csv_parse_error"] = str(e)
        break

    result["shimcache_entries"] = entries
    result["entry_count"] = len(entries)
    result["output_dir"] = out_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 16 — parse_prefetch
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_prefetch(prefetch_dir: str) -> dict:
    """
    Parse Windows Prefetch files using PECmd.
    Returns an execution evidence table with run counts, last run times,
    and loaded files for each prefetch entry.
    """
    _validate_evidence(prefetch_dir)
    _path_exists(prefetch_dir)

    out_dir = "./exports/prefetch/"
    _validate_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = PECMD.split() + ["-d", prefetch_dir, "--csv", out_dir]
    stdout, stderr, rc, dur = _run(cmd, timeout=180)

    result = _build_response("parse_prefetch", cmd, stdout, stderr, rc, dur)

    entries: list[dict] = []
    for csv_file in Path(out_dir).glob("*.csv"):
        try:
            import csv
            with open(csv_file, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    entry = {
                        "executable": row.get("ExecutableName", row.get("Name", "")),
                        "run_count": row.get("RunCount", ""),
                        "last_run": row.get("LastRun", row.get("LastRunTime", "")),
                        "size": row.get("Size", ""),
                        "hash": row.get("Hash", ""),
                    }
                    entries.append(entry)
        except Exception as e:
            result["csv_parse_error"] = str(e)
        break

    # Sort by last_run descending
    entries.sort(key=lambda e: e.get("last_run", ""), reverse=True)

    result["prefetch_entries"] = entries[:200]
    result["entry_count"] = len(entries)
    result["output_dir"] = out_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 17 — generate_timeline
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_timeline(
    image_path: str,
    offset: int,
    output_dir: str = "./analysis/timeline/",
) -> dict:
    """
    Generate a forensic super-timeline using log2timeline.py and psort.py.
    Returns summary statistics from the timeline.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)
    _validate_output(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    plaso_out = os.path.join(output_dir, "timeline.plaso")
    csv_out = os.path.join(output_dir, "timeline.csv")

    # Run log2timeline
    l2t_cmd = [
        "log2timeline.py",
        "--partition", str(offset),
        "--storage-file", plaso_out,
        image_path,
    ]
    l2t_out, l2t_err, l2t_rc, l2t_dur = _run(l2t_cmd, timeout=600)

    # Run psort to output CSV
    psort_cmd = [
        "psort.py",
        "-o", "dynamic",
        "--write", csv_out,
        plaso_out,
    ]
    psort_out, psort_err, psort_rc, psort_dur = _run(psort_cmd, timeout=300)

    total_dur = l2t_dur + psort_dur

    # Count CSV rows for summary
    event_count = 0
    date_range_start = ""
    date_range_end = ""
    if os.path.exists(csv_out):
        try:
            import csv
            with open(csv_out, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            event_count = len(rows)
            if rows:
                date_col = next(
                    (c for c in rows[0].keys() if "date" in c.lower() or "time" in c.lower()),
                    None,
                )
                if date_col:
                    dates = sorted(r.get(date_col, "") for r in rows if r.get(date_col))
                    if dates:
                        date_range_start = dates[0]
                        date_range_end = dates[-1]
        except Exception:
            pass

    combined_out = l2t_out[:3000] + "\n--- psort ---\n" + psort_out[:3000]

    return {
        "tool": "generate_timeline",
        "cmd": f"{' '.join(l2t_cmd)} | {' '.join(psort_cmd)}",
        "stdout_preview": combined_out[:MAX_OUTPUT_CHARS],
        "stderr_preview": (l2t_err + psort_err)[:2000],
        "returncode": max(l2t_rc, psort_rc),
        "duration_s": round(total_dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": len(l2t_out) > 3000 or len(psort_out) > 3000,
        "event_count": event_count,
        "date_range_start": date_range_start,
        "date_range_end": date_range_end,
        "output_dir": output_dir,
        "plaso_file": plaso_out,
        "csv_file": csv_out,
    }


# ---------------------------------------------------------------------------
# Tool: 18 — run_yara_scan
# ---------------------------------------------------------------------------

@mcp.tool()
def run_yara_scan(rules_path: str, target_path: str) -> dict:
    """
    Run a YARA scan against a target file or directory.
    Args:
        rules_path: Path to YARA rules file (.yar/.yara). Must be in evidence or safe output dir.
        target_path: File or directory to scan. Must be in evidence dir or safe output dir.
    Returns match list with rule name, matched file, and byte offset.
    """
    # Rules can be in evidence OR safe output (user may have created them in analysis/)
    if not (_is_evidence_path(rules_path) or _is_safe_output_path(rules_path)):
        # Also allow absolute paths under /opt/ for system rule sets
        if not os.path.abspath(rules_path).startswith("/opt/"):
            raise ValueError(
                f"rules_path '{rules_path}' must be in an evidence dir, safe output dir, or /opt/."
            )
    if not (_is_evidence_path(target_path) or _is_safe_output_path(target_path)):
        raise ValueError(f"target_path '{target_path}' must be in an evidence or safe output dir.")

    _path_exists(rules_path)
    _path_exists(target_path)

    cmd = [YARA_BIN, "-r", rules_path, target_path]
    stdout, stderr, rc, dur = _run(cmd, timeout=300)

    result = _build_response("run_yara_scan", cmd, stdout, stderr, rc, dur)

    # Parse matches: "RuleName /path/to/file"
    matches: list[dict] = []
    for line in _lines(stdout):
        parts = line.split(" ", 1)
        if len(parts) == 2:
            matches.append({
                "rule": parts[0].strip(),
                "file": parts[1].strip(),
            })
        elif len(parts) == 1:
            matches.append({"rule": parts[0].strip(), "file": target_path})

    result["matches"] = matches
    result["match_count"] = len(matches)
    return result


# ---------------------------------------------------------------------------
# Tool: 19 — hash_file
# ---------------------------------------------------------------------------

@mcp.tool()
def hash_file(file_path: str, algorithm: str = "sha256") -> dict:
    """
    Compute a cryptographic hash of a file.
    Args:
        file_path: Path to file. Must be in evidence dir or safe output dir.
        algorithm: One of "sha256", "sha1", "md5".
    Returns hash value and file size.
    """
    if not (_is_evidence_path(file_path) or _is_safe_output_path(file_path)):
        raise ValueError(f"file_path '{file_path}' must be in an evidence or safe output dir.")
    _path_exists(file_path)

    algorithm = algorithm.lower().strip()
    algo_map = {
        "sha256": "sha256sum",
        "sha1": "sha1sum",
        "md5": "md5sum",
    }
    if algorithm not in algo_map:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Use: sha256, sha1, md5.")

    cmd = [algo_map[algorithm], file_path]
    stdout, stderr, rc, dur = _run(cmd)

    result = _build_response("hash_file", cmd, stdout, stderr, rc, dur)

    # Parse hash value from output (format: "HASH  FILENAME")
    hash_value = ""
    if stdout.strip():
        hash_value = stdout.strip().split()[0]

    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    result["hash_value"] = hash_value
    result["algorithm"] = algorithm
    result["file_size_bytes"] = file_size
    return result


# ---------------------------------------------------------------------------
# Tool: 20 — run_bulk_extractor
# ---------------------------------------------------------------------------

@mcp.tool()
def run_bulk_extractor(
    image_path: str,
    output_dir: str,
    feature_list: Optional[list[str]] = None,
) -> dict:
    """
    Run bulk_extractor on a disk image to extract forensic features.
    Args:
        image_path: Path to disk image (must be in evidence dir).
        output_dir: Output directory for feature files (must be in safe output dir).
        feature_list: List of features to extract. Supported: email, url, domain,
                      credit_card, telephone. Defaults to all five.
    Returns feature counts per type.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)
    _validate_output(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    ALLOWED_FEATURES = {"email", "url", "domain", "credit_card", "telephone"}
    if feature_list is None:
        feature_list = list(ALLOWED_FEATURES)

    # Validate feature list
    invalid = set(feature_list) - ALLOWED_FEATURES
    if invalid:
        raise ValueError(f"Unsupported features: {invalid}. Allowed: {ALLOWED_FEATURES}")

    # Build command: disable all scanners, then enable only requested ones
    cmd = [BULK_EXTRACTOR, "-o", output_dir, "-S", "default_histogram=YES"]
    for feat in ALLOWED_FEATURES:
        cmd += ["-e" if feat in feature_list else "-x", feat]
    cmd.append(image_path)

    stdout, stderr, rc, dur = _run(cmd, timeout=600)
    result = _build_response("run_bulk_extractor", cmd, stdout, stderr, rc, dur)

    # Count feature file entries
    feature_counts: dict[str, int] = {}
    for feat in feature_list:
        feat_file = Path(output_dir) / f"{feat}.txt"
        if feat_file.exists():
            try:
                with open(feat_file) as f:
                    count = sum(1 for l in f if l.strip() and not l.startswith("#"))
                feature_counts[feat] = count
            except Exception:
                feature_counts[feat] = -1
        else:
            feature_counts[feat] = 0

    result["feature_counts"] = feature_counts
    result["output_dir"] = output_dir
    return result


# ---------------------------------------------------------------------------
# Tool: 21 — get_strings
# ---------------------------------------------------------------------------

@mcp.tool()
def get_strings(file_path: str, min_length: int = 8, encoding: str = "both") -> dict:
    """
    Extract printable strings from a binary file and highlight IOC patterns.
    Args:
        file_path: Path to file (must be in evidence or safe output dir).
        min_length: Minimum string length (default 8).
        encoding: "ascii", "unicode", or "both".
    Returns top IOC matches: URLs, IPs, registry paths, base64 blobs.
    """
    if not (_is_evidence_path(file_path) or _is_safe_output_path(file_path)):
        raise ValueError(f"file_path '{file_path}' must be in an evidence or safe output dir.")
    _path_exists(file_path)

    if encoding not in ("ascii", "unicode", "both"):
        raise ValueError("encoding must be 'ascii', 'unicode', or 'both'")

    results_combined: list[str] = []

    if encoding in ("ascii", "both"):
        cmd_ascii = ["strings", "-a", "-n", str(min_length), file_path]
        out_a, _, _, _ = _run(cmd_ascii)
        results_combined.extend(_lines(out_a))

    if encoding in ("unicode", "both"):
        cmd_uni = ["strings", "-a", "-n", str(min_length), "-e", "l", file_path]
        out_u, _, _, _ = _run(cmd_uni)
        results_combined.extend(_lines(out_u))

    # Deduplicate
    all_strings = list(dict.fromkeys(results_combined))

    # IOC pattern matching
    URL_RE = re.compile(r"https?://[^\s\"'<>]{6,}", re.IGNORECASE)
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    REG_RE = re.compile(r"(?:HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']{4,}", re.IGNORECASE)
    B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")

    urls: list[str] = []
    ips: list[str] = []
    reg_paths: list[str] = []
    b64_blobs: list[str] = []

    for s in all_strings:
        urls += URL_RE.findall(s)
        ips += IP_RE.findall(s)
        reg_paths += REG_RE.findall(s)
        b64_blobs += B64_RE.findall(s)

    # Deduplicate IOC lists
    urls = list(dict.fromkeys(urls))[:100]
    ips = list(dict.fromkeys(ips))[:100]
    reg_paths = list(dict.fromkeys(reg_paths))[:100]
    b64_blobs = list(dict.fromkeys(b64_blobs))[:50]

    total_strings = len(all_strings)
    start = time.monotonic()
    dur = time.monotonic() - start

    return {
        "tool": "get_strings",
        "cmd": f"strings -a -n {min_length} {file_path}",
        "stdout_preview": "\n".join(all_strings[:200]),
        "stderr_preview": "",
        "returncode": 0,
        "duration_s": round(dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": total_strings > 200,
        "total_strings": total_strings,
        "ioc_urls": urls,
        "ioc_ips": ips,
        "ioc_registry_paths": reg_paths,
        "ioc_base64_blobs": b64_blobs,
        "ioc_url_count": len(urls),
        "ioc_ip_count": len(ips),
    }


# ---------------------------------------------------------------------------
# Tool: 22 — parse_network_capture
# ---------------------------------------------------------------------------

@mcp.tool()
def parse_network_capture(pcap_path: str, filter_expr: str = "") -> dict:
    """
    Analyze a network packet capture using tshark.
    Args:
        pcap_path: Path to .pcap/.pcapng file (must be in evidence dir).
        filter_expr: Optional BPF/display filter expression.
    Returns top talkers (by packet count) and protocol distribution.
    """
    _validate_evidence(pcap_path)
    _path_exists(pcap_path)

    # Get protocol distribution
    proto_cmd = [
        TSHARK, "-r", pcap_path,
        "-q", "-z", "io,phs",
    ]
    if filter_expr:
        proto_cmd += ["-Y", filter_expr]
    proto_out, proto_err, proto_rc, proto_dur = _run(proto_cmd, timeout=120)

    # Get top conversation talkers (IPv4)
    conv_cmd = [
        TSHARK, "-r", pcap_path,
        "-q", "-z", "conv,ip",
    ]
    if filter_expr:
        conv_cmd += ["-Y", filter_expr]
    conv_out, conv_err, conv_rc, conv_dur = _run(conv_cmd, timeout=120)

    total_dur = proto_dur + conv_dur
    combined = proto_out[:4000] + "\n--- Conversations ---\n" + conv_out[:4000]
    truncated = len(proto_out) > 4000 or len(conv_out) > 4000

    # Parse top talkers from conversation output
    top_talkers: list[dict] = []
    for line in _lines(conv_out):
        # tshark conv,ip format: "A <-> B  frames_a bytes_a frames_b bytes_b total_frames total_bytes"
        m = re.match(
            r"(\S+)\s+<->\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", line
        )
        if m:
            top_talkers.append({
                "addr_a": m.group(1),
                "addr_b": m.group(2),
                "frames_a_to_b": int(m.group(3)),
                "frames_b_to_a": int(m.group(5)),
                "total_frames": int(m.group(7)),
                "total_bytes": int(m.group(8)),
            })

    top_talkers.sort(key=lambda x: x["total_frames"], reverse=True)

    return {
        "tool": "parse_network_capture",
        "cmd": f"{' '.join(proto_cmd)} + {' '.join(conv_cmd)}",
        "stdout_preview": combined[:MAX_OUTPUT_CHARS],
        "stderr_preview": (proto_err + conv_err)[:2000],
        "returncode": max(proto_rc, conv_rc),
        "duration_s": round(total_dur, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "truncated": truncated,
        "top_talkers": top_talkers[:20],
        "protocol_stats": proto_out[:3000],
        "filter_applied": filter_expr or None,
    }


# ---------------------------------------------------------------------------
# Tool: 23 — baseline_memory
# ---------------------------------------------------------------------------

@mcp.tool()
def baseline_memory(
    image_path: str,
    baseline_json: str,
    mode: str = "proc",
) -> dict:
    """
    Compare a memory image against a known-good baseline using memory-baseliner.
    Args:
        image_path: Path to memory image (must be in evidence dir).
        baseline_json: Path to baseline JSON file (must be in evidence or safe output dir).
        mode: Comparison mode — "proc" (processes), "net" (network), or "svc" (services).
    Returns diff of anomalous entries not present in the baseline.
    """
    _validate_evidence(image_path)
    _path_exists(image_path)

    if not (_is_evidence_path(baseline_json) or _is_safe_output_path(baseline_json)):
        raise ValueError(
            f"baseline_json '{baseline_json}' must be in an evidence or safe output dir."
        )
    _path_exists(baseline_json)

    VALID_MODES = {"proc", "net", "svc"}
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Choose from: {VALID_MODES}")

    cmd = MEMORY_BASELINER.split() + [
        "--compare",
        "--image", image_path,
        "--baseline", baseline_json,
        "--mode", mode,
    ]
    stdout, stderr, rc, dur = _run(cmd, timeout=300)

    result = _build_response("baseline_memory", cmd, stdout, stderr, rc, dur)

    # Parse anomalous entries from JSON output if available
    anomalies: list[dict] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            anomalies = data.get("anomalies", data.get("diff", []))
        elif isinstance(data, list):
            anomalies = data
    except json.JSONDecodeError:
        # Fall back to line parsing
        for line in _lines(stdout):
            if re.search(r"\[ANOMALY\]|\[NEW\]|\[MISSING\]|\[CHANGED\]", line, re.IGNORECASE):
                anomalies.append({"raw": line})

    result["anomalies"] = anomalies[:100]
    result["anomaly_count"] = len(anomalies)
    result["mode"] = mode
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
