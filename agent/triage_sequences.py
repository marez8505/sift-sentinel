"""
triage_sequences.py — Senior analyst playbooks for DFIR evidence triage.

Each sequence represents the ordered set of analysis steps that a skilled
DFIR analyst would execute against a given evidence type. These drive the
autonomous agent's investigation loop and self-correction logic.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Core triage sequences per evidence type
# ---------------------------------------------------------------------------

TRIAGE_SEQUENCES: dict[str, list[str]] = {
    "disk": [
        "1. Verify image integrity (md5sum / sha256sum + ewfinfo for E01 containers).",
        "2. List partitions and identify volume offsets (mmls, fdisk -l).",
        "3. Mount image read-only (ewfmount / affuse + mount -o ro,loop,offset=...).",
        "4. Run filesystem triage with fls — enumerate suspicious files in "
        "System32, Users, Temp, AppData, ProgramData, and recycle bin.",
        "5. Extract and parse MFT with MFTECmd or analyzeMFT — surface files "
        "created/modified/accessed within 90 days of the reported incident date.",
        "6. Parse Shimcache (AppCompatCache) and Amcache.hve for execution evidence "
        "— note last-modified timestamps and full executable paths.",
        "7. Parse Windows Event Logs (EVTX) using evtx_dump or python-evtx:\n"
        "   - Security: 4624 (logon), 4625 (failed logon), 4648 (explicit creds), "
        "4688 (process creation), 4720/4726 (account create/delete), 4732/4733 (group change)\n"
        "   - System: 7045 (new service installed), 7034/7036 (service state changes)\n"
        "   - TaskScheduler/Operational: 106 (task registered), 200/201 (task run/complete)\n"
        "   - Microsoft-Windows-Windows Defender/Operational: 1116 (malware detected), "
        "1117 (action taken), 1118/1119 (remediation)",
        "8. Parse registry hives with RECmd using the Kroll batch file:\n"
        "   - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/RunOnce\n"
        "   - HKLM\\SYSTEM\\CurrentControlSet\\Services (detect malicious services)\n"
        "   - HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\n"
        "   - User NTUSER.DAT: Run, RunOnce, RecentDocs, UserAssist, MuiCache, WordWheelQuery",
        "9. Run YARA against System32, Temp, AppData\\Roaming, and ProgramData directories "
        "(use standard malware + webshell rule sets).",
        "10. Generate super-timeline with Plaso (log2timeline.py) if image is under 50 GB; "
        "otherwise generate targeted timeline using mactime on selected directories.",
        "11. Cross-reference all findings into a unified artifact table: process → binary on "
        "disk → registry persistence → event log entry → timeline entry.",
    ],

    "memory": [
        "1. Run windows.psscan AND windows.pslist — diff output to identify hidden/unlinked "
        "processes (present in psscan but absent from pslist).",
        "2. Analyze parent-child relationships with windows.pstree — flag LOLBins "
        "(cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe, regsvr32.exe, "
        "certutil.exe, bitsadmin.exe) spawned from unexpected parents (e.g., svchost, "
        "Word, Excel, browser).",
        "3. Examine command lines for every process with windows.cmdline — flag:\n"
        "   - Base64-encoded blobs (-EncodedCommand, [Convert]::FromBase64)\n"
        "   - Download cradles (DownloadString, WebClient, iex, Invoke-Expression)\n"
        "   - Unusual working directories or UNC paths\n"
        "   - Pipe-delimited execution chains",
        "4. Run windows.netscan AND windows.netstat — extract all unique external IPs/ports; "
        "flag connections to non-standard ports (not 80/443/53) and loopback listeners.",
        "5. Run windows.svcscan — flag services whose binary path is NOT in "
        "C:\\Windows\\System32 or C:\\Windows\\SysWOW64, or that use DCOM/netsvcs hosting.",
        "6. Run windows.malfind — identify memory regions with RWX permissions containing "
        "PE headers or shellcode; dump top 10 hits to disk for further analysis.",
        "7. Run windows.registry.hivelist to enumerate loaded hives, then "
        "windows.registry.printkey on:\n"
        "   - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "   - HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "8. Run windows.dlllist for processes flagged in steps 1–6 — identify injected or "
        "anomalous DLLs (wrong path, no disk backing, unsigned).",
        "9. Correlate: any process showing suspicious cmdline AND active network connection "
        "AND malfind hit = HIGH CONFIDENCE IOC — escalate immediately.",
        "10. If a memory baseline is available, run memory-baseliner to diff against known "
        "good state and highlight deviations.",
    ],

    "disk+memory": [
        "Cross-reference disk artifacts with live memory state to detect advanced evasion:",
        "1. Process binary verification: for each memory process, confirm the binary path "
        "exists on disk; compute hash and compare against known-good (VirusTotal / NSRL).",
        "2. Network correlation: match memory netscan connections against firewall/proxy logs "
        "on disk — identify connections absent from disk logs (potential log tampering).",
        "3. Service reconciliation: compare windows.svcscan output against SYSTEM\\Services "
        "registry hive on disk — unregistered in-memory services indicate malware.",
        "4. Timeline correlation: overlay MFT MAC times against memory process creation "
        "timestamps — detect timestomping (MFT birth time newer than first-seen-in-memory).",
        "5. Process hollowing detection: for malfind hits, check if the in-memory PE hash "
        "differs from the on-disk binary hash at the same path.",
        "6. Prefetch cross-check: correlate Prefetch execution counts/timestamps with memory "
        "process start times — mismatches suggest process injection or masquerading.",
        "7. User-space hook detection: compare IAT entries for key system DLLs in memory "
        "against their on-disk counterparts (detect API hooking).",
    ],

    "pcap": [
        "1. Get high-level protocol distribution and top-N talkers (capinfos, tshark -qz io,phs).",
        "2. Extract and analyse DNS queries (tshark -Y dns):\n"
        "   - Flag high-entropy domain names (DGA patterns: random-looking, long labels)\n"
        "   - Flag DNS over non-standard ports\n"
        "   - Flag newly-registered or low-prevalence TLDs\n"
        "   - Count unique subdomains per apex — high count may indicate DNS tunnelling",
        "3. Extract all HTTP/HTTPS connections (tshark -Y http):\n"
        "   - Flag long-duration sessions (potential C2 keep-alive)\n"
        "   - Detect beaconing: connections to the same host at suspiciously regular "
        "intervals (compute inter-arrival time statistics)\n"
        "   - Flag non-standard or spoofed User-Agent strings\n"
        "   - Identify large data transfers (exfiltration candidates)",
        "4. C2 pattern analysis:\n"
        "   - Periodic connections with uniform byte counts suggest automated C2\n"
        "   - JA3/JA3S fingerprinting of TLS sessions (zeek or ja3 tool)\n"
        "   - Flag certificate anomalies: self-signed, mismatched CN, short validity",
        "5. File carving with bulk_extractor or NetworkMiner — extract transferred "
        "executables, documents, archives, and credentials.",
        "6. Cross-reference all observed IPs against threat intel feeds "
        "(abuse.ch Feodo, Emerging Threats, internal blocklists).",
    ],

    "logs": [
        "1. Identify log format (syslog, JSON, CEF, W3C) and determine full time range.",
        "2. Parse authentication events:\n"
        "   - Compute success/failure ratio per source IP and username\n"
        "   - Flag accounts with >10 failures in 60 seconds (brute force)\n"
        "   - Flag password spray: many accounts from single source with low per-account failures",
        "3. Identify source IPs with multiple failed authentication events across different "
        "accounts — cluster by subnet and time window.",
        "4. Privilege escalation sequences:\n"
        "   - sudo usage followed by sensitive file access\n"
        "   - Token impersonation events (Windows: 4624 type 3 → 4648 → admin action)\n"
        "   - Group membership changes (4732) followed by privileged operations",
        "5. Lateral movement detection:\n"
        "   - Single source IP authenticating to multiple internal hosts within short window\n"
        "   - SMB/WMI/RDP connections from workstation-class hosts to other workstations\n"
        "   - Pass-the-hash indicators: NTLM auth with mismatched account context",
        "6. Data exfiltration indicators:\n"
        "   - Large outbound transfers at unusual hours\n"
        "   - Archive creation followed by transfer events\n"
        "   - Cloud storage upload events (OneDrive, Dropbox, S3) from endpoints",
    ],

    "dir": [
        "1. Enumerate directory structure to three levels deep (ls -laR or find).",
        "2. Identify recently modified files (find . -newer reference_file -type f).",
        "3. Compute hashes of all executables and scripts (find . -executable -type f).",
        "4. Check for hidden files and directories (ls -la | grep '^\\.').",
        "5. Identify world-writable directories and SUID/SGID binaries on Linux.",
        "6. Review shell history files (.bash_history, .zsh_history, PowerShell history).",
        "7. Run YARA against all files.",
    ],
}

# ---------------------------------------------------------------------------
# Analyst heuristics — red flags to check across all evidence types
# ---------------------------------------------------------------------------

ANALYST_HEURISTICS: dict[str, list[str]] = {
    "process_anomalies": [
        "svchost.exe NOT hosted by services.exe or wininit.exe",
        "lsass.exe with child processes",
        "explorer.exe spawned from cmd.exe, powershell.exe, or a browser",
        "services.exe with network connections",
        "csrss.exe or smss.exe with non-SYSTEM integrity",
        "Multiple instances of single-instance processes (lsass, lsm, winlogon)",
        "Process name matches system binary name but wrong path (e.g., svchost.exe in Temp)",
        "Process with blank or single-space name",
        "Base64 or hex-encoded command line arguments",
        "PowerShell with -EncodedCommand, -NonInteractive, -WindowStyle Hidden",
        "cmd.exe /c with long argument string containing pipes",
        "mshta.exe, regsvr32.exe, or rundll32.exe calling remote URL",
        "wscript.exe or cscript.exe in AppData or Temp",
        "certutil.exe with -urlcache -f or -decode flags",
        "bitsadmin.exe /transfer to external host",
    ],

    "network_anomalies": [
        "Connections to IP addresses (not hostnames) on port 80 or 443",
        "Periodic beaconing: same host/port contacted at regular intervals",
        "Large outbound transfers to cloud storage or residential IPs",
        "DNS queries for high-entropy domains (Shannon entropy > 3.5)",
        "DNS TXT record queries (common in DNS tunnelling)",
        "Non-browser process making HTTPS connections",
        "Process connecting to Tor exit nodes or known C2 infrastructure",
        "Connections on unusual high ports (>49152) to external hosts",
        "ICMP with unusually large payload (covert channel)",
        "UDP port 53 to non-corporate DNS servers",
        "Internal host connecting to multiple other internal hosts via SMB/RDP (lateral movement)",
        "RDP to non-standard port (not 3389)",
    ],

    "persistence_mechanisms": [
        "Registry Run/RunOnce keys with LOLBin or script interpreter",
        "New service pointing to binary outside System32/SysWOW64",
        "Scheduled task with randomised name and encoded action",
        "Startup folder entry (C:\\Users\\...\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)",
        "WMI event subscription (permanent subscriptions in root\\subscription)",
        "AppInit_DLLs, AppCertDlls registry keys",
        "Browser extension with unusual permissions or non-store source",
        "COM object hijacking (HKCU\\Software\\Classes\\CLSID with user-writable path)",
        "Image File Execution Options debugger key (IFEO hijack)",
        "Netsh helper DLL persistence",
        "Time provider DLL (HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders)",
        "LSA notification package or security package DLL injection",
        "Bootkit / MBR modification (compare MBR hash against known-good)",
    ],

    "timestomping_indicators": [
        "MFT $STANDARD_INFORMATION created timestamp is NEWER than $FILE_NAME created timestamp",
        "File modified time (M) is earlier than created time (B) in $STANDARD_INFORMATION",
        "MFT entry sequence number inconsistent with timestamp ordering of adjacent entries",
        "Shimcache/Prefetch last-run timestamp predates MFT modified timestamp",
        "Identical timestamps (all four MAC times equal) for a large number of files",
        "Timestamp in the future (greater than incident date)",
        "PE compile timestamp in embedded binary is far earlier than surrounding files",
    ],

    "lateral_movement_indicators": [
        "Authentication event 4648 (explicit credential use) from workstation to server",
        "Logon type 3 (network) or type 10 (remote interactive) from unexpected source",
        "PsExec artefacts: PSEXESVC service creation + admin$ share access",
        "WMI lateral movement: wmiprvse.exe spawning cmd.exe or powershell.exe",
        "DCOM lateral movement: mmc.exe or dllhost.exe spawning shell",
        "SMB admin share access (\\\\host\\ADMIN$, \\\\host\\C$) from workstation",
        "RDP session originating from another internal workstation (not jump server)",
        "Scheduled task created remotely (via at.exe or schtasks /s <remote>)",
        "Token impersonation followed by network access",
        "Pass-the-hash: NTLM authentication where source and target are workstations",
        "Kerberoasting: large number of TGS requests for service accounts",
        "DCSync: domain controller queried via DRSUAPI from non-DC host",
    ],
}

# ---------------------------------------------------------------------------
# Mapping: evidence type → minimum required analysis steps for gap detection
# ---------------------------------------------------------------------------

REQUIRED_ANALYSIS_STEPS: dict[str, list[str]] = {
    "disk": [
        "mft_parsed",
        "registry_parsed",
        "event_logs_parsed",
        "shimcache_parsed",
        "yara_run",
    ],
    "memory": [
        "pslist_run",
        "psscan_run",
        "cmdline_run",
        "netscan_run",
        "malfind_run",
        "svcscan_run",
    ],
    "pcap": [
        "protocol_distribution",
        "dns_analysis",
        "http_analysis",
        "c2_beacon_check",
    ],
    "logs": [
        "auth_events_parsed",
        "lateral_movement_checked",
        "privilege_escalation_checked",
    ],
    "dir": [
        "directory_enumerated",
        "hashes_computed",
        "yara_run",
    ],
}

# ---------------------------------------------------------------------------
# Gap → remediation mapping: what to do when a gap is detected
# ---------------------------------------------------------------------------

GAP_REMEDIATION: dict[str, str] = {
    "mft_parsed": "Parse the Master File Table using MFTECmd to identify recently created/modified files.",
    "registry_parsed": "Run RECmd with the Kroll batch file against all user and system hives.",
    "event_logs_parsed": "Extract and parse EVTX files with evtx_dump; focus on Security, System, and TaskScheduler channels.",
    "shimcache_parsed": "Parse AppCompatCache from SYSTEM hive to recover execution evidence.",
    "yara_run": "Run YARA with standard malware/webshell ruleset against executable locations.",
    "pslist_run": "Run volatility3 windows.pslist to enumerate running processes.",
    "psscan_run": "Run volatility3 windows.psscan to detect hidden/unlinked processes.",
    "cmdline_run": "Run volatility3 windows.cmdline to inspect process arguments for encoded payloads.",
    "netscan_run": "Run volatility3 windows.netscan to enumerate network connections.",
    "malfind_run": "Run volatility3 windows.malfind to identify injected code regions.",
    "svcscan_run": "Run volatility3 windows.svcscan to find rogue services.",
    "protocol_distribution": "Run tshark -qz io,phs to get protocol breakdown.",
    "dns_analysis": "Extract DNS queries with tshark -Y dns and check for DGA/tunnelling.",
    "http_analysis": "Extract HTTP streams; look for beaconing intervals and unusual User-Agents.",
    "c2_beacon_check": "Compute inter-arrival times for external connections to identify automated C2.",
    "auth_events_parsed": "Filter log entries for authentication success and failure events.",
    "lateral_movement_checked": "Check for single-source multi-target authentication patterns.",
    "privilege_escalation_checked": "Look for sudo/UAC bypass sequences and group membership changes.",
    "directory_enumerated": "Run find / ls -laR to map directory contents.",
    "hashes_computed": "Compute SHA-256 hashes for all executables and scripts.",
    "disk_memory_correlation": "Cross-reference memory process list with disk binary paths and hashes.",
    "network_process_correlation": "Link network connections back to responsible processes.",
    "persistence_checked": "Check all known persistence locations (Run keys, services, tasks, startup).",
    "timeline_generated": "Generate a MAC-time timeline covering the incident window.",
    "ioc_enrichment": "Enrich discovered IPs and hashes against threat intelligence feeds.",
}
