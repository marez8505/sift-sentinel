# SIFT Sentinel — Dataset Documentation

**Version:** 1.0  
**Builder:** Edward Marez ([@marez8505](https://github.com/marez8505))

---

## 1. Primary Test Dataset

### 1.1 Overview

SIFT Sentinel was primarily evaluated against the **SANS FOR508 Stark Research Labs (SRL)** dataset, which is distributed to students enrolled in SANS FOR508: "Advanced Incident Response, Threat Hunting, and Digital Forensics." This dataset represents a realistic APT intrusion by a simulated state-level threat actor (CRIMSON OSPREY) across a small corporate Active Directory environment.

The SRL dataset was chosen because:
1. It has documented ground truth — the course materials enumerate the complete IOC set, enabling precision/recall measurement
2. It represents realistic enterprise complexity (domain controller + workstation, both disk and memory images)
3. It is the de facto standard evaluation dataset for incident response training, familiar to judge-level DFIR practitioners
4. The Protocol SIFT repository includes case templates and CLAUDE.md files for the SRL scenario, confirming it as the intended evaluation environment for this hackathon

### 1.2 Evidence File Inventory

| Filename | Format | Size | Acquired System | Acquisition Method |
|---|---|---|---|---|
| base-dc-cdrive.E01 | EnCase E01 (segmented) | 12.5 GB | Domain Controller — C: drive | FTK Imager logical acquisition |
| base-rd01-cdrive.E01 | EnCase E01 (segmented) | 16.6 GB | RD01 Workstation — C: drive | FTK Imager logical acquisition |
| rd01-memory.img | Raw memory (flat) | 5 GB | RD01 Workstation — live memory | AVML / WinPMem |
| base-rd_memory.img | Raw memory (flat) | 3 GB | RD01 Workstation — baseline memory | AVML / WinPMem |
| base-dc_memory.img | Raw memory (flat) | 5 GB | Domain Controller — live memory | AVML / WinPMem |

**Total evidence volume:** ~42.1 GB  
**Case directory structure used in testing:**
```
/cases/srl/
├── disk/
│   ├── base-dc-cdrive.E01
│   └── base-rd01-cdrive.E01
└── memory/
    ├── rd01-memory.img
    ├── base-rd_memory.img
    └── base-dc_memory.img
```

### 1.3 Environment Details

| Property | Value |
|---|---|
| Domain | STARKRESEARCH.LOCAL |
| Domain Controller | DC01 (Windows Server 2019) |
| Compromised Workstation | RD01 (Windows 10 22H2) |
| Threat Actor | CRIMSON OSPREY (state-level APT designation) |
| Attack Type | Spear phishing → STUN.exe → lateral movement → domain persistence |
| Timeline | Compressed multi-day intrusion in lab environment |

### 1.4 Ground Truth IOC Set

The following IOCs are documented in the FOR508 course materials and were used as the reference set for accuracy measurement:

| IOC | Type | System | Source |
|---|---|---|---|
| STUN.exe at C:\Windows\System32\STUN.exe | Malicious binary | RD01 | Disk + memory |
| PID 1912 (STUN.exe) | Active process | RD01 memory | Memory |
| Parent PID 1244 (svchost.exe) for STUN.exe | Suspicious parent | RD01 memory | Memory |
| msedge.exe masquerading (7 instances) | Process masquerade | RD01 | Memory |
| Trojan:Win32/PowerRunner.A | AV classification | RD01 | Disk |
| pssdnsvc.exe | Suspicious service | RD01 | Disk + memory |
| net use H: \\172.16.6.12\c$\Users | SMB lateral movement command | RD01 | Memory (cmdline) |
| 172.15.1.20 | External attacker IP | RD01 | Memory + disk |
| Run key persistence for STUN.exe | Registry persistence | RD01 | Disk |
| Prefetch entry for STUN.exe | Execution evidence | RD01 | Disk |
| Shellbag entries for attacker filesystem navigation | Browsing evidence | RD01 | Disk |
| SRUM network activity correlation | Network persistence | RD01 | Disk |

### 1.5 Reproducibility

Judges who wish to reproduce results need:

1. **SANS FOR508 course enrollment** (required to access SRL lab data) OR use of the alternative public dataset described in Section 2
2. **SIFT Workstation OVA** — available free at [https://www.sans.org/tools/sift-workstation/](https://www.sans.org/tools/sift-workstation/)
3. **Protocol SIFT** — install via: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
4. **SIFT Sentinel** — install via: `git clone https://github.com/marez8505/sift-sentinel && bash install.sh`
5. **Anthropic API key** with Claude access

The `install.sh` script configures the MCP server, verifies evidence directory mounts, and downloads required Vol3 symbol tables for Windows 10 22H2 and Windows Server 2019.

---

## 2. Alternative Public Dataset (No License Restrictions)

Judges who do not have access to FOR508 materials can use the **NIST CFReDS (Computer Forensics Reference Data Sets)** project, which provides public domain disk images with documented ground truth.

**Dataset:** NIST CFReDS Hacking Case  
**URL:** [https://cfreds.nist.gov/all/NIST/HackingCase](https://cfreds.nist.gov/all/NIST/HackingCase)  
**License:** Public domain (U.S. government work)  
**Format:** DD raw image  
**Ground truth:** Documented in the CFReDS case notes (hacking scenario with known artifacts)

To run SIFT Sentinel against the NIST CFReDS image:

```bash
# Download image
wget https://cfreds-archive.nist.gov/[image-url] -O /cases/nist/hacking_case.dd

# Mount read-only
sudo mount -o ro,noatime /cases/nist/hacking_case.dd /mnt/nist

# Run agent
python3 agent/orchestrator.py \
  --case-dir /cases/nist \
  --evidence disk:/cases/nist/hacking_case.dd \
  --max-iterations 3
```

Note: The NIST CFReDS dataset does not include memory images. SIFT Sentinel will analyze disk artifacts only; memory analysis modules will be skipped and logged as `evidence_type_unavailable`.

**Other public datasets compatible with SIFT Sentinel:**

| Dataset | Source | Format | Has Memory |
|---|---|---|---|
| Digital Corpora M57-Patents scenario | [digitalcorpora.org](https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario) | E01 | No |
| DFRWS 2008 Challenge | [dfrws.org/dfrws-2008-challenge](https://www.dfrws.org/dfrws-2008-challenge/) | DD | Yes (partial) |
| NIST CFReDS Hacking Case | [cfreds.nist.gov](https://cfreds.nist.gov/all/NIST/HackingCase) | DD | No |

---

## 3. Data Handling and Privacy

The FOR508 SRL dataset is synthetic — all user accounts, hostnames, IP addresses, and file contents were created by SANS instructors for training purposes. There is no personally identifiable information or real organizational data in the evidence files.

SIFT Sentinel does not transmit evidence content to any external service. All analysis runs locally within the SIFT Workstation VM. The only external communication is to the Anthropic API (prompt text and tool call summaries — not raw evidence file content).

---

## 4. Vol3 Symbol Table Requirements

Memory analysis requires Volatility 3 ISF symbol tables matching the target OS:

| Evidence File | OS Version | Required Symbol Profile |
|---|---|---|
| rd01-memory.img | Windows 10 22H2 (19045) | windows.10.0.19045.*.json.xz |
| base-rd_memory.img | Windows 10 22H2 (19045) | windows.10.0.19045.*.json.xz |
| base-dc_memory.img | Windows Server 2019 (17763) | windows.10.0.17763.*.json.xz |

The `install.sh` script downloads the correct symbol tables from the Volatility Foundation's ISF server. If the target OS version differs, the MCP server will return a `{error: "missing_symbols", os_version: "...", resolution: "..."}` error and the orchestrator will queue a symbol download step before retrying.
