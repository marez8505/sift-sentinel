# CLAUDE.md — Case Template

This file provides case-specific context to SIFT Sentinel.
Copy this file into your case working directory and fill in the fields below.

---

## Case Overview

| Field | Value |
|-------|-------|
| **Case ID** | CASE-XXXX |
| **Client** | |
| **Incident Declared** | YYYY-MM-DD |
| **Threat Actor** | Unknown / [Name if known] |
| **Your Role** | IR Analyst |
| **Case Working Dir** | /cases/XXXX/ |

---

## Evidence Files

| File | System | Type | Size | Notes |
|------|--------|------|------|-------|
| `/cases/XXXX/disk.E01` | hostname | Disk image (E01) | | |
| `/cases/XXXX/memory.img` | hostname | Memory capture | | |

**All evidence is read-only. Do NOT modify evidence files.**
**Write all output to** `./analysis/`, `./exports/`, or `./reports/` relative to the case working directory.

---

## Partition Offsets

Run `list_partitions` on each image, then record offsets here for reference:

| Image | Partition | Offset (sectors) | Filesystem |
|-------|-----------|-----------------|------------|
| disk.E01 | C: | TBD | NTFS |

---

## Network Topology

| Network | Subnet | Key Hosts |
|---------|--------|-----------|
| | | |

**External attacker IP:** Unknown

---

## Domain Accounts of Interest

| Account | Role |
|---------|------|
| | |

---

## Known / Suspected IOCs

### Confirmed Malware

| Indicator | Type | Detail |
|-----------|------|--------|
| | | |

### Attacker Activity

| Indicator | Detail |
|-----------|--------|
| | |

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| | Incident declared |

---

## Analysis Instructions

Run the full autonomous triage sequence using the SIFT Sentinel orchestrator:

```bash
python3 ~/.claude/agent/orchestrator.py \
  --case-dir /cases/XXXX \
  --evidence disk:/cases/XXXX/disk.E01 memory:/cases/XXXX/memory.img \
  --max-iterations 3 \
  --output-dir /cases/XXXX/analysis
```

Or run interactively with Claude Code (which will read this CLAUDE.md automatically):

```bash
cd /cases/XXXX
claude
```

---

## Notes

- Always report timestamps in UTC
- Use Vol3 at `/opt/volatility3-2.20.0/vol.py` — NOT `/usr/local/bin/vol.py` (that is Vol2)
- EZ Tools: `dotnet /opt/zimmermantools/<Tool>.dll`
- VSCMount is Windows-only — use TSK `mmls` + `icat` for VSS access on SIFT
