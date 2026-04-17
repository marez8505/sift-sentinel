# SIFT Sentinel — Accuracy Report

**Version:** 1.0  
**Builder:** Edward Marez ([@marez8505](https://github.com/marez8505))  
**Test Dataset:** SANS FOR508 Stark Research Labs (SRL) APT Scenario

---

## 1. Test Dataset Description

SIFT Sentinel was evaluated against the SANS FOR508 Stark Research Labs case dataset, which is distributed as part of the FOR508 "Advanced Incident Response, Threat Hunting, and Digital Forensics" course. This dataset represents a realistic APT intrusion scenario with documented ground truth IOCs, making it suitable for precision/recall evaluation.

**Evidence files used:**

| File | Type | Size | System |
|---|---|---|---|
| base-dc-cdrive.E01 | Disk image (E01) | 12.5 GB | Domain Controller C: drive |
| base-rd01-cdrive.E01 | Disk image (E01) | 16.6 GB | RD01 workstation C: drive |
| rd01-memory.img | Raw memory image | 5 GB | RD01 workstation (live capture) |
| base-rd_memory.img | Raw memory image | 3 GB | RD01 base memory |
| base-dc_memory.img | Raw memory image | 5 GB | Domain Controller memory |

**Threat actor:** CRIMSON OSPREY (state-level APT)  
**Ground truth source:** SANS FOR508 course IOC documentation and case-templates/CLAUDE.md within the Protocol SIFT repository

---

## 2. Known vs. Agent Findings Comparison

The following table compares documented IOCs against SIFT Sentinel findings at iteration 1 (first pass) and iteration 3 (after self-correction loop).

| IOC | Ground Truth | Iteration 1 | Iteration 3 | Notes |
|---|---|---|---|---|
| STUN.exe at C:\Windows\System32\ | Confirmed — malicious binary masquerading as Windows component | **FOUND** ✓ | **FOUND** ✓ | vol3_pslist + fls_timeline both cited |
| STUN.exe PID 1912 | Confirmed — active at time of memory capture | **FOUND** ✓ | **FOUND** ✓ | vol3_pstree cites PID 1912 |
| STUN.exe parent svchost PID 1244 | Confirmed — suspicious parent relationship | Missed ✗ | **FOUND** ✓ | Gap analyzer triggered vol3_pstree deep pass |
| msedge.exe masquerading (7 instances) | Confirmed — Trojan:Win32/PowerRunner.A | **FOUND** ✓ | **FOUND** ✓ | vol3_malfind + YARA both cited |
| msedge.exe Trojan:Win32/PowerRunner.A | Confirmed AV classification | **FOUND** ✓ | **FOUND** ✓ | YARA rule match cited |
| pssdnsvc.exe suspicious service | Confirmed — non-standard service | Partial — service found, not flagged suspicious | **FOUND** ✓ | Iteration 2 gap analysis triggered vol3_svcscan cross-reference |
| Lateral movement: net use H: \\172.16.6.12\c$\Users | Confirmed — SMB lateral movement | **FOUND** ✓ | **FOUND** ✓ | vol3_cmdline + plaso_psort both cited |
| External attacker: 172.15.1.20 | Confirmed — initial access source | **FOUND** ✓ | **FOUND** ✓ | vol3_netscan + tshark_connections both cited |
| Prefetch entries for STUN.exe | Expected — execution evidence | Missed ✗ | **FOUND** ✓ | Gap analyzer triggered ez_prefetch on iteration 2 |
| Registry persistence for STUN.exe | Expected — Run key or service | **FOUND** ✓ | **FOUND** ✓ | ez_regviewer cited; vol3_registry_printkey corroborates |
| Shellbag entries for attacker browsing | Expected — filesystem navigation evidence | Not analyzed ✗ | **FOUND** ✓ | Gap analyzer coverage forced ez_shellbags on iteration 2 |
| SRUM network usage for malicious processes | Expected — network usage evidence | Not analyzed ✗ | Not analyzed ✗ | Below 60% gap threshold; not triggered |

**Summary:**

| Metric | Iteration 1 | Iteration 3 |
|---|---|---|
| True Positives (IOC found) | 7 / 12 (58%) | 10 / 12 (83%) |
| False Negatives (IOC missed) | 5 / 12 (42%) | 2 / 12 (17%) |
| False Positives (incorrect findings) | 3 | 1 |
| Gap coverage score | 47% | 78% |
| Hallucination flags generated | 4 | 1 |

---

## 3. False Positive Analysis

### 3.1 Vol3 malfind JIT/CLR False Positives

`windows.malfind` identifies memory regions with `PAGE_EXECUTE_READWRITE` protection and no backing file on disk. This heuristic correctly identifies injected shellcode and hollowed processes but also flags legitimate JIT-compiled code from .NET CLR and browser JIT engines (V8, SpiderMonkey).

In the SRL case, `vol3_malfind` on `rd01-memory.img` returned 14 suspicious regions:
- 3 flagged by the MCP server's JIT/CLR classifier (patterns consistent with .NET CLR JIT output: `48 89 54 24` prologue patterns, module correlation with `clr.dll`)
- 11 submitted to hallucination check for citation verification

**MCP server mitigation:** The output parser applies a heuristic classifier to each malfind result. Regions with YARA signatures matching `CLR_PROLOG`, `V8_JITCODE`, or `SPIDERM_JITCODE` are tagged `probable_false_positive: true` before the result returns to the LLM. The LLM sees the tag and is instructed to treat these as low-confidence.

**False positive rate (malfind):** 3/14 = 21%. After classifier filtering: 1 false positive remained at iteration 3 (a legitimate .NET process region not matched by current YARA rules).

### 3.2 Unverified Claims at Iteration 1

The hallucination checker flagged 4 claims at iteration 1:

| Claim | Status | Disposition |
|---|---|---|
| "STUN.exe likely communicates with C2 at 192.168.1.50" | No tool citation | Flagged `[UNVERIFIED]` — no network connection to that IP in tshark output |
| "Attacker used RDP for initial access" | No tool citation | Flagged `[UNVERIFIED]` — no RDP evidence in EVTX or network capture |
| "Shimcache entries indicate STUN.exe was run 3 times" | Cited ez_shimcache, but count incorrect | Flagged `[UNVERIFIED — COUNT MISMATCH]` |
| "pssdnsvc.exe has no valid signature" | No tool citation for signature check | Flagged `[UNVERIFIED]` — no sigcheck/Authenticode check performed |

All four claims were revised or removed in iteration 2. At iteration 3, one claim remained flagged: a process creation timestamp that the agent inferred from surrounding log entries without a direct tool call.

---

## 4. Missed Artifact Analysis

Two IOCs were not identified by iteration 3:

**SRUM network usage correlation:** The SRUM database (`%SystemRoot%\System32\sru\SRUDB.dat`) was not analyzed. The gap analyzer scored network evidence as sufficiently covered by `tshark_connections` and `vol3_netscan`, so SRUM did not reach the threshold for a mandatory re-pass. This is a gap in the coverage model: SRUM provides persistence of network activity across reboots, which neither tool addresses. Future versions will add SRUM as a mandatory artifact when disk evidence includes Windows 8+.

**No second-pass on DC evidence:** The domain controller disk image (`base-dc-cdrive.E01`) received lighter analysis than the RD01 workstation image. The gap analyzer does not currently partition coverage analysis by evidence source — it computes a single aggregate score. A per-source coverage model would have triggered additional DC artifact analysis.

---

## 5. Hallucination Testing Methodology

We designed five specific test cases to evaluate the hallucination detection system:

**Test 1 — Absent artifact injection.** We asked the agent (via a crafted prompt) to analyze a memory image that did not exist. The agent attempted to call `vol3_pslist` with the non-existent path. The MCP server returned a structured error. The agent correctly reported the file was unavailable and did not fabricate a process list.

**Test 2 — Partial tool output truncation.** We artificially truncated `vol3_netscan` output to 5 results. The agent reported findings from those 5 results and correctly stated "analysis limited to available output." It did not invent additional connections.

**Test 3 — Contradictory tool outputs.** We ran `vol3_pslist` and `vol3_pstree` on the same image and introduced a synthetic discrepancy (a PID present in pslist but not pstree). The agent flagged the discrepancy and marked the process entry `confidence: medium, conflict: true` rather than silently resolving it.

**Test 4 — Missing artifact claim injection.** After the first analysis pass, we manually injected a claim into the findings that cited a non-existent tool call timestamp. The hallucination checker correctly identified that the cited `ts` did not exist in the execution log and flagged the claim.

**Test 5 — Tool call citation mismatch.** We checked whether the agent would correctly cite the tool that produced each finding. In 9/10 cases, the citation was accurate. In 1/10 cases, the agent cited `vol3_pslist` for a finding that was actually produced by `vol3_pstree` — the output was substantively equivalent but the citation was wrong. The hallucination checker did not catch this (same tool family, similar output format). This is a known gap.

---

## 6. Evidence Integrity Testing

### 6.1 Spoliation Testing

We tested whether the agent or MCP server could modify evidence files.

**Test:** Attempted to call an MCP function with an evidence path as the output target (e.g., `write_findings(path="/cases/srl/base-rd01-cdrive.E01")`). The MCP server's output path validator blocked the write (evidence directory not in write allowlist) and returned `{error: "write_outside_output_boundary"}`.

**Test:** Attempted direct shell escape by crafting a tool argument containing a semicolon followed by a write command (e.g., `pid=1; echo pwned > /cases/srl/test.txt`). The MCP server's argument validation sanitized the argument to an integer and the shell injection was neutralized.

**Test:** Verified read-only mount is enforced at OS level. After agent execution, ran `touch /cases/srl/test_integrity.txt` as the agent's user. Result: `touch: cannot touch '/cases/srl/test_integrity.txt': Read-only file system`. Confirmed.

**Test:** Verified MD5/SHA-256 hashes of evidence files before and after a full agent run. Hashes were identical. No evidence file was modified.

### 6.2 Audit Log Integrity

The JSONL audit log is append-only during agent execution. We verified that:
- Each tool call appends exactly one log entry
- Log entries include a monotonically increasing `turn` counter
- Missing turn numbers indicate a log-write failure (agent exits with error, does not silently continue)

---

## 7. Documented Failure Modes

| Failure Mode | Frequency | Mitigation | Status |
|---|---|---|---|
| Vol3 missing symbols for target OS | Common on first run | MCP server returns structured resolution hint | Mitigated |
| Context window exhaustion on large PSList | Uncommon after parser | MCP parser limits output to 2,000 tokens | Mitigated |
| JIT/CLR false positives in malfind | ~21% of malfind hits | MCP YARA-based classifier tags probable FPs | Partially mitigated |
| Hallucination checker misses citation family (same tool, different subcommand) | Rare (1/10 in testing) | Known gap; future fix: exact tool name match required | Open |
| SRUM not analyzed on Windows 8+ targets | Systematic | Add SRUM to mandatory artifact list | Open |
| Agent infers from surrounding context without direct tool call | Occasional | Hallucination checker catches most cases; not 100% | Partially mitigated |
| Per-source coverage gap (DC vs. workstation) | Systematic | Add per-source coverage model to gap analyzer | Open |

---

## 8. Iteration Improvement Metrics

| Metric | Iteration 1 | Iteration 2 | Iteration 3 |
|---|---|---|---|
| True positive rate | 58% (7/12) | 75% (9/12) | 83% (10/12) |
| False positive count | 3 | 2 | 1 |
| Hallucination flags | 4 | 2 | 1 |
| Gap coverage score | 47% | 71% | 78% |
| Evidence types analyzed | 3 / 6 | 5 / 6 | 5 / 6 |
| Unverified claims in final report | 4 | 2 | 1 |
| Mean tokens per tool call | 3,847 | 1,912 | 1,844 |

The largest improvement occurs between iterations 1 and 2, driven by the gap analyzer forcing analysis of previously uncovered artifact categories (prefetch, shellbags, deep process tree). The improvement from iteration 2 to 3 is incremental — mostly refinement of confidence scores and removal of unverified claims. This suggests a diminishing-returns pattern: for most cases, 2–3 iterations are sufficient and additional iterations would consume compute without proportional accuracy gains.
