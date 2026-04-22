# SIFT Sentinel — Demo Video Script
**Hackathon:** SANS Find Evil! (findevil.devpost.com)  
**Builder:** Edward Marez, Austin Community College  
**Target duration:** 5 minutes (~750 spoken words)  
**Format:** Live terminal narration, SIFT Workstation (Ubuntu VM in VMware)

---

## SECTION 1 — Hook and Problem Statement

**[0:00]**

> **[VIEWER SEES]** SIFT Workstation desktop. Open terminal, clean prompt.

> **[SAY]** DFIR triage has a trust problem. You can drop an LLM into a terminal and watch it call Volatility — but when it hands you a findings report, can you verify every claim traces back to an actual tool execution? And are you certain it hasn't quietly deleted or exfiltrated anything while it worked?

> **[SAY]** SIFT Sentinel solves both. It's a custom MCP server plus a self-correcting triage agent built on Protocol SIFT. The agent physically cannot destroy evidence — not because the system prompt says so, but because the destructive functions don't exist in the server. And every finding in the output report cites the exact tool call that produced it.

> **[SAY]** Let me show you.

---

## SECTION 2 — Installation

**[0:35]**

> **[VIEWER SEES]** Terminal. Full-screen, 14pt font.

> **[SAY]** One-command install on any SIFT Workstation.

```bash
git clone https://github.com/marez8505/sift-sentinel.git
cd sift-sentinel
bash install.sh
```

> **[SAY]** The install script registers the MCP server with Claude Code's config, verifies Volatility 3 symbol tables, and mounts the evidence partition read-only. That mount happens at the OS level — before the agent process ever starts.

> **[CAMERA NOTE]** Stay on terminal output as install.sh runs. Pause briefly when it prints "Evidence mounted -o ro,noatime."

---

## SECTION 3 — Case Briefing and Agent Launch

**[1:10]**

> **[VIEWER SEES]** Terminal. Evidence directory listing shown briefly.

> **[SAY]** The case is a suspected lateral movement incident. We have a full disk image of the Windows workstation and a memory capture taken at the time of the alert. I'm pointing the orchestrator at both.

```bash
python3 ~/.claude/agent/orchestrator.py \
    --case-dir /cases/srl \
    --evidence disk:/cases/srl/base-rd01-cdrive.E01 \
                memory:/cases/memory/rd01-memory.img \
    --max-iterations 3
```

> **[SAY]** Three iterations maximum, hard ceiling enforced in Python — the agent cannot reason past it. Watch the orchestrator output.

> **[VIEWER SEES]** Orchestrator begins printing iteration headers and MCP tool call events as it runs.

> **[SAY]** The agent is now calling the MCP server. Each call goes through path validation, runs the SIFT tool as a read-only subprocess, and gets back structured JSON — not raw terminal output. A single `vol3_pslist` call returns a typed array of process objects, not four hundred lines of text. That's how we keep the context window from blowing out.

---

## SECTION 4 — Live Findings (Iteration 1)

**[2:00]**

> **[VIEWER SEES]** Orchestrator printing tool call events. Iteration 1 progress.

> **[SAY]** Iteration one is running memory analysis first. The agent calls `vol3_pstree` and immediately flags something.

> **[CAMERA NOTE]** Zoom or highlight the terminal line when it prints the STUN.exe finding.

> **[VIEWER SEES]** Terminal output line: `[FINDING] STUN.exe PID 1912 — parent svchost PID 1244 — suspicious masquerading at C:\Windows\System32`

> **[SAY]** STUN.exe at `C:\Windows\System32`, parent process svchost. That's a masquerading indicator — legitimate STUN protocol tooling doesn't live there. PID 1912, parent 1244. The agent traces the process tree automatically, no prompt required.

> **[SAY]** `vol3_malfind` runs next. Seven instances of msedge.exe come back flagged with suspicious memory regions. The agent notes those and continues — it won't stop on the first hit.

> **[SAY]** On the disk side, `ez_prefetch` pulls `pssdnsvc.exe` from the Prefetch directory — a service binary at a non-standard path, not under System32 or SysWOW64. Persistence candidate.

> **[SAY]** And on the network side, `vol3_netscan` finds the lateral movement: `net use H: \\172.16.6.12\c$\Users` — the attacker is mapping shares to an internal host. The session originates from external IP 172.15.1.20.

---

## SECTION 5 — Self-Correction Sequence

**[3:05]**

> **[VIEWER SEES]** Orchestrator prints the gap analysis block after iteration 1 completes.

> **[SAY]** This is the part that matters most to defenders. After iteration one, the orchestrator runs the gap analyzer. It compares the evidence types that were ingested against the evidence types that were actually analyzed.

> **[CAMERA NOTE]** Highlight or zoom on the "Gaps identified" output block.

> **[VIEWER SEES]** Terminal output:
> ```
> [GAP ANALYZER] Coverage: 48% — below 60% threshold
> Gaps identified:
>   [DISK] MISSING: yara_run, ez_shimcache, ez_amcache
>   [MEMORY] MISSING: vol3_svcscan, vol3_ldrmodules
> Triggering iteration 2 — mandatory gap-fill scope
> ```

> **[SAY]** Forty-eight percent coverage. That's below the sixty-percent threshold, so the orchestrator builds a targeted mandate and re-enters the loop. The second pass is not a generic "check your work" — it has a specific list of artifact categories it must cover.

> **[SAY]** Watch the finding count change.

> **[VIEWER SEES]** Orchestrator running iteration 2. Tool calls printing for svcscan, shimcache, amcache.

> **[SAY]** Iteration two pulls shimcache and amcache entries for pssdnsvc.exe — confirming execution, not just prefetch presence. `vol3_svcscan` catches the suspicious service registration in memory. The finding count climbs.

> **[CAMERA NOTE]** Show both JSON files side by side or in sequence — findings_1.json vs findings_2.json.

```bash
# findings after iteration 1
cat /cases/srl/analysis/findings_1.json | python3 -m json.tool | grep '"finding"' | wc -l
# findings after iteration 2
cat /cases/srl/analysis/findings_2.json | python3 -m json.tool | grep '"finding"' | wc -l
```

> **[SAY]** Eleven findings after pass one. Seventeen after pass two. The self-correction loop isn't cosmetic — it finds things the first pass missed.

---

## SECTION 6 — Audit Trail

**[4:00]**

> **[VIEWER SEES]** Terminal. Outputs of cat commands.

> **[SAY]** Two output files. First, the findings.

```bash
cat /cases/srl/analysis/findings_final.json | python3 -m json.tool | head -60
```

> **[SAY]** Every finding has an `evidence_chain` block — the tool name, timestamp, and exact arguments that produced it. Any judge can trace STUN.exe back to `vol3_pstree` at a specific timestamp in iteration one.

```bash
cat /cases/srl/analysis/execution_log.jsonl | head -20
```

> **[SAY]** The JSONL audit log records every tool call: timestamp, iteration, turn number, arguments, token counts, duration. This is not a summary — it's a machine-readable chain of custody.

> **[SAY]** Claims that couldn't be traced to a tool call are flagged `[UNVERIFIED]` by the hallucination checker. They appear in the report but with `confidence: low`. You know exactly what the agent is certain about and what it inferred.

---

## SECTION 7 — HTML Report

**[4:30]**

> **[VIEWER SEES]** Firefox opens the HTML report.

```bash
firefox /cases/srl/reports/final_report.html
```

> **[SAY]** The HTML report groups findings by MITRE ATT&CK technique, separates confirmed from inferred findings, and renders each evidence chain as a collapsible section. Scroll into any finding and you see the exact tool call that backs it.

> **[CAMERA NOTE]** Click to expand the STUN.exe evidence chain in the browser.

---

## SECTION 8 — Architecture Close

**[4:45]**

> **[VIEWER SEES]** Terminal. Brief view of sift_mcp_server.py function list (grep output or quick scroll).

> **[SAY]** One last thing. Here's what the MCP server does not have: no `rm`, no `dd`, no `wget`, no `curl`, no `ssh`. Run `grep -E "def tool_" sift_mcp_server.py` right now. The destructive functions are not registered. The agent cannot call what doesn't exist. That's an architectural guarantee, not a prompt instruction.

> **[SAY]** SIFT Sentinel. Autonomous triage with a verifiable chain of custody and guardrails you can read in the source code. Link in the description.

**[5:00] — END**

---

## Word Count Reference

| Section | Approx. Words | Cumulative |
|---|---|---|
| 1 — Hook | 100 | 100 |
| 2 — Installation | 65 | 165 |
| 3 — Launch | 105 | 270 |
| 4 — Live Findings | 120 | 390 |
| 5 — Self-Correction | 165 | 555 |
| 6 — Audit Trail | 100 | 655 |
| 7 — HTML Report | 55 | 710 |
| 8 — Architecture Close | 75 | 785 |

**Total: ~785 spoken words** — approximately 5 minutes at 155–160 wpm.

---

## Production Notes

- Record at 1920×1080. Font size ≥ 14pt in terminal for readability at 1080p.
- Use `tmux` or split panes if showing two files side by side in Section 5.
- The gap analyzer output block in Section 5 is the demo's narrative apex — pause narration briefly and let the viewer read the terminal before continuing.
- If Volatility symbol tables are not pre-cached, the first tool call will be slow. Pre-warm with a dry run before recording, or cut the install-to-launch transition.
- Narration timing assumes the agent run is pre-recorded or time-lapsed. Do not record agent execution live — run time on real evidence is several minutes. Record the execution, edit to real-time speed for key moments (iteration start, gap analyzer output, finding count jump), and narrate over the edited cut.
