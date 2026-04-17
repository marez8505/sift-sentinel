# SIFT Sentinel — Project Description

**Builder:** Edward Marez ([@marez8505](https://github.com/marez8505))  
**Submission:** SANS "Find Evil!" Hackathon · April 15 – June 15, 2026  
**Architecture:** Custom MCP Server + Self-Correcting Triage Agent

---

## What It Does

SIFT Sentinel is an autonomous digital forensics triage agent that operates on the SANS SIFT Workstation and ingests real case data — disk images, memory captures, or both — and produces a structured findings report without human prompting between steps.

More precisely: you hand it an E01 and a memory image, set `--max-iterations 3`, and walk away. When you come back, you have a timestamped JSONL execution log, a findings JSON keyed by artifact type, and an HTML report that distinguishes *confirmed findings* (backed by at least one tool execution citation) from *inferences* (pattern-matches with no direct artifact). No vague summary paragraphs. No undifferentiated wall of Vol3 output dumped into the context window.

The self-correction loop is the core differentiator. After the first analysis pass, the orchestrator runs a dedicated hallucination-check prompt that evaluates every claim against the execution log. Claims with no tool-citation get flagged as `[UNVERIFIED]`. The gap analyzer then examines which evidence types were *not* analyzed — if memory was ingested but `windows.malfind` was never called, that becomes a mandatory second-pass task. The agent re-enters the loop, fills the gaps, re-runs the hallucination check, and only then writes the final report. This is not a retry on failure — it is a deliberate second opinion the agent runs against its own work.

---

## How We Built It

The starting observation was that the hardest problem in autonomous DFIR is not "can the agent call Vol3?" — it's "can we trust what it claims to have found?" When an LLM is handed 200+ SIFT tools and a 12 GB disk image, two failure modes are nearly guaranteed: context window overload and confident hallucination on absent artifacts.

Both problems have an architectural solution, not just a prompt-engineering one.

**Custom MCP Server (`sift_mcp_server.py`)** — Rather than letting Claude Code invoke SIFT tools directly as shell commands, every tool is wrapped as a typed MCP function. The server sanitizes paths, validates that evidence paths exist before invoking any analysis tool, captures stdout/stderr, and returns *parsed structured output* rather than raw terminal text. A `vol3_pslist` call does not return 400 lines of process table; it returns a JSON array of `{pid, name, parent_pid, create_time, wow64}` objects. This keeps individual tool responses under 2,000 tokens regardless of case size, preventing context blowout.

Critically, the MCP server has no `rm`, `dd`, `wget`, `ssh`, or `curl` functions. This is not documented in the system prompt and then hoped to be obeyed — the functions simply do not exist in the server. An agent operating through this server *cannot* delete or exfiltrate evidence because the capability is not registered. The OS layer reinforces this: evidence directories are mounted read-only (`-o ro,noatime`) before the agent process starts, so even a direct subprocess call would fail at the kernel level.

**Orchestrator (`orchestrator.py`)** — The orchestrator is a thin Python wrapper that runs `claude --print` in a subprocess, captures output, writes each turn to the JSONL audit log with timestamps and token counts, and manages the iteration loop. A hard `--max-iterations` cap (default 3) is enforced at the process level: after N iterations the orchestrator terminates the loop and writes `status: MAX_ITERATIONS_REACHED` to the log. The agent cannot reason its way past this ceiling.

---

## Challenges

**Context window overload on large images.** The first prototype fed raw `vol3 --output text` output directly to the model. A single `windows.pslist` run on a 5 GB memory image produces ~4,000 tokens. `windows.netscan` adds another ~3,000. By the fourth tool call the context was saturated and the model began ignoring earlier findings. The fix was the output parser layer in the MCP server — every tool result is summarized before it crosses the trust boundary.

**Hallucination on missing artifacts.** When a registry key or prefetch entry simply does not exist on the target, Vol3 and EZ Tools return empty output. In early testing, the model would sometimes infer that an artifact *probably* existed based on the attack pattern it was tracking, even with no tool evidence. The hallucination-check prompt specifically targets "artifact exists" claims with no corresponding tool call in the log.

**Volatility 3 symbol downloads.** Fresh SIFT installs may lack ISF symbol tables for the target OS version. The MCP server catches `Symbol file not found` errors and returns a structured `{error: "missing_symbols", os_version: "...", resolution: "run vol3 --symbols-download"}` object rather than letting the raw error propagate. The orchestrator treats this as a recoverable condition and queues a symbol-download step before retrying.

**Calibrating the self-correction loop.** Running three full analysis passes on a 16 GB disk image takes time. Early versions ran the gap analyzer too aggressively, triggering second passes for negligible coverage gaps. The current implementation only triggers a mandatory re-pass when gap coverage drops below a 60% threshold — i.e., when more than 40% of applicable evidence categories were not analyzed in the first pass.

---

## What We Learned

Architectural guardrails compound. Making the MCP server the only path to SIFT tools, and making that server stateless and path-validated, eliminated an entire class of safety concerns that would otherwise require extensive prompt engineering and ongoing red-team testing. Prompt-based restrictions are negotiable; missing function registrations are not.

Output parsing belongs at the server boundary. Any raw tool output that crosses the MCP server into the LLM context should be pre-processed. The 20-second investment in writing a Vol3 output parser pays dividends across every case the agent runs.

Iterative self-correction is meaningful only if each iteration has a specific mandate. Generic "check your work" prompts produce marginal improvement. A structured gap analysis that identifies *which specific artifact types were not examined* forces targeted re-analysis that meaningfully expands coverage.

---

## What's Next

**Live memory triage via MCP.** The current implementation requires a static memory image. AVML or LiME could feed a live memory stream to the server for in-progress incident response.

**Multi-agent task decomposition.** Large cases benefit from parallel analysis: one agent on memory, one on disk timeline, one on network captures. A coordinator agent merging findings from sub-agents would scale the approach to enterprise-scale evidence sets.

**Analyst review loop.** Add an optional human-in-the-loop pause after the first iteration, so a practitioner can redirect the gap analysis before the second pass rather than after the full run.

**Automated IOC enrichment.** Post-analysis, automatically query VirusTotal and MISP against extracted hashes and IPs, annotate findings with threat intel, and update confidence scores.
