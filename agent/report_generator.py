"""
report_generator.py — Final report renderer for the SIFT Autonomous DFIR Agent.

Generates a self-contained HTML report (and optionally PDF via WeasyPrint).
Uses Jinja2 if available, falls back to f-string templating.

Sections:
  1. Executive Summary
  2. Timeline of Events
  3. High-Confidence Findings
  4. Indicators of Compromise (IOC table)
  5. Evidence Chain (finding → tool that produced it)
  6. MITRE ATT&CK Mapping
  7. Analyst Notes
  8. Appendix (iteration details, raw output references)
"""

from __future__ import annotations

import html as html_lib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Attempt Jinja2 import — fall back gracefully
try:
    from jinja2 import Environment, BaseLoader  # type: ignore
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False

# ---------------------------------------------------------------------------
# Type alias (avoid importing from orchestrator to keep this self-contained)
# ---------------------------------------------------------------------------

class _Finding:
    """Lightweight finding representation used when not imported from orchestrator."""
    __slots__ = (
        "artifact_type", "description", "confidence", "tool_evidence",
        "ioc", "timestamp_utc", "is_hallucination"
    )

    def __init__(self, **kwargs: Any) -> None:
        for attr in self.__slots__:
            setattr(self, attr, kwargs.get(attr))
        if self.tool_evidence is None:
            self.tool_evidence = []
        if self.is_hallucination is None:
            self.is_hallucination = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "_Finding":
        return cls(**d)

    def to_dict(self) -> dict[str, Any]:
        return {attr: getattr(self, attr) for attr in self.__slots__}


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping heuristics
# ---------------------------------------------------------------------------

_MITRE_PATTERNS: list[tuple[str, str, str]] = [
    # (keyword_in_description, technique_id, technique_name)
    ("powershell",          "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ("wscript",             "T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    ("scheduled task",      "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    ("service",             "T1543.003", "Create or Modify System Process: Windows Service"),
    ("run key",             "T1547.001", "Boot or Logon Autostart: Registry Run Keys"),
    ("startup folder",      "T1547.001", "Boot or Logon Autostart: Registry Run Keys / Startup Folder"),
    ("dll",                 "T1574",     "Hijack Execution Flow: DLL Side-Loading"),
    ("injected",            "T1055",     "Process Injection"),
    ("malfind",             "T1055",     "Process Injection"),
    ("hollowing",           "T1055.012", "Process Injection: Process Hollowing"),
    ("lsass",               "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("kerberoast",          "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ("dcsync",              "T1003.006", "OS Credential Dumping: DCSync"),
    ("lateral",             "T1021",     "Remote Services"),
    ("psexec",              "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("wmi",                 "T1047",     "Windows Management Instrumentation"),
    ("rdp",                 "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("exfil",               "T1041",     "Exfiltration Over C2 Channel"),
    ("dns tunnel",          "T1071.004", "Application Layer Protocol: DNS"),
    ("beacon",              "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("c2",                  "T1071",     "Application Layer Protocol"),
    ("certutil",            "T1105",     "Ingress Tool Transfer"),
    ("bitsadmin",           "T1197",     "BITS Jobs"),
    ("timestomp",           "T1070.006", "Indicator Removal: Timestomp"),
    ("pass-the-hash",       "T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
    ("brute force",         "T1110",     "Brute Force"),
    ("spray",               "T1110.003", "Brute Force: Password Spraying"),
    ("yara",                "T1027",     "Obfuscated Files or Information"),
    ("encoded",             "T1027",     "Obfuscated Files or Information"),
    ("base64",              "T1027",     "Obfuscated Files or Information"),
    ("mshta",               "T1218.005", "System Binary Proxy Execution: Mshta"),
    ("regsvr32",            "T1218.010", "System Binary Proxy Execution: Regsvr32"),
    ("rundll32",            "T1218.011", "System Binary Proxy Execution: Rundll32"),
    ("wmic",                "T1047",     "Windows Management Instrumentation"),
    ("persistence",         "T1547",     "Boot or Logon Autostart Execution"),
    ("privilege escalation","T1068",     "Exploitation for Privilege Escalation"),
]


def _map_to_mitre(findings: list[Any]) -> list[dict[str, str]]:
    """Return a de-duplicated list of MITRE ATT&CK techniques referenced by findings."""
    seen: set[str] = set()
    techniques: list[dict[str, str]] = []
    for f in findings:
        desc_lower = (getattr(f, "description", "") or "").lower()
        for keyword, tid, tname in _MITRE_PATTERNS:
            if keyword in desc_lower and tid not in seen:
                seen.add(tid)
                techniques.append({
                    "id": tid,
                    "name": tname,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                })
    return sorted(techniques, key=lambda x: x["id"])


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates the final HTML (and optionally PDF) incident report.

    Usage:
        rg = ReportGenerator()
        html = rg.generate(findings, iterations, case_info)
        Path("report.html").write_text(html)
    """

    def generate(
        self,
        findings: list[Any],          # list of Finding objects or dicts
        iterations: list[dict[str, Any]],
        case_info: dict[str, Any],
    ) -> str:
        """
        Produce a self-contained HTML report string.
        Uses Jinja2 if available, otherwise pure f-string rendering.
        """
        # Normalise findings to _Finding objects
        normalised: list[_Finding] = []
        for f in findings:
            if isinstance(f, dict):
                normalised.append(_Finding.from_dict(f))
            elif hasattr(f, "to_dict"):
                normalised.append(_Finding.from_dict(f.to_dict()))
            else:
                normalised.append(f)

        context = self._build_context(normalised, iterations, case_info)

        if _JINJA2_AVAILABLE:
            return self._render_jinja(context)
        return self._render_fstring(context)

    # ------------------------------------------------------------------
    # Context builder (shared between render paths)
    # ------------------------------------------------------------------

    def _build_context(
        self,
        findings: list[_Finding],
        iterations: list[dict[str, Any]],
        case_info: dict[str, Any],
    ) -> dict[str, Any]:
        confirmed = [f for f in findings if f.confidence == "confirmed" and not f.is_hallucination]
        probable  = [f for f in findings if f.confidence == "probable"  and not f.is_hallucination]
        possible  = [f for f in findings if f.confidence == "possible"  and not f.is_hallucination]
        unverified = [f for f in findings if f.confidence == "unverified" or f.is_hallucination]
        iocs = [f for f in findings if f.ioc and not f.is_hallucination]

        # Build timeline from timestamped findings
        timeline = sorted(
            [f for f in findings if f.timestamp_utc and not f.is_hallucination],
            key=lambda x: x.timestamp_utc or "",
        )

        mitre = _map_to_mitre(confirmed + probable)

        # Evidence chain: group findings by artifact_type
        evidence_chain: dict[str, list[_Finding]] = {}
        for f in confirmed + probable:
            evidence_chain.setdefault(f.artifact_type or "unknown", []).append(f)

        return {
            "case_info": case_info,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "findings": findings,
            "confirmed": confirmed,
            "probable": probable,
            "possible": possible,
            "unverified": unverified,
            "iocs": iocs,
            "timeline": timeline,
            "mitre": mitre,
            "evidence_chain": evidence_chain,
            "iterations": iterations,
            "total_findings": len(findings),
            "stats": {
                "confirmed": len(confirmed),
                "probable":  len(probable),
                "possible":  len(possible),
                "unverified": len(unverified),
                "iocs":      len(iocs),
                "iterations": len(iterations),
            },
        }

    # ------------------------------------------------------------------
    # Jinja2 render path
    # ------------------------------------------------------------------

    def _render_jinja(self, ctx: dict[str, Any]) -> str:
        env = Environment(loader=BaseLoader(), autoescape=True)  # type: ignore
        env.globals["e"] = html_lib.escape
        template = env.from_string(_HTML_TEMPLATE)
        return template.render(**ctx)

    # ------------------------------------------------------------------
    # f-string render path (no third-party deps)
    # ------------------------------------------------------------------

    def _render_fstring(self, ctx: dict[str, Any]) -> str:
        """Render the full HTML report using Python f-strings."""
        e = html_lib.escape  # shorthand

        case = ctx["case_info"]
        stats = ctx["stats"]

        # ----- Executive Summary -----
        exec_summary = f"""
        <p>This report documents the autonomous DFIR triage performed by the SIFT Autonomous Agent
        over <strong>{stats['iterations']}</strong> iteration(s) against the following evidence:</p>
        <ul>
          {"".join(f"<li><code>{e(str(ev.get('type','').upper()))}</code> — {e(str(ev.get('path','')))}</li>"
                   for ev in case.get("evidence_items", []))}
        </ul>
        <p>The investigation produced <strong>{ctx['total_findings']}</strong> total findings:
        <span class="badge confirmed">{stats['confirmed']} Confirmed</span>
        <span class="badge probable">{stats['probable']} Probable</span>
        <span class="badge possible">{stats['possible']} Possible</span>
        <span class="badge unverified">{stats['unverified']} Unverified</span>
        </p>
        <p>{stats['iocs']} distinct IOC(s) were extracted. See the IOC table for details.</p>
        """

        # ----- Timeline -----
        if ctx["timeline"]:
            timeline_rows = "\n".join(
                f"""<tr>
                  <td class="mono">{e(str(f.timestamp_utc or ''))}</td>
                  <td><span class="badge {e(f.confidence)}">{e(f.confidence)}</span></td>
                  <td>{e(str(f.artifact_type or ''))}</td>
                  <td>{e(str(f.description or '')[:200])}</td>
                  <td class="mono">{e(str(f.ioc or '—'))}</td>
                </tr>"""
                for f in ctx["timeline"]
            )
            timeline_html = f"""
            <table>
              <thead><tr>
                <th>Timestamp (UTC)</th><th>Confidence</th>
                <th>Type</th><th>Description</th><th>IOC</th>
              </tr></thead>
              <tbody>{timeline_rows}</tbody>
            </table>"""
        else:
            timeline_html = "<p class='muted'>No timestamped findings were extracted.</p>"

        # ----- High-Confidence Findings -----
        def render_finding_card(f: _Finding) -> str:
            evidence_items = "".join(
                f"<li><code>{e(str(te))}</code></li>" for te in (f.tool_evidence or [])
            ) or "<li class='muted'>No tool evidence cited.</li>"
            ioc_badge = (
                f'<span class="ioc-value">{e(str(f.ioc))}</span>'
                if f.ioc else ""
            )
            ts = f'<span class="timestamp">{e(str(f.timestamp_utc))}</span>' if f.timestamp_utc else ""
            halluc_warn = (
                '<div class="hallucination-warning">⚠ Potential hallucination — '
                'verify with tool evidence</div>'
                if f.is_hallucination else ""
            )
            return f"""
            <div class="finding-card confidence-{e(f.confidence or 'unverified')}">
              <div class="finding-header">
                <span class="badge {e(f.confidence or 'unverified')}">{e(f.confidence or 'unverified')}</span>
                <span class="artifact-type">{e(str(f.artifact_type or 'unknown').upper())}</span>
                {ioc_badge}{ts}
              </div>
              {halluc_warn}
              <p class="finding-desc">{e(str(f.description or ''))}</p>
              <details>
                <summary>Tool Evidence ({len(f.tool_evidence or [])} citation(s))</summary>
                <ul class="tool-evidence">{evidence_items}</ul>
              </details>
            </div>"""

        high_conf_html = "".join(
            render_finding_card(f) for f in ctx["confirmed"] + ctx["probable"]
        ) or "<p class='muted'>No high-confidence findings.</p>"

        # ----- IOC Table -----
        if ctx["iocs"]:
            ioc_rows = "\n".join(
                f"""<tr>
                  <td class="mono ioc-value">{e(str(f.ioc or ''))}</td>
                  <td>{e(str(f.artifact_type or ''))}</td>
                  <td><span class="badge {e(f.confidence)}">{e(f.confidence)}</span></td>
                  <td>{e(str(f.description or '')[:150])}</td>
                </tr>"""
                for f in ctx["iocs"]
            )
            ioc_html = f"""
            <table>
              <thead><tr>
                <th>IOC Value</th><th>Type</th><th>Confidence</th><th>Context</th>
              </tr></thead>
              <tbody>{ioc_rows}</tbody>
            </table>"""
        else:
            ioc_html = "<p class='muted'>No IOCs extracted.</p>"

        # ----- Evidence Chain -----
        chain_blocks: list[str] = []
        for artifact_type, group in ctx["evidence_chain"].items():
            items = "".join(
                f"<li>{e(str(f.description or '')[:120])} "
                f"<span class='badge {e(f.confidence)}'>{e(f.confidence)}</span>"
                f"{''.join(f'<code class=tool-evidence-inline>{e(str(te))}</code>' for te in (f.tool_evidence or [])[:2])}"
                f"</li>"
                for f in group
            )
            chain_blocks.append(
                f"<div class='chain-group'>"
                f"<h4>{e(artifact_type.upper())}</h4><ul>{items}</ul></div>"
            )
        chain_html = "\n".join(chain_blocks) or "<p class='muted'>No evidence chain available.</p>"

        # ----- MITRE ATT&CK -----
        if ctx["mitre"]:
            mitre_items = "\n".join(
                f'<tr><td><a href="{e(t["url"])}" target="_blank">'
                f'<code>{e(t["id"])}</code></a></td>'
                f'<td>{e(t["name"])}</td></tr>'
                for t in ctx["mitre"]
            )
            mitre_html = f"""
            <table>
              <thead><tr><th>Technique ID</th><th>Technique Name</th></tr></thead>
              <tbody>{mitre_items}</tbody>
            </table>"""
        else:
            mitre_html = "<p class='muted'>No MITRE ATT&CK techniques mapped.</p>"

        # ----- Analyst Notes -----
        unverified_notes = "".join(
            f"<li><code>[{e(str(f.artifact_type or 'unknown').upper())}]</code> "
            f"{e(str(f.description or '')[:200])}"
            f"{'<span class=halluc-tag>unverified</span>' if f.is_hallucination else ''}"
            f"</li>"
            for f in ctx["unverified"]
        ) or "<li class='muted'>None.</li>"

        # ----- Appendix -----
        iter_rows = "\n".join(
            f"""<tr>
              <td>{i.get('iteration', '?')}</td>
              <td>{i.get('findings_count', 0)}</td>
              <td>{i.get('quality_score', 0.0):.2f}</td>
              <td>{len(i.get('gaps', []))}</td>
              <td class='mono small'>{e(i.get('timestamp', ''))}</td>
            </tr>"""
            for i in ctx["iterations"]
        )
        appendix_html = f"""
        <table>
          <thead><tr>
            <th>Iteration</th><th>Findings</th>
            <th>Quality Score</th><th>Gaps</th><th>Timestamp</th>
          </tr></thead>
          <tbody>{iter_rows}</tbody>
        </table>""" if ctx["iterations"] else "<p class='muted'>No iteration data.</p>"

        # ----- Assemble full document -----
        return _HTML_TEMPLATE_FSTRING.format(
            case_dir       = e(str(case.get("case_dir", ""))),
            generated_at   = e(ctx["generated_at"]),
            total_findings = ctx["total_findings"],
            stats_confirmed = stats["confirmed"],
            stats_probable  = stats["probable"],
            stats_possible  = stats["possible"],
            stats_unverified = stats["unverified"],
            stats_iocs       = stats["iocs"],
            exec_summary     = exec_summary,
            timeline_html    = timeline_html,
            high_conf_html   = high_conf_html,
            ioc_html         = ioc_html,
            chain_html       = chain_html,
            mitre_html       = mitre_html,
            unverified_notes = unverified_notes,
            appendix_html    = appendix_html,
        )

    # ------------------------------------------------------------------
    # PDF generation (optional — requires WeasyPrint)
    # ------------------------------------------------------------------

    def generate_pdf(self, html_content: str, output_path: Path) -> bool:
        """
        Write a PDF version of the report using WeasyPrint.
        Returns True if successful, False otherwise.
        """
        try:
            from weasyprint import HTML as WP_HTML  # type: ignore
            WP_HTML(string=html_content).write_pdf(str(output_path))
            return True
        except ImportError:
            return False
        except Exception as exc:  # noqa: BLE001
            print(f"[report_generator] PDF generation failed: {exc}", file=sys.stderr)
            return False


# ---------------------------------------------------------------------------
# HTML Templates
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #6e7681;
  --accent: #58a6ff;
  --green: #3fb950;
  --yellow: #d29922;
  --orange: #e3b341;
  --red: #f85149;
  --purple: #bc8cff;
  --confirmed-bg: #1a3a1a;
  --confirmed-fg: #3fb950;
  --probable-bg: #1a2d3a;
  --probable-fg: #58a6ff;
  --possible-bg: #2d2a1a;
  --possible-fg: #d29922;
  --unverified-bg: #2a1a1a;
  --unverified-fg: #f85149;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
header {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 20px 0; margin-bottom: 32px;
}
header h1 { font-size: 22px; font-weight: 700; color: var(--text); }
header .meta { color: var(--text-muted); font-size: 12px; margin-top: 4px; }
.stat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin-bottom: 32px;
}
.stat-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; text-align: center;
}
.stat-card .num { font-size: 28px; font-weight: 700; }
.stat-card .label { color: var(--text-muted); font-size: 12px; margin-top: 4px; }
.stat-card.confirmed .num { color: var(--confirmed-fg); }
.stat-card.probable  .num { color: var(--probable-fg); }
.stat-card.possible  .num { color: var(--possible-fg); }
.stat-card.unverified .num { color: var(--unverified-fg); }
.stat-card.iocs .num { color: var(--purple); }
section { margin-bottom: 40px; }
section h2 {
  font-size: 18px; font-weight: 700; margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid var(--border);
  color: var(--text);
}
section h3 { font-size: 14px; font-weight: 600; color: var(--text-muted); margin: 12px 0 8px; }
section h4 { font-size: 13px; color: var(--accent); margin: 8px 0 4px; }
table {
  width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px;
}
th {
  background: var(--surface2); padding: 8px 12px; text-align: left;
  border: 1px solid var(--border); color: var(--text-muted); font-weight: 600;
}
td { padding: 8px 12px; border: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: var(--surface2); }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
  font-weight: 600; white-space: nowrap;
}
.badge.confirmed  { background: var(--confirmed-bg); color: var(--confirmed-fg); }
.badge.probable   { background: var(--probable-bg);  color: var(--probable-fg);  }
.badge.possible   { background: var(--possible-bg);  color: var(--possible-fg);  }
.badge.unverified { background: var(--unverified-bg);color: var(--unverified-fg);}
.finding-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 12px;
}
.finding-card.confidence-confirmed { border-left: 3px solid var(--confirmed-fg); }
.finding-card.confidence-probable  { border-left: 3px solid var(--probable-fg);  }
.finding-card.confidence-possible  { border-left: 3px solid var(--possible-fg);  }
.finding-card.confidence-unverified { border-left: 3px solid var(--unverified-fg); }
.finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.artifact-type { font-size: 11px; color: var(--text-muted); font-weight: 600; }
.finding-desc { margin-bottom: 8px; }
.ioc-value { font-family: monospace; font-size: 12px; background: var(--surface2); padding: 2px 6px; border-radius: 4px; color: var(--purple); }
.timestamp { font-size: 11px; color: var(--text-muted); font-family: monospace; }
.hallucination-warning {
  background: #2a1a00; border: 1px solid #7d4e00; border-radius: 4px;
  padding: 6px 10px; margin-bottom: 8px; font-size: 12px; color: #e3b341;
}
details summary { cursor: pointer; color: var(--accent); font-size: 12px; margin-top: 4px; }
.tool-evidence { list-style: none; padding-left: 0; margin-top: 8px; }
.tool-evidence li { margin-bottom: 4px; }
.tool-evidence li code {
  background: var(--surface2); padding: 2px 6px; border-radius: 4px;
  font-size: 12px; color: var(--text);
}
.tool-evidence-inline {
  font-family: monospace; font-size: 11px; background: var(--surface2);
  padding: 1px 4px; border-radius: 3px; margin-left: 4px; color: var(--text-muted);
}
.chain-group { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; }
.chain-group ul { list-style: none; padding-left: 0; margin-top: 8px; }
.chain-group li { padding: 4px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.chain-group li:last-child { border-bottom: none; }
.muted { color: var(--text-muted); font-style: italic; }
.mono { font-family: monospace; font-size: 12px; }
.small { font-size: 11px; }
.halluc-tag { background: var(--unverified-bg); color: var(--unverified-fg); padding: 1px 4px; border-radius: 3px; font-size: 11px; margin-left: 4px; }
p { margin-bottom: 8px; }
ul { padding-left: 20px; margin-bottom: 8px; }
code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
footer { background: var(--surface); border-top: 1px solid var(--border); padding: 16px 0; margin-top: 48px; text-align: center; color: var(--text-muted); font-size: 12px; }
@media print {
  body { background: white; color: black; }
  .finding-card { page-break-inside: avoid; }
  table { page-break-inside: avoid; }
}
"""

_HTML_TEMPLATE_FSTRING = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SIFT DFIR Incident Report</title>
  <style>{css}</style>
</head>
<body>
  <header>
    <div class="container">
      <h1>&#x1F50D; SIFT Autonomous DFIR Agent — Incident Report</h1>
      <div class="meta">
        Case: {case_dir} &nbsp;&bull;&nbsp; Generated: {generated_at}
      </div>
    </div>
  </header>

  <div class="container">

    <div class="stat-grid">
      <div class="stat-card confirmed"><div class="num">{stats_confirmed}</div><div class="label">Confirmed</div></div>
      <div class="stat-card probable"><div class="num">{stats_probable}</div><div class="label">Probable</div></div>
      <div class="stat-card possible"><div class="num">{stats_possible}</div><div class="label">Possible</div></div>
      <div class="stat-card unverified"><div class="num">{stats_unverified}</div><div class="label">Unverified</div></div>
      <div class="stat-card iocs"><div class="num">{stats_iocs}</div><div class="label">IOCs</div></div>
      <div class="stat-card"><div class="num">{total_findings}</div><div class="label">Total Findings</div></div>
    </div>

    <section id="exec-summary">
      <h2>1. Executive Summary</h2>
      {exec_summary}
    </section>

    <section id="timeline">
      <h2>2. Timeline of Events</h2>
      {timeline_html}
    </section>

    <section id="findings">
      <h2>3. High-Confidence Findings</h2>
      {high_conf_html}
    </section>

    <section id="iocs">
      <h2>4. Indicators of Compromise</h2>
      {ioc_html}
    </section>

    <section id="evidence-chain">
      <h2>5. Evidence Chain</h2>
      <p class="muted">Each finding grouped by artifact type with supporting tool evidence.</p>
      {chain_html}
    </section>

    <section id="mitre">
      <h2>6. MITRE ATT&amp;CK Mapping</h2>
      {mitre_html}
    </section>

    <section id="analyst-notes">
      <h2>7. Analyst Notes</h2>
      <h3>Unverified / Flagged Findings (require manual review)</h3>
      <ul>{unverified_notes}</ul>
    </section>

    <section id="appendix">
      <h2>8. Appendix — Iteration Log</h2>
      {appendix_html}
    </section>

  </div>

  <footer>
    <div class="container">
      SIFT Autonomous DFIR Agent &mdash; SANS &ldquo;Find Evil!&rdquo; Hackathon
      &nbsp;&bull;&nbsp; Report generated {generated_at}
    </div>
  </footer>
</body>
</html>
""".replace("{css}", _CSS)


# Jinja2 version of the same template (autoescape handles escaping)
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SIFT DFIR Incident Report</title>
  <style>""" + _CSS + r"""</style>
</head>
<body>
  <header>
    <div class="container">
      <h1>&#x1F50D; SIFT Autonomous DFIR Agent — Incident Report</h1>
      <div class="meta">
        Case: {{ case_info.case_dir }} &bull; Generated: {{ generated_at }}
      </div>
    </div>
  </header>

  <div class="container">

    <div class="stat-grid">
      <div class="stat-card confirmed"><div class="num">{{ stats.confirmed }}</div><div class="label">Confirmed</div></div>
      <div class="stat-card probable"><div class="num">{{ stats.probable }}</div><div class="label">Probable</div></div>
      <div class="stat-card possible"><div class="num">{{ stats.possible }}</div><div class="label">Possible</div></div>
      <div class="stat-card unverified"><div class="num">{{ stats.unverified }}</div><div class="label">Unverified</div></div>
      <div class="stat-card iocs"><div class="num">{{ stats.iocs }}</div><div class="label">IOCs</div></div>
      <div class="stat-card"><div class="num">{{ total_findings }}</div><div class="label">Total Findings</div></div>
    </div>

    <section id="exec-summary">
      <h2>1. Executive Summary</h2>
      <p>This report documents autonomous DFIR triage across
        <strong>{{ stats.iterations }}</strong> iteration(s).</p>
      <ul>
        {% for ev in case_info.evidence_items %}
        <li><code>{{ ev.type | upper }}</code> — {{ ev.path }}</li>
        {% endfor %}
      </ul>
    </section>

    <section id="timeline">
      <h2>2. Timeline of Events</h2>
      {% if timeline %}
      <table>
        <thead><tr><th>Timestamp (UTC)</th><th>Confidence</th><th>Type</th><th>Description</th><th>IOC</th></tr></thead>
        <tbody>
        {% for f in timeline %}
          <tr>
            <td class="mono">{{ f.timestamp_utc }}</td>
            <td><span class="badge {{ f.confidence }}">{{ f.confidence }}</span></td>
            <td>{{ f.artifact_type }}</td>
            <td>{{ f.description[:200] }}</td>
            <td class="mono">{{ f.ioc or '—' }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted">No timestamped findings extracted.</p>
      {% endif %}
    </section>

    <section id="findings">
      <h2>3. High-Confidence Findings</h2>
      {% for f in confirmed + probable %}
      <div class="finding-card confidence-{{ f.confidence }}">
        <div class="finding-header">
          <span class="badge {{ f.confidence }}">{{ f.confidence }}</span>
          <span class="artifact-type">{{ (f.artifact_type or 'unknown') | upper }}</span>
          {% if f.ioc %}<span class="ioc-value">{{ f.ioc }}</span>{% endif %}
          {% if f.timestamp_utc %}<span class="timestamp">{{ f.timestamp_utc }}</span>{% endif %}
        </div>
        {% if f.is_hallucination %}
        <div class="hallucination-warning">⚠ Potential hallucination — verify with tool evidence</div>
        {% endif %}
        <p class="finding-desc">{{ f.description }}</p>
        <details>
          <summary>Tool Evidence ({{ f.tool_evidence | length }} citation(s))</summary>
          <ul class="tool-evidence">
            {% for te in f.tool_evidence %}
            <li><code>{{ te }}</code></li>
            {% else %}
            <li class="muted">No tool evidence cited.</li>
            {% endfor %}
          </ul>
        </details>
      </div>
      {% else %}
      <p class="muted">No high-confidence findings.</p>
      {% endfor %}
    </section>

    <section id="iocs">
      <h2>4. Indicators of Compromise</h2>
      {% if iocs %}
      <table>
        <thead><tr><th>IOC Value</th><th>Type</th><th>Confidence</th><th>Context</th></tr></thead>
        <tbody>
        {% for f in iocs %}
          <tr>
            <td class="mono ioc-value">{{ f.ioc }}</td>
            <td>{{ f.artifact_type }}</td>
            <td><span class="badge {{ f.confidence }}">{{ f.confidence }}</span></td>
            <td>{{ f.description[:150] }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted">No IOCs extracted.</p>
      {% endif %}
    </section>

    <section id="evidence-chain">
      <h2>5. Evidence Chain</h2>
      {% for atype, group in evidence_chain.items() %}
      <div class="chain-group">
        <h4>{{ atype | upper }}</h4>
        <ul>
          {% for f in group %}
          <li>
            {{ f.description[:120] }}
            <span class="badge {{ f.confidence }}">{{ f.confidence }}</span>
            {% for te in f.tool_evidence[:2] %}<code class="tool-evidence-inline">{{ te }}</code>{% endfor %}
          </li>
          {% endfor %}
        </ul>
      </div>
      {% else %}
      <p class="muted">No evidence chain available.</p>
      {% endfor %}
    </section>

    <section id="mitre">
      <h2>6. MITRE ATT&amp;CK Mapping</h2>
      {% if mitre %}
      <table>
        <thead><tr><th>Technique ID</th><th>Technique Name</th></tr></thead>
        <tbody>
        {% for t in mitre %}
          <tr>
            <td><a href="{{ t.url }}" target="_blank"><code>{{ t.id }}</code></a></td>
            <td>{{ t.name }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted">No MITRE ATT&CK techniques mapped.</p>
      {% endif %}
    </section>

    <section id="analyst-notes">
      <h2>7. Analyst Notes</h2>
      <h3>Unverified / Flagged Findings</h3>
      <ul>
        {% for f in unverified %}
        <li>
          <code>[{{ (f.artifact_type or 'unknown') | upper }}]</code>
          {{ f.description[:200] }}
          {% if f.is_hallucination %}<span class="halluc-tag">unverified</span>{% endif %}
        </li>
        {% else %}
        <li class="muted">None.</li>
        {% endfor %}
      </ul>
    </section>

    <section id="appendix">
      <h2>8. Appendix — Iteration Log</h2>
      {% if iterations %}
      <table>
        <thead><tr><th>Iteration</th><th>Findings</th><th>Quality Score</th><th>Gaps</th><th>Timestamp</th></tr></thead>
        <tbody>
        {% for i in iterations %}
          <tr>
            <td>{{ i.iteration }}</td>
            <td>{{ i.findings_count }}</td>
            <td>{{ "%.2f" | format(i.quality_score) }}</td>
            <td>{{ i.gaps | length }}</td>
            <td class="mono small">{{ i.timestamp }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted">No iteration data.</p>
      {% endif %}
    </section>

  </div>

  <footer>
    <div class="container">
      SIFT Autonomous DFIR Agent &mdash; SANS &ldquo;Find Evil!&rdquo; Hackathon
      &nbsp;&bull;&nbsp; Report generated {{ generated_at }}
    </div>
  </footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Standalone entry point (for testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate SIFT DFIR report from findings JSON")
    parser.add_argument("--findings", type=Path, required=True, help="Path to findings JSON array")
    parser.add_argument("--output",   type=Path, default=Path("report.html"))
    parser.add_argument("--case-dir", type=str, default="/cases/unknown")
    args = parser.parse_args()

    raw = json.loads(args.findings.read_text())
    case_info = {
        "case_dir": args.case_dir,
        "evidence_items": [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    rg = ReportGenerator()
    html = rg.generate(raw, [], case_info)
    args.output.write_text(html, encoding="utf-8")
    print(f"Report written to {args.output}")

    if rg.generate_pdf(html, args.output.with_suffix(".pdf")):
        print(f"PDF written to {args.output.with_suffix('.pdf')}")
