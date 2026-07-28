#!/usr/bin/env python3
"""
report_generator.py — HTML pentest report generator for the HALO agent.

Reads a session log produced during an engagement and renders a self-contained,
branded HTML report. Runs on the standard library only (no external deps).

Usage:
    python3 report_generator.py <session_log_file> [output.html]

The input may be either:
  * a structured JSON session file (see logger.py), or
  * a plain-text .log file.

If no output path is given, the report is written next to the input file
with a .html extension.
"""

import html
import json
import os
import re
import sys
from datetime import datetime

# Lines matching any of these patterns are surfaced as "findings" highlights.
FINDING_PATTERNS = [
    re.compile(r"\bopen\b", re.I),
    re.compile(r"\bvulnerab", re.I),
    re.compile(r"\bconfirmed\b", re.I),
    re.compile(r"\bexploit", re.I),
    re.compile(r"\bCVE-\d{4}-\d+", re.I),
    re.compile(r"\[\+\]"),
]


def _load(path):
    """Return (session_dict_or_None, raw_text)."""
    with open(path, "r", errors="replace") as f:
        raw = f.read()
    try:
        return json.loads(raw), raw
    except (ValueError, json.JSONDecodeError):
        return None, raw


def _is_finding(line):
    return any(p.search(line) for p in FINDING_PATTERNS)


def _render_events(session):
    """Render the structured logger.py session format."""
    rows = []
    findings = []
    for event in session.get("events", []):
        etype = event.get("event_type", "event")
        data = event.get("data", {})
        ts = event.get("timestamp", "")
        summary = json.dumps(data, indent=2)
        rows.append(
            f"<tr><td class='ts'>{html.escape(ts)}</td>"
            f"<td class='type type-{html.escape(etype)}'>{html.escape(etype)}</td>"
            f"<td><pre>{html.escape(summary)}</pre></td></tr>"
        )
        if etype == "tool_call":
            result = json.dumps(data.get("result", ""))
            for line in result.splitlines():
                if _is_finding(line):
                    findings.append(line.strip())
    meta = {
        "session_id": session.get("session_id", "unknown"),
        "started_at": session.get("started_at", "—"),
        "ended_at": session.get("ended_at", "—"),
        "event_count": len(session.get("events", [])),
    }
    body = (
        "<table class='events'><thead><tr>"
        "<th>Time</th><th>Type</th><th>Detail</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )
    return meta, findings, body


def _render_text(raw):
    """Render a plain-text log."""
    lines = raw.splitlines()
    findings = [ln.strip() for ln in lines if _is_finding(ln)]
    escaped = html.escape(raw)
    meta = {
        "session_id": "text-log",
        "started_at": "—",
        "ended_at": "—",
        "event_count": len(lines),
    }
    body = f"<pre class='rawlog'>{escaped}</pre>"
    return meta, findings, body


def build_report(input_path, output_path=None):
    session, raw = _load(input_path)
    if session is not None:
        meta, findings, body = _render_events(session)
    else:
        meta, findings, body = _render_text(raw)

    findings_html = (
        "<ul class='findings'>"
        + "".join(f"<li>{html.escape(f)}</li>" for f in findings[:200])
        + "</ul>"
        if findings
        else "<p class='muted'>No high-signal findings were flagged in this session.</p>"
    )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HALO Engagement Report — {html.escape(str(meta['session_id']))}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #0d1117; color: #e6edf3; line-height: 1.5; }}
  header {{ padding: 2rem; background: linear-gradient(135deg,#0d1117,#161b22);
           border-bottom: 2px solid #238636; }}
  header h1 {{ margin: 0; font-size: 1.6rem; }}
  header .sub {{ color: #8b949e; font-size: .9rem; }}
  main {{ padding: 1.5rem 2rem; max-width: 1100px; }}
  h2 {{ border-bottom: 1px solid #30363d; padding-bottom: .3rem; margin-top: 2rem; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 1rem 0; }}
  .meta div {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: .6rem 1rem; }}
  .meta .k {{ color: #8b949e; font-size: .75rem; text-transform: uppercase; }}
  .meta .v {{ font-size: 1.1rem; font-weight: 600; }}
  ul.findings li {{ font-family: ui-monospace, monospace; font-size: .85rem;
                    background: #161b22; border-left: 3px solid #238636;
                    padding: .3rem .6rem; margin: .25rem 0; list-style: none;
                    overflow-x: auto; }}
  ul.findings {{ padding-left: 0; }}
  table.events {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  table.events th, table.events td {{ border: 1px solid #30363d; padding: .4rem .6rem;
                                      text-align: left; vertical-align: top; }}
  table.events th {{ background: #161b22; }}
  pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; }}
  pre.rawlog {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 1rem; overflow-x: auto; font-size: .8rem; }}
  .ts {{ color: #8b949e; white-space: nowrap; }}
  .muted {{ color: #8b949e; }}
  footer {{ padding: 1.5rem 2rem; color: #8b949e; font-size: .8rem;
           border-top: 1px solid #30363d; }}
</style>
</head>
<body>
<header>
  <h1>🔐 HALO — Engagement Report</h1>
  <div class="sub">Autonomous penetration testing agent · generated {generated}</div>
</header>
<main>
  <div class="meta">
    <div><div class="k">Session</div><div class="v">{html.escape(str(meta['session_id']))}</div></div>
    <div><div class="k">Started</div><div class="v">{html.escape(str(meta['started_at']))}</div></div>
    <div><div class="k">Ended</div><div class="v">{html.escape(str(meta['ended_at']))}</div></div>
    <div><div class="k">Events</div><div class="v">{meta['event_count']}</div></div>
  </div>

  <h2>Flagged Findings</h2>
  {findings_html}

  <h2>Full Activity Log</h2>
  {body}
</main>
<footer>
  Generated by HALO report_generator.py. For authorized security testing only.
</footer>
</body>
</html>"""

    if output_path is None:
        base, _ = os.path.splitext(input_path)
        output_path = base + ".html"
    with open(output_path, "w") as f:
        f.write(doc)
    return output_path


def main(argv):
    if len(argv) < 2:
        print("Usage: python3 report_generator.py <session_log_file> [output.html]")
        return 1
    input_path = argv[1]
    if not os.path.exists(input_path):
        print(f"[REPORT] Log file not found: {input_path}")
        return 1
    output_path = argv[2] if len(argv) > 2 else None
    out = build_report(input_path, output_path)
    print(f"[REPORT] 📝 HTML report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
