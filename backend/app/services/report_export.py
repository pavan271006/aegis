"""HTML report export service.

Generates a professional, styled, self-contained HTML incident report suitable
for client delivery.  Uses inline CSS with a dark theme matching the AEGIS
console."""
from html import escape


def generate_html(incident) -> str:
    """Generate a full styled HTML report for the given incident ORM object.

    *incident* is expected to be an ``Incident`` model instance with its
    ``.report`` JSON field populated.
    """
    report = incident.report or {}

    threat_type = escape(str(report.get("threat_type", "Unknown")))
    source = escape(str(report.get("source", incident.source_ip or "")))
    target = escape(str(report.get("target", "")))
    severity_text = escape(str(report.get("severity", incident.severity or "")))
    actions_taken = escape(str(report.get("actions_taken", "")))
    verification = escape(str(report.get("verification_result", "")))
    root_cause = escape(str(report.get("root_cause", incident.root_cause or "")))
    final_status = escape(str(report.get("final_status", incident.status or "")))
    req_count = report.get("request_count", incident.request_count or 0)
    geo = escape(str(report.get("geo", "")))

    # Timeline
    timeline_rows = ""
    for step in report.get("timeline") or incident.timeline or []:
        at = escape(str(step.get("at", "")))
        ev = escape(str(step.get("event", "")))
        timeline_rows += f"<tr><td>{at}</td><td>{ev}</td></tr>\n"

    # Recommended fixes
    fixes_items = ""
    for fix in report.get("recommended_fixes", []):
        fixes_items += f"<li>{escape(str(fix))}</li>\n"

    # Affected endpoints
    endpoints_items = ""
    for ep in report.get("affected_endpoints", []):
        endpoints_items += f"<li><code>{escape(str(ep))}</code></li>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS Lite — Incident Report #{incident.id}</title>
<style>
  :root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155;
           --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
           --danger: #f87171; --success: #4ade80; --warn: #fbbf24; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family:
         'Segoe UI', system-ui, -apple-system, sans-serif; padding: 2rem;
         line-height: 1.6; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  header {{ border-bottom: 2px solid var(--accent); padding-bottom: 1rem;
           margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.5rem; color: var(--accent); }}
  header p {{ color: var(--muted); font-size: 0.85rem; }}
  .badge {{ display: inline-block; padding: 0.2em 0.7em; border-radius: 4px;
            font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
  .badge-high {{ background: var(--danger); color: #1e1e1e; }}
  .badge-medium {{ background: var(--warn); color: #1e1e1e; }}
  .badge-low {{ background: var(--success); color: #1e1e1e; }}
  section {{ background: var(--surface); border: 1px solid var(--border);
            border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1.2rem; }}
  section h2 {{ font-size: 1rem; color: var(--accent); margin-bottom: 0.7rem;
               border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
  .field {{ margin-bottom: 0.5rem; }}
  .field .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase;
                  letter-spacing: 0.5px; }}
  .field .value {{ font-size: 0.95rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th, td {{ text-align: left; padding: 0.5rem 0.7rem; border-bottom: 1px solid var(--border);
           font-size: 0.85rem; }}
  th {{ color: var(--muted); text-transform: uppercase; font-size: 0.75rem; }}
  ul {{ padding-left: 1.5rem; }}
  li {{ margin-bottom: 0.3rem; font-size: 0.9rem; }}
  code {{ background: var(--bg); padding: 0.15em 0.4em; border-radius: 3px;
         font-size: 0.85em; }}
  footer {{ margin-top: 2rem; text-align: center; color: var(--muted);
           font-size: 0.75rem; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🛡️ AEGIS Lite — Incident Report</h1>
  <p>Incident #{incident.id} &middot; Generated {_now_str()}</p>
</header>

<section>
  <h2>Overview</h2>
  <div class="field"><span class="label">Threat Type</span>
    <div class="value">{threat_type}</div></div>
  <div class="field"><span class="label">Source IP</span>
    <div class="value">{source} {f'({geo})' if geo else ''}</div></div>
  <div class="field"><span class="label">Target</span>
    <div class="value">{target}</div></div>
  <div class="field"><span class="label">Severity</span>
    <div class="value"><span class="badge badge-{incident.severity or 'low'}">{severity_text}</span></div></div>
  <div class="field"><span class="label">Request Count</span>
    <div class="value">{req_count}</div></div>
  <div class="field"><span class="label">Status</span>
    <div class="value">{final_status}</div></div>
</section>

<section>
  <h2>Timeline</h2>
  <table>
    <thead><tr><th>Time</th><th>Event</th></tr></thead>
    <tbody>{timeline_rows or '<tr><td colspan="2">No timeline data</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>Root Cause Analysis</h2>
  <p>{root_cause}</p>
</section>

<section>
  <h2>Actions Taken</h2>
  <p>{actions_taken}</p>
  <div class="field" style="margin-top:0.5rem"><span class="label">Verification</span>
    <div class="value">{verification}</div></div>
</section>

<section>
  <h2>Affected Endpoints</h2>
  <ul>{endpoints_items or '<li>None identified</li>'}</ul>
</section>

<section>
  <h2>Recommended Fixes</h2>
  <ul>{fixes_items or '<li>No specific recommendations</li>'}</ul>
</section>

<footer>
  <p>AEGIS Lite Cybersecurity Platform &middot; Confidential</p>
</footer>

</div>
</body>
</html>"""


def _now_str() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
