# ot_recon/core/report_html.py
#
# Self-contained HTML assessment report: one file, inline CSS, no scripts,
# no external assets - safe to email, archive, or open on an air-gapped
# machine. Built from the pipeline's host dicts plus the scan context
# (profile, scope, coverage) so the report can say not just what was found
# but how, with what confidence, and what was NOT assessed.
#
# SECURITY: much of what is rendered is controlled by the devices that were
# scanned (vendor strings, HTTP titles, system names, raw probe output) -
# i.e. by whoever could put a device on the network. Every dynamic value
# goes through _e() (HTML-escaping), URLs are limited to http(s), and the
# page contains no JavaScript, so a hostile banner cannot attack the person
# opening the report.

import html
import re
from collections import Counter
from datetime import datetime, timezone

from ot_recon import __version__
from ot_recon.core.risk import (
    DETECTION_LEVELS, SEVERITY_ORDER, SEVERITY_WEIGHTS, ASSET_MULTIPLIERS,
)

SEV_CLASS = {
    "Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium",
    "Low": "sev-low", "Info": "sev-info",
}
COVERAGE_CLASS = {"full": "cov-full", "partial": "cov-partial", "limited": "cov-limited", "n/a": "cov-na"}
COVERAGE_LABEL = {
    "full": "Full", "partial": "Partial", "limited": "Limited", "n/a": "No OT services",
}
PROBE_CLASS = {"data": "cov-full", "no_data": "cov-partial", "timeout": "cov-limited", "error": "cov-limited"}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _e(value):
    """HTML-escape any value (None -> empty string)."""
    return html.escape("" if value is None else str(value), quote=True)


def _safe_url(url):
    """Only plain http(s) links are ever rendered as links - never
    javascript:, data:, etc. from advisory fields."""
    url = (url or "").strip()
    return url if re.match(r"^https?://", url, re.IGNORECASE) else None


def _link(url, label=None):
    safe = _safe_url(url)
    if not safe:
        return _e(label or url)
    return f'<a href="{_e(safe)}" rel="noopener noreferrer">{_e(label or safe)}</a>'


def _cve_links(cve_field):
    """'CVE-2019-10943, CVE-2019-10944' -> links to NVD; anything else
    (e.g. a vendor advisory id like SA25P002) stays plain escaped text."""
    parts = []
    for item in str(cve_field or "").split(","):
        item = item.strip()
        if not item:
            continue
        if _CVE_RE.match(item):
            parts.append(_link(f"https://nvd.nist.gov/vuln/detail/{item}", item))
        else:
            parts.append(_e(item))
    return ", ".join(parts)


def _anchor(ip):
    return "host-" + re.sub(r"[^A-Za-z0-9]+", "-", str(ip)).strip("-")


def _badge(text, css):
    return f'<span class="badge {css}">{_e(text)}</span>'


def _sev_badge(sev):
    return _badge(sev, SEV_CLASS.get(sev, "sev-info"))


def _sorted_hosts(data):
    return sorted(data, key=lambda h: (-(h.get("risk_score") or 0), str(h.get("ip"))))


def _is_ot_relevant(host):
    return bool(
        host.get("risks")
        or host.get("vendor")
        or any(s.get("category") == "ot" for s in host.get("services", []))
    )


def _top_finding(host):
    risks = host.get("risks", [])
    if not risks:
        return None
    return min(risks, key=lambda f: SEVERITY_ORDER.index(f["severity"])
               if f.get("severity") in SEVERITY_ORDER else 99)


# --------------------------------------------------------------------------
# CSS
# --------------------------------------------------------------------------

CSS = """
body{margin:0;background:#e9edf2;color:#1c2733;font-family:-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;line-height:1.45}
.page{max-width:1040px;margin:0 auto;padding:28px 34px;background:#fff}
h1{font-size:26px;margin:0 0 4px;color:#14303f}
h2{font-size:19px;margin:34px 0 10px;padding-bottom:5px;border-bottom:2px solid #1f3a4d;color:#14303f}
h3{font-size:15px;margin:18px 0 6px;color:#14303f}
.sub{color:#5b6b7a;margin:0 0 4px}
table.data{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}
table.data th{background:#1f3a4d;color:#fff;text-align:left;padding:6px 8px;font-weight:600}
table.data td{border-bottom:1px solid #dde3ea;padding:6px 8px;vertical-align:top}
table.kv td:first-child{width:200px;color:#5b6b7a;font-weight:600}
table.tiles{border-collapse:separate;border-spacing:8px;width:100%;margin:6px -8px}
table.tiles td{background:#f3f6f9;border:1px solid #dde3ea;text-align:center;padding:10px 4px}
.tile-n{font-size:26px;font-weight:700;color:#14303f}
.tile-l{font-size:11px;color:#5b6b7a;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:700;white-space:nowrap}
.sev-critical{background:#b71c1c;color:#fff}
.sev-high{background:#e64a19;color:#fff}
.sev-medium{background:#f9a825;color:#3a2a00}
.sev-low{background:#1e88e5;color:#fff}
.sev-info{background:#90a4ae;color:#fff}
.cov-full{background:#2e7d32;color:#fff}
.cov-partial{background:#f9a825;color:#3a2a00}
.cov-limited{background:#c62828;color:#fff}
.cov-na{background:#b0bec5;color:#263238}
.det{background:#fff;color:#37474f;border:1px solid #90a4ae}
.posture{padding:12px 16px;margin:10px 0;font-size:16px;font-weight:700;border-radius:3px}
.security-posture{background:#f3f6f9;border-left:4px solid #1f3a4d;padding:8px 12px;margin:10px 0;font-size:13px;border-radius:2px}
.callout{border-left:4px solid #f9a825;background:#fff8e1;padding:10px 14px;margin:14px 0}
.note{border-left:4px solid #90a4ae;background:#f3f6f9;padding:8px 14px;margin:10px 0;font-size:13px}
.host{border:1px solid #cfd8e3;margin:20px 0;border-radius:3px}
.host-head{background:#f3f6f9;padding:10px 14px;border-bottom:1px solid #cfd8e3}
.host-body{padding:6px 14px 12px}
.finding{border-left:4px solid #cfd8e3;margin:10px 0;padding:4px 12px}
.finding.sev-critical-b{border-color:#b71c1c}.finding.sev-high-b{border-color:#e64a19}
.finding.sev-medium-b{border-color:#f9a825}.finding.sev-low-b{border-color:#1e88e5}
.muted{color:#5b6b7a}.small{font-size:12px}
code{background:#eef1f5;padding:1px 4px;border-radius:2px;font-size:12px;word-break:break-all}
pre{background:#0f1b26;color:#d6e2ee;padding:8px 10px;font-size:11px;white-space:pre-wrap;word-break:break-all;margin:4px 0}
details{margin:6px 0}summary{cursor:pointer;color:#1f3a4d;font-weight:600}
a{color:#0b5cad}
.gap{color:#8a4b00}
.footer{margin-top:36px;padding-top:10px;border-top:1px solid #cfd8e3;color:#5b6b7a;font-size:12px}
@media print{body{background:#fff}.page{padding:0;max-width:none}.host{page-break-inside:auto}details>*{display:block}}
"""


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------

def _severity_counts(data):
    counts = Counter()
    for h in data:
        for f in h.get("risks", []):
            counts[f.get("severity")] += 1
    return counts


def _posture(counts):
    if counts["Critical"]:
        return "Critical exposure identified", "sev-critical"
    if counts["High"]:
        return "High-risk exposure identified", "sev-high"
    if counts["Medium"]:
        return "Moderate exposure identified", "sev-medium"
    if counts["Low"]:
        return "Low-severity issues only", "sev-low"
    return "No findings among the checks that could be performed - see Coverage", "sev-info"


def _section_summary(data, ctx):
    counts = _severity_counts(data)
    label, css = _posture(counts)
    ot_hosts = sum(1 for h in data if h.get("type") not in (None, "Unknown"))
    cov = (ctx.get("coverage") or {}).get("host_status_counts")
    gap_hosts = (cov.get("partial", 0) + cov.get("limited", 0)) if cov else None

    out = ['<h2>1. Executive Summary</h2>',
           f'<div class="posture {css}">{_e(label)}</div>']

    tiles = [
        (len(data), "Hosts discovered"),
        (ot_hosts, "OT assets identified"),
        (counts["Critical"], "Critical findings"),
        (counts["High"], "High findings"),
        (counts["Medium"] + counts["Low"], "Medium / Low"),
        ("n/a" if gap_hosts is None else gap_hosts, "Hosts with coverage gaps"),
    ]
    out.append('<table class="tiles"><tr>' + "".join(
        f'<td><div class="tile-n">{_e(n)}</div><div class="tile-l">{_e(l)}</div></td>' for n, l in tiles
    ) + '</tr></table>')

    if gap_hosts:
        out.append(
            f'<div class="callout"><b>Read this with the Coverage section.</b> {gap_hosts} host(s) were only '
            f'partially or minimally assessed. For those hosts, <b>no finding does not mean no vulnerability</b> '
            f'&mdash; it may mean the check could not run.</div>'
        )
    elif cov is None:
        out.append('<div class="note">Coverage information was not recorded for this report.</div>')

    ranked = [h for h in _sorted_hosts(data) if (h.get("risk_score") or 0) > 0][:5]
    if ranked:
        out.append('<h3>Highest-risk assets</h3><table class="data"><tr><th>Host</th><th>Type</th>'
                   '<th>Vendor / Model</th><th>Score</th><th>Top finding</th></tr>')
        for h in ranked:
            top = _top_finding(h)
            out.append(
                f'<tr><td><a href="#{_anchor(h["ip"])}">{_e(h["ip"])}</a></td><td>{_e(h.get("type"))}</td>'
                f'<td>{_e(" ".join(x for x in (h.get("vendor"), h.get("model")) if x) or "-")}</td>'
                f'<td>{_e(h.get("risk_score"))}/100</td>'
                f'<td>{_sev_badge(top["severity"]) if top else ""} {_e(top["finding"][:140]) if top else "-"}</td></tr>'
            )
        out.append("</table>")
    return "".join(out)


def _section_methodology(ctx):
    out = ['<h2>2. Scope &amp; Methodology</h2>']

    if not ctx:
        out.append('<div class="note">Scan metadata was not recorded for this report (the snapshot was created '
                   'by an older version of OT-Recon), so scope, profile and coverage details are unavailable.</div>')
    else:
        prof = ctx.get("profile") or {}
        ps = prof.get("settings") or {}
        scope = ctx.get("scope") or {}
        rows = [
            ("Target", ctx.get("target")),
            ("Addresses in scope", scope.get("address_count")),
            ("Allowed scope (policy)", ", ".join(scope.get("allowed") or []) or "none configured"),
            ("Guardrails overridden", "; ".join(scope.get("overridden") or []) or "none"),
            ("Excluded from scan", (", ".join(ctx.get("excluded") or []) or "no do-not-scan entries")
             + ("; this machine itself" if ctx.get("exclude_self") else "")),
            ("Scan profile", f'{prof.get("name", "?")} - {prof.get("description", "")}'),
            ("Timing / pacing", f'TCP {ps.get("tcp_timing")}, UDP {ps.get("udp_timing")}, '
                                f'delay {ps.get("scan_delay") or "default"}, retries {ps.get("max_retries") if ps.get("max_retries") is not None else "default"}'),
            ("Fingerprint workers / timeout", f'{ps.get("workers")} / {ps.get("nmap_script_timeout")}s'),
            ("TCP ports scanned", ctx.get("tcp_ports")),
            ("UDP scanned", f'yes ({ctx.get("udp_ports")})' if ctx.get("udp_scanned") else "no"),
            ("Live NVD lookup", "enabled" if ctx.get("cve_live") else "disabled (local database only)"),
            ("Deep OT inspection", "enabled (CIP backplane, S7comm keyswitch/SZL, Modbus MEI)" if ctx.get("deep_inspection") else "disabled (standard fingerprinting)"),
            ("Started / finished (UTC)", f'{ctx.get("started")} / {ctx.get("finished")}'),
            ("Operator", ctx.get("operator")),
            ("OT-Recon / Nmap", f'{ctx.get("tool_version")} / {ctx.get("nmap_version") or "unknown"}'),
            ("Commands executed", ctx.get("commands_run")),
            ("Audit log", ctx.get("audit_log") or "not recorded"),
        ]
        out.append('<table class="data kv">' + "".join(
            f'<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>' for k, v in rows) + '</table>')

    out.append(
        '<h3>What was done</h3><ul>'
        '<li>Host discovery (ping sweep) and a TCP connect scan of OT and IT service ports.</li>'
        '<li>Native read-only deep protocol inspection (Siemens S7comm SZL CPU state &amp; protection, Rockwell '
        'EtherNet/IP CIP backplane chassis enumeration, Modbus TCP MEI device identification) and safe vendor-specific probes.</li>'
        '<li>Evidence-based device classification and rule-based exposure assessment.</li>'
        '<li>Correlation of identified products and firmware against known vulnerabilities (curated local '
        'database, plus NVD when enabled).</li></ul>'
        '<h3>What was deliberately <i>not</i> done</h3><ul>'
        '<li>No exploitation, no proof-of-concept or crash-inducing tests.</li>'
        '<li>No authentication attempts or credential guessing.</li>'
        '<li>No configuration changes and no write operations to any device.</li></ul>'
    )
    return "".join(out)


def _section_inventory(data):
    out = ['<h2>3. Asset Inventory</h2>']
    if not data:
        return out[0] + '<p class="muted">No hosts were discovered.</p>'

    out.append('<table class="data"><tr><th>Host</th><th>Type</th><th>Vendor</th><th>Model</th><th>Firmware</th>'
               '<th>Services</th><th>Risk</th><th>Coverage</th></tr>')
    for h in _sorted_hosts(data):
        protos = list(dict.fromkeys(
            p["protocol"] for p in h.get("ot_ports", [])
            if p.get("state", "open") == "open" and p.get("protocol")))
        sev = h.get("risk_severity")
        risk = (_sev_badge(sev) + f' {_e(h.get("risk_score"))}') if sev and sev != "None" else '<span class="muted">none</span>'
        cstat = (h.get("coverage") or {}).get("status")
        cov = _badge(COVERAGE_LABEL[cstat], COVERAGE_CLASS[cstat]) if cstat in COVERAGE_LABEL else '<span class="muted">not recorded</span>'
        out.append(
            f'<tr><td><a href="#{_anchor(h["ip"])}">{_e(h.get("ip"))}</a></td><td>{_e(h.get("type"))}</td>'
            f'<td>{_e(h.get("vendor") or "-")}</td><td>{_e(h.get("model") or "-")}</td>'
            f'<td>{_e(h.get("firmware") or "-")}</td><td>{_e(", ".join(protos) or "-")}</td>'
            f'<td>{risk}</td><td>{cov}</td></tr>'
        )
    out.append("</table>")
    return "".join(out)


def _remediation_groups(data):
    groups = {}
    for h in data:
        for f in h.get("risks", []):
            prio = f.get("remediation_priority") or "P4"
            g = groups.setdefault((prio, f.get("finding")), {
                "priority": prio, "finding": f.get("finding"), "severity": f.get("severity"),
                "recommendation": f.get("recommendation"), "detection": f.get("detection"),
                "cve": f.get("cve"), "hosts": [],
            })
            g["hosts"].append(h.get("ip"))
    return sorted(groups.values(), key=lambda g: (g["priority"], -len(g["hosts"]), str(g["finding"])))


def _section_remediation(data):
    out = ['<h2>4. Remediation Plan</h2>']
    groups = _remediation_groups(data)
    if not groups:
        return out[0] + '<p class="muted">No findings to remediate.</p>'

    out.append('<p class="muted small">Ordered by priority (P1 = address first), then by number of affected hosts. '
               'Priorities express relative order only &mdash; set timelines to suit your change windows and '
               'operational constraints; on a live control network, schedule changes with the plant.</p>')
    out.append('<table class="data"><tr><th>Priority</th><th>Finding</th><th>Hosts</th><th>Recommended action</th></tr>')
    for g in groups:
        out.append(
            f'<tr><td><b>{_e(g["priority"])}</b><br>{_sev_badge(g["severity"])}</td>'
            f'<td>{_e(g["finding"])}'
            f'{"<br><span class=small>" + _cve_links(g["cve"]) + "</span>" if g["cve"] else ""}'
            f'<br>{_badge(g["detection"], "det") if g["detection"] else ""}</td>'
            f'<td>{_e(", ".join(sorted(set(map(str, g["hosts"])))))}</td>'
            f'<td>{_e(g["recommendation"] or "-")}</td></tr>'
        )
    out.append("</table>")
    return "".join(out)


def _section_coverage(data, ctx):
    out = ['<h2>5. Coverage &amp; Limitations</h2>',
           '<p>A report that lists only what was found invites the conclusion that everything else is fine. '
           'This section states what could <b>not</b> be assessed.</p>']

    scov = (ctx or {}).get("coverage")
    if scov is None:
        out.append('<div class="note">Coverage details were not recorded for this report.</div>')
    else:
        counts = scov.get("host_status_counts", {})
        out.append('<p>' + " &nbsp; ".join(
            f'{_badge(COVERAGE_LABEL[k], COVERAGE_CLASS[k])} {counts.get(k, 0)}'
            for k in ("full", "partial", "limited", "n/a")) + '</p>')
        if scov.get("gaps"):
            out.append("<h3>Scan-wide gaps</h3><ul>" + "".join(
                f'<li class="gap">{_e(g)}</li>' for g in scov["gaps"]) + "</ul>")
        if scov.get("notes"):
            out.append("<h3>Notes</h3><ul>" + "".join(f"<li>{_e(n)}</li>" for n in scov["notes"]) + "</ul>")

    gap_hosts = [h for h in _sorted_hosts(data) if (h.get("coverage") or {}).get("gaps")]
    if gap_hosts:
        out.append("<h3>Per-host gaps</h3>")
        for h in gap_hosts:
            out.append(f'<p><a href="#{_anchor(h["ip"])}"><b>{_e(h["ip"])}</b></a> '
                       f'{_badge(COVERAGE_LABEL[h["coverage"]["status"]], COVERAGE_CLASS[h["coverage"]["status"]])}</p><ul>'
                       + "".join(f'<li class="gap">{_e(g)}</li>' for g in h["coverage"]["gaps"]) + "</ul>")

    out.append(
        '<h3>Detection confidence</h3><p class="small muted">Each finding states how it was established:</p><table class="data">'
        + "".join(f'<tr><td>{_badge(k, "det")}</td><td>{_e(v)}</td></tr>' for k, v in DETECTION_LEVELS.items())
        + "</table>")
    return "".join(out)


def _render_finding(f):
    sev = f.get("severity", "Info")
    out = [f'<div class="finding {SEV_CLASS.get(sev, "sev-info")}-b">'
           f'{_sev_badge(sev)} {_badge(f.get("remediation_priority") or "-", "det")} '
           f'{_badge(f.get("detection") or "-", "det")} <b>{_e(f.get("finding"))}</b>']
    if f.get("impact") or f.get("likelihood"):
        out.append(f'<div class="small muted">Impact: {_e(f.get("impact") or "-")} &middot; '
                   f'Likelihood: {_e(f.get("likelihood") or "-")}'
                   f'{" &middot; Related ports: " + _e(", ".join(map(str, f["related_ports"]))) if f.get("related_ports") else ""}</div>')
    if f.get("recommendation"):
        out.append(f'<div><b>Action:</b> {_e(f["recommendation"])}</div>')
    refs = []
    if f.get("cve"):
        refs.append(_cve_links(f["cve"]))
    if _safe_url(f.get("advisory")):
        refs.append(_link(f["advisory"], "advisory"))
    if refs:
        out.append(f'<div class="small">Reference: {" &middot; ".join(refs)}</div>')
    out.append("</div>")
    return "".join(out)


def _render_host(h):
    cov = h.get("coverage") or {}
    cstat = cov.get("status")
    sev = h.get("risk_severity")
    head = [f'<div class="host" id="{_anchor(h["ip"])}"><div class="host-head">'
            f'<b style="font-size:16px">{_e(h.get("ip"))}</b> &nbsp;{_e(h.get("type"))} '
            f'&middot; {_e(" ".join(x for x in (h.get("vendor"), h.get("model")) if x) or "vendor unknown")}'
            f'{" &middot; fw " + _e(h["firmware"]) if h.get("firmware") else ""} &nbsp;']
    if sev and sev != "None":
        head.append(f'{_sev_badge(sev)} <b>{_e(h.get("risk_score"))}/100</b> ')
    if cstat in COVERAGE_LABEL:
        head.append(f'Coverage: {_badge(COVERAGE_LABEL[cstat], COVERAGE_CLASS[cstat])}')
    head.append("</div><div class=\"host-body\">")
    out = ["".join(head)]

    if h.get("summary"):
        out.append(f'<p class="muted">{_e(h["summary"])}</p>')

    # Deep Inspection & Security Posture (Native S7/CIP SZL Inspection)
    if h.get("keyswitch_mode") or h.get("protection_level") or h.get("mlfb") or h.get("component_name"):
        sp = ['<div class="security-posture"><b>Deep Protocol Inspection &amp; Security Posture:</b><br>']
        if h.get("keyswitch_mode"):
            kw = h["keyswitch_mode"]
            kw_badge = "sev-critical" if "REMOTE" in kw else ("sev-low" if kw == "RUN" else "sev-medium")
            sp.append(f'Keyswitch Mode: {_badge(kw, kw_badge)} ')
        if h.get("protection_level"):
            prot = h["protection_level"]
            prot_badge = "sev-critical" if "Level 1" in prot else ("sev-medium" if "Level 2" in prot else "sev-low")
            sp.append(f'&middot; Protection: {_badge(prot, prot_badge)} ')
        if h.get("component_name"):
            sp.append(f'&middot; System / Project: <b>{_e(h["component_name"])}</b> ')
        if h.get("mlfb"):
            sp.append(f'&middot; MLFB: <code>{_e(h["mlfb"])}</code> ')
        sp.append('</div>')
        out.append("".join(sp))

    # Chassis / Backplane Rack Layout (Native CIP Backplane Scanning)
    if h.get("chassis_modules"):
        chassis = h["chassis_modules"]
        out.append('<h3>Chassis / Backplane Rack Layout</h3>')
        out.append('<table class="data"><tr><th>Slot</th><th>Module Model</th><th>Device Type</th><th>Firmware</th></tr>')
        for m in chassis:
            is_cpu = "Programmable Logic Controller" in m.get("device_type", "")
            row_style = ' style="background:#f0f7fc;font-weight:600"' if is_cpu else ''
            cpu_badge = ' <span class="badge sev-low">CPU</span>' if is_cpu else ''
            out.append(
                f'<tr{row_style}><td>Slot {m.get("slot", 0)}</td>'
                f'<td>{_e(m.get("model", "-"))}{cpu_badge}</td>'
                f'<td>{_e(m.get("device_type", "-"))}</td>'
                f'<td>{_e(m.get("firmware", "-"))}</td></tr>'
            )
        out.append('</table>')

    services = h.get("services") or h.get("ot_ports") or []
    if services:
        out.append('<table class="data"><tr><th>Port</th><th>State</th><th>Protocol</th><th>Category</th>'
                   '<th>Authentication</th></tr>' + "".join(
            f'<tr><td>{_e(s.get("port"))}/{_e(s.get("transport", "tcp"))}</td><td>{_e(s.get("state"))}</td>'
            f'<td>{_e(s.get("protocol") or s.get("service") or "-")}</td><td>{_e(s.get("category") or "-")}</td>'
            f'<td>{_e(s.get("authentication") or "-")}</td></tr>' for s in services) + "</table>")

    findings = sorted(h.get("risks", []), key=lambda f: SEVERITY_ORDER.index(f["severity"])
                      if f.get("severity") in SEVERITY_ORDER else 99)
    if findings:
        out.append("<h3>Findings</h3>" + "".join(_render_finding(f) for f in findings))
    else:
        out.append('<p class="muted">No findings were raised for this host'
                   + (" - but see its coverage gaps below." if cov.get("gaps") else ".") + "</p>")

    if cov.get("gaps"):
        out.append("<h3>Coverage gaps</h3><ul>" + "".join(f'<li class="gap">{_e(g)}</li>' for g in cov["gaps"]) + "</ul>")

    # --- evidence: what the device actually told us ---
    probes = h.get("probes") or []
    evidence = h.get("evidence") or []
    if probes or evidence or cov.get("checks"):
        ev = ["<details><summary>Evidence &amp; checks performed</summary>"]
        if evidence:
            ev.append("<h3>Identification evidence</h3><ul>" + "".join(f"<li>{_e(x)}</li>" for x in evidence) + "</ul>")
        if h.get("detection_method"):
            ev.append(f'<p class="small muted">Classification method: {_e(h["detection_method"])} '
                      f'(confidence {_e(h.get("confidence"))}'
                      f'{", score " + _e(h["confidence_score"]) if h.get("confidence_score") is not None else ""}).</p>')
        if cov.get("checks"):
            ev.append('<h3>Checks</h3><table class="data"><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' + "".join(
                f'<tr><td>{_e(c["check"])}</td><td>{_e(c["status"])}</td><td>{_e(c.get("detail"))}</td></tr>'
                for c in cov["checks"]) + "</table>")
        for p in probes:
            ev.append(
                f'<h3>Probe: {_e(p.get("probe"))} {_badge(p.get("status"), PROBE_CLASS.get(p.get("status"), "cov-na"))}</h3>'
                f'<div class="small muted">Command: <code>{_e(p.get("command"))}</code> &middot; '
                f'{_e(p.get("duration_s"))}s{(" &middot; " + _e(p["error"])) if p.get("error") else ""}</div>'
                f'<pre>{_e(p.get("output") or "(no output)")}</pre>')
        ev.append("</details>")
        out.append("".join(ev))

    out.append("</div></div>")
    return "".join(out)


def _section_hosts(data):
    out = ['<h2>6. Detailed Findings by Host</h2>']
    relevant = [h for h in _sorted_hosts(data) if _is_ot_relevant(h)]
    others = [h for h in _sorted_hosts(data) if not _is_ot_relevant(h)]
    if not data:
        return out[0] + '<p class="muted">No hosts to report.</p>'
    out.extend(_render_host(h) for h in relevant)
    if others:
        out.append('<h3>Hosts with no OT services and no findings</h3><p class="small muted">' + ", ".join(
            f'<a href="#{_anchor(h["ip"])}">{_e(h["ip"])}</a>' for h in others) + "</p>")
        out.extend(_render_host(h) for h in others)
    return "".join(out)


def _section_changes(diff, previous_timestamp):
    out = ['<h2>7. Changes Since the Previous Scan</h2>']
    if diff is None:
        return out[0] + '<p class="muted">No previous scan was available to compare against.</p>'

    out.append(f'<p class="muted">Compared with the scan from {_e(previous_timestamp or "an earlier run")}.</p>')
    if not (diff["new_hosts"] or diff["removed_hosts"] or diff["host_changes"]):
        return "".join(out) + "<p>No changes detected.</p>"

    if diff["new_hosts"]:
        out.append(f'<p><b>New hosts ({len(diff["new_hosts"])}):</b> {_e(", ".join(diff["new_hosts"]))}</p>')
    if diff["removed_hosts"]:
        out.append(f'<p><b>No longer responding ({len(diff["removed_hosts"])}):</b> {_e(", ".join(diff["removed_hosts"]))}</p>')

    for ip, ch in sorted(diff["host_changes"].items()):
        items = []   # every entry is escaped HTML
        if ch.get("new_ports"):
            items.append(_e("Ports opened: " + ", ".join(f"{p}/{t}" for p, t in ch["new_ports"])))
        if ch.get("closed_ports"):
            items.append(_e("Ports closed: " + ", ".join(f"{p}/{t}" for p, t in ch["closed_ports"])))
        for field in ("vendor", "model", "firmware"):
            if ch.get(f"{field}_change"):
                old, new = ch[f"{field}_change"]
                items.append(_e(f"{field.title()} changed: {old} -> {new}"))
        if ch.get("severity_change"):
            old, new = ch["severity_change"]
            items.append(_e(f"Overall severity: {old} -> {new}"))
        for f in ch.get("new_findings", []):
            items.append("<b>NEW</b> " + _e(f'{f.get("severity", "")} - {f.get("finding", "")}'))
        for f in ch.get("resolved_findings", []):
            items.append("<b>RESOLVED</b> " + _e(f'{f.get("severity", "")} - {f.get("finding", "")}'))
        out.append(f'<h3><a href="#{_anchor(ip)}">{_e(ip)}</a></h3><ul>'
                   + "".join(f"<li>{x}</li>" for x in items) + "</ul>")
    return "".join(out)


def _section_appendix():
    weights = ", ".join(f"{k} = {v}" for k, v in SEVERITY_WEIGHTS.items())
    mult = ", ".join(f"{k} x{v}" for k, v in ASSET_MULTIPLIERS.items())
    return (
        '<h2>Appendix: Definitions</h2>'
        '<table class="data kv">'
        f'<tr><td>Risk score (0-100)</td><td>Sum of finding weights ({_e(weights)}), multiplied by an asset-criticality '
        f'factor ({_e(mult)}; other types x1.0), capped at 100. It ranks hosts for triage; it is not a '
        f'probability of compromise.</td></tr>'
        '<tr><td>Severity</td><td>Critical / High / Medium / Low / Info - the seriousness of the issue if it applies. '
        'Info findings are things to verify, not confirmed problems.</td></tr>'
        '<tr><td>Priority P1-P5</td><td>Relative remediation order only (P1 first).</td></tr>'
        '<tr><td>Coverage</td><td><b>Full</b>: assessed with no gaps. <b>Partial</b>: assessed but some checks could '
        'not run. <b>Limited</b>: OT services present but nothing authoritative was learned. '
        '<b>No OT services</b>: OT checks do not apply.</td></tr></table>'
        '<h3>Limitations</h3><p class="small">Results reflect the network as reachable from the scanning host at the '
        'time of the scan; a different vantage point may expose different services. Vulnerability matching uses a '
        'curated local database (and NVD when enabled) and is not exhaustive. Firmware-dependent checks are '
        'inconclusive where firmware could not be read. This report supports, and does not replace, review by '
        'someone who knows the plant.</p>'
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def render_html(data, scan_ctx=None, diff=None, previous_timestamp=None, snapshot_timestamp=None):
    ctx = scan_ctx or {}
    now = datetime.now().astimezone()
    tz_name = now.strftime("%Z") or now.strftime("%z")
    generated = now.strftime(f"%Y-%m-%d %H:%M ({tz_name})")
    target = ctx.get("target")

    body = [
        f'<h1>OT Network Assessment Report</h1>'
        f'<p class="sub">{_e("Target: " + str(target)) if target else "Target: not recorded"}'
        f'{" &middot; Scan: " + _e(snapshot_timestamp) if snapshot_timestamp else ""}</p>'
        f'<p class="sub small">Generated {_e(generated)} by OT-Recon v{_e(ctx.get("tool_version") or __version__)}</p>',
        _section_summary(data, ctx),
        _section_methodology(scan_ctx),
        _section_inventory(data),
        _section_remediation(data),
        _section_coverage(data, ctx),
        _section_hosts(data),
        _section_changes(diff, previous_timestamp),
        _section_appendix(),
        '<div class="footer">Generated by OT-Recon. Contains asset and vulnerability information - '
        'handle according to your organisation\'s data-classification policy.</div>',
    ]

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        # Belt and braces: the page has no scripts, and this forbids any.
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        f'<title>OT Network Assessment{" - " + _e(target) if target else ""}</title>'
        f'<style>{CSS}</style></head><body><div class="page">' + "".join(body) + "</div></body></html>"
    )


def export_html(data, path, scan_ctx=None, diff=None, previous_timestamp=None, snapshot_timestamp=None):
    content = render_html(data, scan_ctx=scan_ctx, diff=diff,
                          previous_timestamp=previous_timestamp, snapshot_timestamp=snapshot_timestamp)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] HTML report written to {path}")
