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


def _purdue_level(device_type):
    """Map classified device type to Purdue Model (ISA-95) operational hierarchy."""
    dt = str(device_type or "").lower()
    if "safety" in dt or "guardlogix" in dt or "safedesigner" in dt:
        return "L1: Safety / SIS", "purdue-l1-safety"
    if "plc" in dt or "programmable logic" in dt or "controller" in dt:
        return "L1: Basic Control (PLC)", "purdue-l1"
    if "adapter" in dt or "discrete" in dt or "drive" in dt or "field" in dt:
        return "L1: Field Device / I/O", "purdue-l1"
    if "hmi" in dt or "panelview" in dt or "simatic hmi" in dt or "screen" in dt or "human-machine" in dt:
        return "L2: Supervisory (HMI)", "purdue-l2"
    if "server" in dt or "scada" in dt or "historian" in dt or "workstation" in dt or "industrial server" in dt:
        return "L3: Operations Infrastructure", "purdue-l3"
    return "Unclassified / IT Host", "purdue-na"


def _compute_iec62443_matrix(data):
    """Map detected assets and exposures against IEC 62443 Foundational Requirements."""
    reqs = [
        {
            "id": "FR 1",
            "name": "Identification & Authentication Control (IAC)",
            "standard": "IEC 62443-3-3 SR 1.1 / 1.2",
            "condition": lambda h: any(p.get("protocol") in ("Modbus", "S7", "EtherNet/IP", "HTTP", "Telnet", "FTP")
                                       for p in h.get("ot_ports", []) if p.get("state", "open") == "open"),
            "risk": "Industrial control protocols operate in cleartext without cryptographic identification or mutual authentication, allowing unauthorized control commands.",
            "recommendation": "Deploy OT-aware micro-segmentation conduits, industrial firewall rules, and migrate to secure protocol profiles (CIP Security, S7comm TLS, Modbus Security) where supported."
        },
        {
            "id": "FR 2",
            "name": "Use Control & Mode Authorization (UC)",
            "standard": "IEC 62443-3-3 SR 2.1 / 2.3",
            "condition": lambda h: "REMOTE" in str(h.get("keyswitch_mode") or "").upper() or "LEVEL 1" in str(h.get("protection_level") or "").upper() or str(h.get("protection_level")) == "1",
            "risk": "Controllers operating in REMOTE mode or Protection Level 1 allow over-the-network ladder logic overwrites, diagnostic force-coils, and CPU halt commands.",
            "recommendation": "Enforce physical keyswitch position in RUN (Hard Lock) during active plant production. Configure memory block and DB read/write protection passwords."
        },
        {
            "id": "FR 3",
            "name": "System Integrity & Vulnerability Management (SI)",
            "standard": "IEC 62443-4-2 EDR 3.1 / 3.2",
            "condition": lambda h: any(f.get("severity") in ("Critical", "High") for f in h.get("risks", [])),
            "risk": "Discovered field devices run vulnerable firmware versions with publicly cataloged CVEs, exposing systems to denial of service, memory corruption, or logic manipulation.",
            "recommendation": "Establish a validated firmware patch schedule for upcoming plant maintenance turnarounds; enforce virtual patching via deep packet inspection rules."
        },
        {
            "id": "FR 4",
            "name": "Data Confidentiality & Cleartext Control (DC)",
            "standard": "IEC 62443-3-3 SR 4.1",
            "condition": lambda h: any(p.get("protocol") in ("HTTP", "Telnet", "FTP") or p.get("port") in (80, 23, 21)
                                       for p in h.get("ot_ports", []) if p.get("state", "open") == "open"),
            "risk": "Unencrypted administrative protocols transmit sensitive industrial setpoints, engineering telemetry, and credentials in plaintext across the LAN.",
            "recommendation": "Disable plaintext HTTP/Telnet/FTP management services on controllers; enforce encrypted HTTPS/SSH management sessions with strict cipher suites."
        },
        {
            "id": "FR 5",
            "name": "Restricted Data Flow & Conduit Separation (RDF)",
            "standard": "IEC 62443-3-2 Zone & Conduit Architecture",
            "condition": lambda h: len(set(p.get("category") for p in h.get("services", []) if p.get("category"))) > 1
                                   or any(p.get("port") in (80, 443, 22, 161) for p in h.get("ot_ports", []) if p.get("state", "open") == "open")
                                   and any(p.get("protocol") in ("S7", "EtherNet/IP", "Modbus") for p in h.get("ot_ports", []) if p.get("state", "open") == "open"),
            "risk": "Controllers expose dual IT and OT services on the same interface, bridging Level 1 control loops directly with supervisory or plant enterprise networks.",
            "recommendation": "Enforce ISA-95 zone boundaries; isolate real-time industrial control I/O from general management traffic using dedicated conduits and VLANs."
        },
    ]

    matrix = []
    for r in reqs:
        affected = [h["ip"] for h in data if r["condition"](h)]
        if not data:
            status = "Compliant"
            status_css = "iec-status-compliant"
        elif affected:
            status = "Non-Compliant" if r["id"] in ("FR 1", "FR 2", "FR 3") else "Exposed"
            status_css = "iec-status-noncompliant" if status == "Non-Compliant" else "iec-status-exposed"
        else:
            status = "Compliant"
            status_css = "iec-status-compliant"

        matrix.append({
            "id": r["id"],
            "name": r["name"],
            "standard": r["standard"],
            "status": status,
            "status_css": status_css,
            "affected_count": len(affected),
            "affected_hosts": affected,
            "risk": r["risk"],
            "recommendation": r["recommendation"],
        })
    return matrix


# --------------------------------------------------------------------------
# CSS
# --------------------------------------------------------------------------

CSS = """
body{margin:0;background:#0f172a;color:#1e293b;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5}
.page{max-width:1120px;margin:24px auto;padding:32px 40px;background:#ffffff;border-radius:10px;box-shadow:0 10px 25px -5px rgba(0,0,0,0.1),0 8px 10px -6px rgba(0,0,0,0.1)}
h1{font-size:26px;margin:0 0 4px;color:#0f172a;letter-spacing:-.02em}
h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid #0f172a;color:#0f172a;display:flex;align-items:center;justify-content:space-between}
h3{font-size:15px;margin:20px 0 8px;color:#1e293b}
.sub{color:#64748b;margin:0 0 6px}
table.data{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
table.data th{background:#0f172a;color:#f8fafc;text-align:left;padding:8px 10px;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
table.data td{border-bottom:1px solid #e2e8f0;padding:8px 10px;vertical-align:top}
table.data tr:hover td{background:#f8fafc}
table.kv td:first-child{width:220px;color:#475569;font-weight:600}
table.tiles{border-collapse:separate;border-spacing:10px;width:100%;margin:10px -10px}
table.tiles td{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;text-align:center;padding:12px 6px;box-shadow:0 1px 3px rgba(0,0,0,0.05)}
.tile-n{font-size:28px;font-weight:700;color:#0f172a}
.tile-l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-top:2px;font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.sev-critical{background:#dc2626;color:#fff}
.sev-high{background:#ea580c;color:#fff}
.sev-medium{background:#f59e0b;color:#1f2937}
.sev-low{background:#2563eb;color:#fff}
.sev-info{background:#64748b;color:#fff}
.cov-full{background:#16a34a;color:#fff}
.cov-partial{background:#f59e0b;color:#1f2937}
.cov-limited{background:#dc2626;color:#fff}
.cov-na{background:#94a3b8;color:#0f172a}
.det{background:#f1f5f9;color:#334155;border:1px solid #cbd5e1}
.posture{padding:14px 18px;margin:12px 0;font-size:16px;font-weight:700;border-radius:6px;display:flex;align-items:center;justify-content:space-between}
.security-posture{background:#f8fafc;border-left:4px solid #0f172a;padding:10px 14px;margin:10px 0;font-size:13px;border-radius:4px;line-height:1.5}
.callout{border-left:4px solid #f59e0b;background:#fffbeb;padding:12px 16px;margin:14px 0;border-radius:4px;color:#78350f}
.note{border-left:4px solid #64748b;background:#f8fafc;padding:10px 14px;margin:10px 0;font-size:13px;border-radius:4px;color:#334155}
.host{border:1px solid #e2e8f0;margin:24px 0;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.05);overflow:hidden}
.host-head{background:#f8fafc;padding:12px 16px;border-bottom:1px solid #e2e8f0;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}
.host-body{padding:14px 18px 18px}
.finding{border-left:4px solid #cbd5e1;margin:12px 0;padding:8px 14px;background:#f8fafc;border-radius:4px}
.finding.sev-critical-b{border-color:#dc2626}.finding.sev-high-b{border-color:#ea580c}
.finding.sev-medium-b{border-color:#f59e0b}.finding.sev-low-b{border-color:#2563eb}
.muted{color:#64748b}.small{font-size:12px}
code{background:#f1f5f9;color:#0f172a;padding:2px 5px;border-radius:3px;font-size:12px;word-break:break-all}
pre{background:#0f172a;color:#e2e8f0;padding:10px 14px;font-size:11px;white-space:pre-wrap;word-break:break-all;margin:6px 0;border-radius:6px}
details{margin:8px 0}summary{cursor:pointer;color:#0f172a;font-weight:600}
a{color:#0284c7;text-decoration:none}a:hover{text-decoration:underline}
.gap{color:#b45309}
.footer{margin-top:40px;padding-top:14px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;text-align:center}

/* Navigation Bar */
.report-nav{background:#0f172a;padding:10px 18px;border-radius:8px;margin-bottom:24px;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px}
.nav-brand{font-weight:700;color:#38bdf8;font-size:13px;letter-spacing:.05em;text-transform:uppercase}
.nav-links{display:flex;flex-wrap:wrap;gap:10px}
.nav-links a{color:#cbd5e1;text-decoration:none;font-size:12px;font-weight:600;padding:3px 8px;border-radius:4px;transition:background .15s}
.nav-links a:hover{color:#ffffff;background:#1e293b}

/* Executive Header Banner */
.exec-header{background:linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);color:#fff;padding:24px 28px;border-radius:8px;margin-bottom:24px}
.exec-title{font-size:24px;font-weight:700;margin:0 0 4px;letter-spacing:-.02em}
.exec-sub{font-size:13px;color:#94a3b8;margin:0 0 16px}
.exec-meta-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(170px, 1fr));gap:12px;border-top:1px solid #334155;padding-top:14px;font-size:12px}
.exec-meta-label{color:#94a3b8;text-transform:uppercase;font-size:10px;font-weight:700;letter-spacing:.05em;margin-bottom:2px}
.exec-meta-val{color:#f8fafc;font-weight:600}

/* Severity Progress Bar */
.sev-bar-container{margin:14px 0 20px;background:#e2e8f0;border-radius:6px;height:16px;display:flex;overflow:hidden;box-shadow:inset 0 1px 2px rgba(0,0,0,0.1)}
.sev-bar-seg{height:100%}

/* Purdue Hierarchy Elements */
.purdue-l1{background:#0284c7;color:#fff}
.purdue-l1-safety{background:#7c3aed;color:#fff}
.purdue-l2{background:#059669;color:#fff}
.purdue-l3{background:#d97706;color:#fff}
.purdue-na{background:#64748b;color:#fff}
.purdue-grid{display:grid;grid-template-columns:repeat(auto-fit, minmax(210px, 1fr));gap:12px;margin:12px 0 18px}
.purdue-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;display:flex;flex-direction:column;justify-content:space-between}
.purdue-card-header{font-size:11px;font-weight:700;padding:2px 6px;border-radius:4px;display:inline-block;width:fit-content;margin-bottom:6px}
.purdue-card-val{font-size:22px;font-weight:700;color:#0f172a}
.purdue-card-desc{font-size:11px;color:#64748b;margin-top:2px}

/* IEC 62443 Compliance Badges */
.iec-status-noncompliant{background:#fef2f2;color:#991b1b;border:1px solid #fecaca;padding:3px 8px;border-radius:4px;font-weight:700;font-size:11px}
.iec-status-exposed{background:#fffbeb;color:#92400e;border:1px solid #fde68a;padding:3px 8px;border-radius:4px;font-weight:700;font-size:11px}
.iec-status-compliant{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0;padding:3px 8px;border-radius:4px;font-weight:700;font-size:11px}

/* Operational Risk Alerts */
.op-alert{border-left:4px solid;padding:12px 16px;margin:12px 0;border-radius:6px;font-size:13px;line-height:1.45}
.op-alert-danger{border-color:#dc2626;background:#fef2f2;color:#7f1d1d}
.op-alert-warning{border-color:#f59e0b;background:#fffbeb;color:#78350f}
.op-alert-info{border-color:#0284c7;background:#f0f9ff;color:#0c4a6e}
.op-alert-title{font-weight:700;margin-bottom:4px}

/* Visual Rack Chassis */
.rack-enclosure{background:#0f172a;border:2px solid #334155;border-radius:8px;padding:14px;margin:14px 0;color:#f8fafc}
.rack-header{font-weight:700;color:#94a3b8;font-size:12px;margin-bottom:10px;display:flex;justify-content:space-between;border-bottom:1px solid #1e293b;padding-bottom:6px}
.rack-slots{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px}
.rack-card{min-width:130px;max-width:145px;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 8px;display:flex;flex-direction:column;justify-content:space-between;font-size:11px}
.rack-card.is-cpu{border-top:4px solid #38bdf8;background:linear-gradient(180deg,#1e3a5f 0%,#1e293b 100%)}
.rack-card.is-comm{border-top:4px solid #34d399;background:linear-gradient(180deg,#134e4a 0%,#1e293b 100%)}
.rack-card.is-io{border-top:4px solid #94a3b8;background:linear-gradient(180deg,#334155 0%,#1e293b 100%)}
.rack-slot-label{font-size:10px;font-weight:700;color:#94a3b8;margin-bottom:4px}
.rack-slot-model{font-size:12px;font-weight:700;color:#f8fafc;word-break:break-all}
.rack-slot-type{font-size:10px;color:#cbd5e1;margin:4px 0}
.rack-slot-fw{font-size:10px;color:#94a3b8}
.rack-led{display:inline-block;width:6px;height:6px;border-radius:50%;background:#4ade80;box-shadow:0 0 5px #4ade80;margin-right:4px}

@media print{
  body{background:#fff !important;padding:0}
  .page{max-width:none;box-shadow:none;padding:0;margin:0}
  .report-nav{display:none !important}
  h2{page-break-before:always}
  h2:first-of-type{page-break-before:avoid}
  table,tr,td,th{page-break-inside:avoid}
  .host{page-break-inside:avoid}
  details>*{display:block}
}
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


def _render_executive_header(ctx, target, snapshot_timestamp):
    now = datetime.now().astimezone()
    tz_name = now.strftime("%Z") or now.strftime("%z")
    generated = now.strftime(f"%Y-%m-%d %H:%M ({tz_name})")

    out = [
        '<div class="exec-header">',
        '<div class="exec-title">OT / ICS Cybersecurity Assessment Report</div>',
        '<div class="exec-sub">Industrial Network Reconnaissance, Hardware Inventory &amp; Risk Audit</div>',
        '<div class="exec-meta-grid">',
        f'<div class="exec-meta-item"><span class="exec-meta-label">Target Scope</span><span class="exec-meta-val">{_e(target or "Subnet scan")}</span></div>',
        f'<div class="exec-meta-item"><span class="exec-meta-label">Assessment Operator</span><span class="exec-meta-val">{_e(ctx.get("operator") or "Operator")}</span></div>',
        f'<div class="exec-meta-item"><span class="exec-meta-label">Pacing Profile</span><span class="exec-meta-val">{_e((ctx.get("profile") or {}).get("name", "safe").capitalize())}</span></div>',
        f'<div class="exec-meta-item"><span class="exec-meta-label">Generated Timestamp</span><span class="exec-meta-val">{_e(generated)}</span></div>',
        '</div></div>',
    ]
    return "".join(out)


def _render_nav_bar():
    return (
        '<div class="report-nav">'
        '<div class="nav-brand">OT-RECON &middot; ICS Assessment</div>'
        '<div class="nav-links">'
        '<a href="#section-exec">Executive Summary</a>'
        '<a href="#section-methodology">Scope &amp; Methodology</a>'
        '<a href="#section-inventory">Asset Inventory</a>'
        '<a href="#section-iec62443">IEC 62443 Matrix</a>'
        '<a href="#section-remediation">Remediation Plan</a>'
        '<a href="#section-coverage">Coverage &amp; Limitations</a>'
        '<a href="#section-hosts">Detailed Host Assessments</a>'
        '<a href="#section-appendix">Appendix</a>'
        '</div></div>'
    )


def _section_summary(data, ctx):
    counts = _severity_counts(data)
    label, css = _posture(counts)
    ot_hosts = sum(1 for h in data if h.get("type") not in (None, "Unknown"))
    l1_hosts = sum(1 for h in data if _purdue_level(h.get("type"))[0].startswith("L1"))
    cov = (ctx.get("coverage") or {}).get("host_status_counts")
    gap_hosts = (cov.get("partial", 0) + cov.get("limited", 0)) if cov else None

    out = ['<h2 id="section-exec">1. Executive Summary</h2>',
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

    # Severity distribution bar
    total_findings = sum(counts.values())
    if total_findings > 0:
        c_pct = (counts["Critical"] / total_findings) * 100
        h_pct = (counts["High"] / total_findings) * 100
        m_pct = (counts["Medium"] / total_findings) * 100
        l_pct = (counts["Low"] / total_findings) * 100
        out.append(
            '<div class="sev-bar-container">'
            f'<div class="sev-bar-seg sev-critical" style="width:{c_pct:.1f}%" title="Critical: {counts["Critical"]}"></div>'
            f'<div class="sev-bar-seg sev-high" style="width:{h_pct:.1f}%" title="High: {counts["High"]}"></div>'
            f'<div class="sev-bar-seg sev-medium" style="width:{m_pct:.1f}%" title="Medium: {counts["Medium"]}"></div>'
            f'<div class="sev-bar-seg sev-low" style="width:{l_pct:.1f}%" title="Low: {counts["Low"]}"></div>'
            '</div>'
        )

    # Purdue Model Distribution
    levels = Counter()
    for h in data:
        p_name, _ = _purdue_level(h.get("type"))
        levels[p_name] += 1

    out.append('<h3>Purdue Model Asset Hierarchy (ISA-95 Distribution)</h3>')
    out.append('<div class="purdue-grid">')
    purdue_cards = [
        ("Level 1: Basic Control & Field", "PLCs, Safety Systems, Remote I/O",
         levels["L1: Basic Control (PLC)"] + levels["L1: Safety / SIS"] + levels["L1: Field Device / I/O"], "purdue-l1"),
        ("Level 2: Supervisory Control", "Operator Panels, HMIs, SCADA",
         levels["L2: Supervisory (HMI)"], "purdue-l2"),
        ("Level 3: Operations Infrastructure", "Historians, Industrial Servers",
         levels["L3: Operations Infrastructure"], "purdue-l3"),
        ("Level 0 / Unclassified Hosts", "IT-side & General Network Hosts",
         levels["Unclassified / IT Host"], "purdue-na"),
    ]
    for p_title, p_desc, p_count, p_css in purdue_cards:
        out.append(
            f'<div class="purdue-card">'
            f'<div class="purdue-card-header {p_css}">{_e(p_title)}</div>'
            f'<div class="purdue-card-val">{_e(p_count)} <span style="font-size:12px;font-weight:400;color:#64748b">asset(s)</span></div>'
            f'<div class="purdue-card-desc">{_e(p_desc)}</div>'
            f'</div>'
        )
    out.append('</div>')

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
    out = ['<h2 id="section-methodology">2. Scope &amp; Methodology</h2>']

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
    out = ['<h2 id="section-inventory">3. Asset Inventory</h2>']
    if not data:
        return out[0] + '<p class="muted">No hosts were discovered.</p>'

    out.append('<table class="data"><tr><th>Host</th><th>Purdue Level</th><th>Type</th><th>Vendor</th><th>Model</th><th>Firmware</th>'
               '<th>Services</th><th>Risk</th><th>Coverage</th></tr>')
    for h in _sorted_hosts(data):
        protos = list(dict.fromkeys(
            p["protocol"] for p in h.get("ot_ports", [])
            if p.get("state", "open") == "open" and p.get("protocol")))
        sev = h.get("risk_severity")
        risk = (_sev_badge(sev) + f' {_e(h.get("risk_score"))}') if sev and sev != "None" else '<span class="muted">none</span>'
        cstat = (h.get("coverage") or {}).get("status")
        cov = _badge(COVERAGE_LABEL[cstat], COVERAGE_CLASS[cstat]) if cstat in COVERAGE_LABEL else '<span class="muted">not recorded</span>'
        p_label, p_css = _purdue_level(h.get("type"))
        out.append(
            f'<tr><td><a href="#{_anchor(h["ip"])}">{_e(h.get("ip"))}</a></td>'
            f'<td>{_badge(p_label, p_css)}</td>'
            f'<td>{_e(h.get("type"))}</td>'
            f'<td>{_e(h.get("vendor") or "-")}</td><td>{_e(h.get("model") or "-")}</td>'
            f'<td>{_e(h.get("firmware") or "-")}</td><td>{_e(", ".join(protos) or "-")}</td>'
            f'<td>{risk}</td><td>{cov}</td></tr>'
        )
    out.append("</table>")
    return "".join(out)


def _section_iec62443(data):
    matrix = _compute_iec62443_matrix(data)
    out = [
        '<h2 id="section-iec62443">IEC 62443 Security Posture &amp; Compliance</h2>',
        '<p class="muted">Alignment of discovered asset exposures and control architectures against '
        '<b>IEC 62443-3-3</b> (System Security Requirements) and <b>IEC 62443-4-2</b> (Technical Security Requirements for IACS Components).</p>',
        '<table class="data">',
        '<tr><th>Requirement</th><th>Standard Ref</th><th>Compliance Status</th><th>Affected Assets</th><th>Primary Risk &amp; Recommended Engineering Controls</th></tr>'
    ]
    for row in matrix:
        affected_links = ", ".join(f'<a href="#{_anchor(ip)}">{_e(ip)}</a>' for ip in row["affected_hosts"][:6])
        if len(row["affected_hosts"]) > 6:
            affected_links += f' <span class="small muted">+{len(row["affected_hosts"]) - 6} more</span>'
        if not affected_links:
            affected_links = '<span class="muted">None identified</span>'

        out.append(
            f'<tr>'
            f'<td><b>{_e(row["id"])}</b><br><span class="small">{_e(row["name"])}</span></td>'
            f'<td><code>{_e(row["standard"])}</code></td>'
            f'<td><span class="{_e(row["status_css"])}">{_e(row["status"])}</span></td>'
            f'<td><b>{row["affected_count"]}</b><br><span class="small">{affected_links}</span></td>'
            f'<td><b>Risk:</b> {_e(row["risk"])}<br><div style="margin-top:4px;color:#0284c7"><b>Control:</b> {_e(row["recommendation"])}</div></td>'
            f'</tr>'
        )
    out.append('</table>')
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
    out = ['<h2 id="section-remediation">4. Remediation Plan</h2>']
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
    out = ['<h2 id="section-coverage">5. Coverage &amp; Limitations</h2>',
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


def _render_visual_chassis(h):
    chassis = h.get("chassis_modules")
    if not chassis:
        return ""

    out = [
        '<div class="rack-enclosure">',
        '<div class="rack-header">',
        f'<span><b>Modular Chassis Rack:</b> {_e(h.get("model", "Chassis Adapter"))} ({_e(h.get("ip"))})</span>',
        f'<span>{len(chassis)} Module(s) Enumerated</span>',
        '</div>',
        '<div class="rack-slots">',
    ]

    for m in chassis:
        dtype = m.get("device_type", "")
        is_cpu = "Programmable Logic Controller" in dtype
        is_comm = "Communications Adapter" in dtype or "Adapter" in dtype
        card_class = "is-cpu" if is_cpu else ("is-comm" if is_comm else "is-io")
        badge_text = "CPU" if is_cpu else ("COMM" if is_comm else "I/O")
        badge_css = "sev-low" if is_cpu else ("sev-info" if is_comm else "det")

        out.append(
            f'<div class="rack-card {card_class}">'
            f'<div>'
            f'<div class="rack-slot-label"><span class="rack-led"></span>SLOT {m.get("slot", 0)} '
            f'<span class="badge {badge_css}">{badge_text}</span></div>'
            f'<div class="rack-slot-model">{_e(m.get("model", "-"))}</div>'
            f'<div class="rack-slot-type">{_e(m.get("device_type", "-"))}</div>'
            f'</div>'
            f'<div class="rack-slot-fw">FW: {_e(m.get("firmware", "N/A"))}</div>'
            f'</div>'
        )

    out.append('</div></div>')
    return "".join(out)


def _render_host(h):
    cov = h.get("coverage") or {}
    cstat = cov.get("status")
    sev = h.get("risk_severity")
    p_label, p_css = _purdue_level(h.get("type"))

    head = [f'<div class="host" id="{_anchor(h["ip"])}"><div class="host-head">'
            f'<div><b style="font-size:16px">{_e(h.get("ip"))}</b> &nbsp;'
            f'{_badge(p_label, p_css)} &nbsp;{_e(h.get("type"))} '
            f'&middot; {_e(" ".join(x for x in (h.get("vendor"), h.get("model")) if x) or "vendor unknown")}'
            f'{" &middot; fw " + _e(h["firmware"]) if h.get("firmware") else ""}</div><div>']
    if sev and sev != "None":
        head.append(f'{_sev_badge(sev)} <b>{_e(h.get("risk_score"))}/100</b> ')
    if cstat in COVERAGE_LABEL:
        head.append(f'Coverage: {_badge(COVERAGE_LABEL[cstat], COVERAGE_CLASS[cstat])}')
    head.append("</div></div><div class=\"host-body\">")
    out = ["".join(head)]

    if h.get("summary"):
        out.append(f'<p class="muted">{_e(h["summary"])}</p>')

    # High-Impact Operational Alerts
    alerts = []
    if h.get("keyswitch_mode"):
        kw = str(h["keyswitch_mode"])
        if "REMOTE" in kw.upper():
            alerts.append(
                '<div class="op-alert op-alert-danger">'
                '<div class="op-alert-title">⚠️ Operational Risk: CPU Keyswitch in REMOTE RUN Mode</div>'
                'The controller keyswitch is set to <b>REMOTE RUN</b>, allowing unauthenticated ladder logic overwrites, '
                'program downloads, and remote CPU state transitions (STOP/PAUSE) over the network without physical cabinet access. '
                'Per <b>NIST SP 800-82 / IEC 62443</b>, rotate physical keyswitch to <b>RUN (Hard Lock)</b> during normal plant operation.'
                '</div>'
            )
        elif kw.upper() == "RUN":
            alerts.append(
                '<div class="op-alert op-alert-info">'
                '<div class="op-alert-title">🔒 Physical Lock: CPU Keyswitch in RUN (Hard Lock)</div>'
                'The controller keyswitch is physically set to RUN mode. Remote logic uploads and program modifications across the network are hardware-inhibited.'
                '</div>'
            )

    if h.get("protection_level") is not None:
        prot = str(h["protection_level"])
        if "Level 1" in prot or "Open" in prot or "No Protection" in prot or prot == "1":
            alerts.append(
                '<div class="op-alert op-alert-warning">'
                '<div class="op-alert-title">⚠️ Access Control Warning: Controller Protection Level 1 (Open / Unrestricted)</div>'
                'PLC memory blocks, data blocks (DBs), and I/O image registers are accessible without password restriction. '
                'Any device on this network conduit can issue read/write requests.'
                '</div>'
            )
    if alerts:
        out.append("".join(alerts))

    # Deep Inspection & Security Posture Card (Native S7/CIP SZL Inspection)
    if h.get("keyswitch_mode") or h.get("protection_level") is not None or h.get("mlfb") or h.get("component_name"):
        sp = ['<div class="security-posture"><b>Deep Protocol Inspection &amp; Security Posture:</b><br>']
        if h.get("keyswitch_mode"):
            kw = str(h["keyswitch_mode"])
            kw_badge = "sev-critical" if "REMOTE" in kw else ("sev-low" if kw == "RUN" else "sev-medium")
            sp.append(f'Keyswitch Mode: {_badge(kw, kw_badge)} ')
        if h.get("protection_level") is not None:
            prot = str(h["protection_level"])
            prot_badge = "sev-critical" if ("Level 1" in prot or prot == "1") else ("sev-medium" if ("Level 2" in prot or prot == "2") else "sev-low")
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
        # Visual rack cards
        out.append(_render_visual_chassis(h))
        # Detailed structured data table
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
    out = ['<h2 id="section-hosts">6. Detailed Findings by Host</h2>']
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
    out = ['<h2 id="section-changes">7. Changes Since the Previous Scan</h2>']
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
        '<h2 id="section-appendix">Appendix: Definitions</h2>'
        '<table class="data kv">'
        f'<tr><td>Risk score (0-100)</td><td>Sum of finding weights ({_e(weights)}), multiplied by an asset-criticality '
        f'factor ({_e(mult)}; other types x1.0), capped at 100. It ranks hosts for triage; it is not a '
        f'probability of compromise.</td></tr>'
        '<tr><td>Severity</td><td>Critical / High / Medium / Low / Info - the seriousness of the issue if it applies. '
        'Info findings are things to verify, not confirmed problems.</td></tr>'
        '<tr><td>Priority P1-P5</td><td>Relative remediation order only (P1 first).</td></tr>'
        '<tr><td>Coverage</td><td><b>Full</b>: assessed with no gaps. <b>Partial</b>: assessed but some checks could '
        'not run. <b>Limited</b>: OT services present but nothing authoritative was learned. '
        '<b>No OT services</b>: OT checks do not apply.</td></tr>'
        '<tr><td>Purdue Model (ISA-95)</td><td><b>Level 1</b>: Basic control (PLCs, SIS, Remote I/O). '
        '<b>Level 2</b>: Area supervisory (HMIs, SCADA). <b>Level 3</b>: Operations infrastructure (Historians, Engineering).</td></tr>'
        '<tr><td>IEC 62443 Alignment</td><td>Industrial automation cybersecurity requirements (3-3 System &amp; 4-2 Component requirements).</td></tr>'
        '</table>'
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
    target = ctx.get("target")

    body = [
        _render_nav_bar(),
        _render_executive_header(ctx, target, snapshot_timestamp),
        _section_summary(data, ctx),
        _section_methodology(scan_ctx),
        _section_inventory(data),
        _section_iec62443(data),
        _section_remediation(data),
        _section_coverage(data, ctx),
        _section_hosts(data),
        _section_changes(diff, previous_timestamp),
        _section_appendix(),
        '<div class="footer">Generated by OT-Recon. Contains industrial asset and security vulnerability data &mdash; '
        'handle in strict accordance with your organisation\'s cybersecurity data classification policy.</div>',
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
