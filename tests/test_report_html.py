import re

import pytest

from ot_recon.core import report_html
from ot_recon.core.report_html import render_html, export_html

XSS = '<script>alert(1)</script><img src=x onerror=alert(2)><svg onload=alert(3)>"\'><iframe src=//evil>'


def _finding(**kw):
    base = {"finding": "Modbus exposed (no authentication)", "severity": "High", "cve": None,
            "advisory": None, "impact": "High", "likelihood": "Medium",
            "recommendation": "Restrict port 502 with a firewall.", "remediation_priority": "P2",
            "related_ports": [502], "detection": "observed"}
    base.update(kw)
    return base


def _host(ip="10.0.0.1", **kw):
    base = {
        "ip": ip, "type": "PLC", "vendor": "Siemens", "model": "S7-1500", "firmware": "2.9.3",
        "confidence": "Very High", "confidence_score": 95, "detection_method": "active_probe",
        "evidence_based": True, "evidence": ["S7comm response confirmed"],
        "ot_ports": [{"port": 102, "state": "open", "protocol": "S7", "transport": "tcp"}],
        "services": [{"port": 102, "state": "open", "protocol": "S7", "category": "ot",
                      "transport": "tcp", "authentication": "none"}],
        "risks": [_finding()], "risk_severity": "High", "risk_score": 48, "summary": "A Siemens PLC.",
        "probes": [{"probe": "s7-info", "ports": "102", "command": "nmap -n -Pn 10.0.0.1 -p 102",
                    "status": "data", "returncode": 0, "duration_s": 1.2,
                    "output": "| s7-info:\n|   Module: 6ES7", "error": None}],
        "coverage": {"status": "full", "gaps": [], "checks": [
            {"check": "Fingerprint probe: s7-info", "status": "completed", "detail": "ok"}]},
    }
    base.update(kw)
    return base


def _ctx(**kw):
    base = {"tool_version": "1.3.0", "nmap_version": "7.94", "operator": "analyst", "target": "10.0.0.0/24",
            "started": "2026-01-01T00:00:00Z", "finished": "2026-01-01T00:05:00Z",
            "profile": {"name": "safe", "description": "Gentle", "settings": {
                "tcp_timing": "T2", "udp_timing": "T2", "scan_delay": "200ms", "max_retries": 1,
                "version_intensity": 0, "workers": 2, "nmap_script_timeout": 60}},
            "tcp_ports": "102,502", "udp_ports": "161", "udp_scanned": False, "cve_live": False,
            "exclude_self": True, "excluded": ["10.0.0.9"], "hosts_discovered": 1, "commands_run": 7,
            "audit_log": "/x/audit.jsonl",
            "scope": {"address_count": 256, "allowed": [], "overridden": []},
            "coverage": {"gaps": ["UDP was not scanned."], "notes": ["Only non-intrusive checks."],
                         "host_status_counts": {"full": 1, "partial": 0, "limited": 0, "n/a": 0}}}
    base.update(kw)
    return base


# ----------------------------------------------------------------- structure

def test_full_report_contains_every_section():
    out = render_html([_host()], scan_ctx=_ctx())
    for heading in ("Executive Summary", "Scope &amp; Methodology", "Asset Inventory", "Remediation Plan",
                    "Coverage &amp; Limitations", "Detailed Findings by Host",
                    "Changes Since the Previous Scan", "Appendix: Definitions"):
        assert heading in out, heading
    assert out.startswith("<!DOCTYPE html>")


def test_report_is_self_contained_no_scripts_no_external_assets():
    out = render_html([_host()], scan_ctx=_ctx())
    assert "<script" not in out.lower()
    assert not re.search(r'(src|href)="https?://(?!nvd\.nist\.gov)', out)   # only NVD links allowed
    assert "<link " not in out and "@import" not in out
    assert "Content-Security-Policy" in out and "default-src 'none'" in out


def test_empty_scan_renders_without_error():
    out = render_html([], scan_ctx=_ctx())
    assert "No hosts were discovered" in out and "No findings to remediate" in out


def test_methodology_shows_profile_scope_and_audit_details():
    out = render_html([_host()], scan_ctx=_ctx())
    for expected in ("10.0.0.0/24", "safe - Gentle", "200ms", "7.94", "analyst", "/x/audit.jsonl", "10.0.0.9"):
        assert expected in out
    assert "No exploitation" in out and "No authentication attempts" in out


def test_methodology_states_when_metadata_missing():
    out = render_html([_host()], scan_ctx=None)
    assert "Scan metadata was not recorded" in out


def test_old_snapshot_hosts_without_new_fields_render():
    """Pre-1.3 snapshots have no coverage/probes/detection - must still render."""
    legacy = {"ip": "10.0.0.7", "type": "PLC", "vendor": "Siemens", "model": None, "firmware": None,
              "ot_ports": [{"port": 102, "state": "open", "protocol": "S7"}],
              "risks": [{"finding": "Siemens S7 exposed", "severity": "High"}],
              "risk_severity": "High", "risk_score": 20}
    out = render_html([legacy], scan_ctx=None)
    assert "10.0.0.7" in out and "Siemens S7 exposed" in out and "not recorded" in out


# ------------------------------------------------------------------- content

@pytest.mark.parametrize("risks,expected", [
    ([_finding(severity="Critical")], "Critical exposure identified"),
    ([_finding(severity="High")], "High-risk exposure identified"),
    ([_finding(severity="Medium")], "Moderate exposure identified"),
    ([_finding(severity="Low")], "Low-severity issues only"),
    ([], "No findings among the checks that could be performed"),
])
def test_posture_reflects_worst_severity(risks, expected):
    assert expected in render_html([_host(risks=risks)], scan_ctx=_ctx())


def test_no_findings_posture_points_reader_to_coverage_not_reassurance():
    out = render_html([_host(risks=[])], scan_ctx=_ctx())
    assert "see Coverage" in out and "safe" not in out.split("Executive Summary")[1].split("Scope")[0].lower().replace("safe profile", "")


def test_callout_warns_when_hosts_have_coverage_gaps():
    ctx = _ctx()
    ctx["coverage"]["host_status_counts"] = {"full": 0, "partial": 1, "limited": 1, "n/a": 0}
    out = render_html([_host()], scan_ctx=ctx)
    assert "no finding does not mean no vulnerability" in out


def test_no_gap_callout_when_everything_fully_covered():
    assert "no finding does not mean" not in render_html([_host()], scan_ctx=_ctx())


def test_scan_wide_and_per_host_gaps_listed():
    h = _host(coverage={"status": "partial", "gaps": ["Firmware version could not be read."], "checks": []})
    out = render_html([h], scan_ctx=_ctx())
    assert "UDP was not scanned." in out and "Firmware version could not be read." in out


def test_detection_tiers_shown_on_findings_and_defined():
    out = render_html([_host(risks=[_finding(detection="inconclusive")])], scan_ctx=_ctx())
    assert "inconclusive" in out and "firmware version could not be read - verify manually" in out


def test_evidence_and_raw_probe_output_included_in_collapsible():
    out = render_html([_host()], scan_ctx=_ctx())
    assert "<details>" in out and "S7comm response confirmed" in out
    assert "| s7-info:" in out and "nmap -n -Pn 10.0.0.1 -p 102" in out


def test_hosts_sorted_by_risk_score_in_inventory():
    out = render_html([_host("10.0.0.1", risk_score=10), _host("10.0.0.2", risk_score=90)], scan_ctx=_ctx())
    inv = out.split("3. Asset Inventory")[1].split("4. Remediation")[0]
    assert inv.index("10.0.0.2") < inv.index("10.0.0.1")


def test_inventory_links_to_host_cards():
    out = render_html([_host("10.0.0.1")], scan_ctx=_ctx())
    assert 'href="#host-10-0-0-1"' in out and 'id="host-10-0-0-1"' in out


def test_remediation_groups_same_finding_across_hosts_and_orders_by_priority():
    hosts = [_host("10.0.0.1"), _host("10.0.0.2"),
             _host("10.0.0.3", risks=[_finding(finding="SNMP open", severity="Medium", remediation_priority="P3")])]
    out = render_html(hosts, scan_ctx=_ctx())
    rem = out.split("4. Remediation Plan")[1].split("5. Coverage")[0]
    assert rem.count("Modbus exposed") == 1                     # grouped, not repeated per host
    assert "10.0.0.1, 10.0.0.2" in rem
    assert rem.index("Modbus exposed") < rem.index("SNMP open")  # P2 before P3


def test_cves_link_to_nvd_and_advisory_links_rendered():
    h = _host(risks=[_finding(cve="CVE-2019-10943, SA25P002", advisory="https://example.com/adv")])
    out = render_html([h], scan_ctx=_ctx())
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2019-10943"' in out
    assert "SA25P002" in out and 'href="https://nvd.nist.gov/vuln/detail/SA25P002"' not in out
    assert 'href="https://example.com/adv"' in out and 'rel="noopener noreferrer"' in out


def test_non_ot_hosts_listed_compactly_but_still_reported():
    plain = _host("10.0.0.50", type="Unknown", vendor=None, risks=[], risk_score=0, risk_severity="None",
                  services=[{"port": 22, "state": "open", "protocol": "SSH", "category": "it"}],
                  coverage={"status": "n/a", "gaps": [], "checks": []})
    out = render_html([plain], scan_ctx=_ctx())
    assert "Hosts with no OT services and no findings" in out and "10.0.0.50" in out


# ---------------------------------------------------------------------- diff

def test_diff_section_renders_all_change_types():
    diff = {"new_hosts": ["10.0.0.9"], "removed_hosts": ["10.0.0.8"], "host_changes": {"10.0.0.1": {
        "new_ports": [(502, "tcp")], "closed_ports": [(80, "tcp")],
        "firmware_change": ("1.0", "2.0"), "severity_change": ("Low", "High"),
        "new_findings": [_finding(finding="Newly exposed")], "resolved_findings": [_finding(finding="Fixed thing")]}}}
    out = render_html([_host()], scan_ctx=_ctx(), diff=diff, previous_timestamp="20260101T000000Z")
    for expected in ("10.0.0.9", "10.0.0.8", "Ports opened: 502/tcp", "Ports closed: 80/tcp",
                     "Firmware changed: 1.0 -&gt; 2.0", "Low -&gt; High", "Newly exposed", "Fixed thing", "20260101T000000Z"):
        assert expected in out, expected


def test_diff_none_says_no_previous_scan():
    assert "No previous scan was available" in render_html([_host()], scan_ctx=_ctx(), diff=None)


def test_diff_with_no_changes():
    diff = {"new_hosts": [], "removed_hosts": [], "host_changes": {}}
    assert "No changes detected" in render_html([_host()], scan_ctx=_ctx(), diff=diff)


# ----------------------------------------------------------------- SECURITY

# Structural checks. A plain substring test would wrongly fail on escaped,
# inert text such as "&lt;img src=x onerror=alert(2)&gt;" - what matters is
# whether a RAW '<' opens a dangerous element, or any tag carries an event
# handler attribute.
_LIVE_TAG = re.compile(r"<\s*(script|img|svg|iframe|object|embed|link|base|form|style\b[^>]*>\s*[^<]*expression)", re.I)
_EVENT_HANDLER = re.compile(r"<[a-z][^>]*\son[a-z]+\s*=", re.I)


def _assert_no_live_markup(out):
    body = out.split("</style>", 1)[1]            # skip the page's own <style> block
    assert not _LIVE_TAG.search(body), _LIVE_TAG.search(body).group(0)
    assert not _EVENT_HANDLER.search(out), _EVENT_HANDLER.search(out).group(0)
    assert "&lt;script&gt;" in out          # ...and it was escaped, not silently dropped


def test_hostile_device_strings_are_escaped_everywhere():
    """Vendor/model/firmware, banners, probe output and errors are all
    controlled by whatever is on the network."""
    h = _host(
        vendor=XSS, model=XSS, firmware=XSS, type=XSS, summary=XSS,
        evidence=[XSS],
        services=[{"port": XSS, "state": XSS, "protocol": XSS, "category": XSS, "transport": XSS, "authentication": XSS}],
        probes=[{"probe": XSS, "ports": XSS, "command": XSS, "status": XSS, "duration_s": XSS,
                 "output": XSS, "error": XSS}],
        coverage={"status": "partial", "gaps": [XSS], "checks": [{"check": XSS, "status": XSS, "detail": XSS}]},
        risks=[_finding(finding=XSS, impact=XSS, likelihood=XSS, recommendation=XSS,
                        remediation_priority=XSS, detection=XSS, related_ports=[XSS], severity="High")],
    )
    _assert_no_live_markup(render_html([h], scan_ctx=_ctx()))


def test_hostile_scan_context_is_escaped():
    ctx = _ctx(target=XSS, operator=XSS, audit_log=XSS, nmap_version=XSS, tcp_ports=XSS,
               excluded=[XSS], profile={"name": XSS, "description": XSS, "settings": {}},
               scope={"address_count": XSS, "allowed": [XSS], "overridden": [XSS]})
    ctx["coverage"] = {"gaps": [XSS], "notes": [XSS], "host_status_counts": {}}
    _assert_no_live_markup(render_html([_host()], scan_ctx=ctx, snapshot_timestamp=XSS))


def test_hostile_diff_content_is_escaped():
    diff = {"new_hosts": [XSS], "removed_hosts": [XSS], "host_changes": {XSS: {
        "vendor_change": (XSS, XSS), "new_ports": [(XSS, XSS)],
        "new_findings": [_finding(finding=XSS)], "resolved_findings": [_finding(finding=XSS)]}}}
    _assert_no_live_markup(render_html([_host()], scan_ctx=_ctx(), diff=diff, previous_timestamp=XSS))


def test_hostile_ip_field_cannot_break_out_of_attributes():
    out = render_html([_host(ip='10.0.0.1" onmouseover="alert(1)')], scan_ctx=_ctx())
    assert 'onmouseover="alert' not in out                 # no attribute injection
    assert re.search(r'id="host-[A-Za-z0-9-]+"', out)       # anchor id sanitised


@pytest.mark.parametrize("url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<b>x</b>",
                                 "vbscript:x", "//evil.example/x", "ftp://x"])
def test_non_http_advisory_urls_are_never_rendered_as_links(url):
    out = render_html([_host(risks=[_finding(advisory=url)])], scan_ctx=_ctx())
    assert f'href="{url}"' not in out
    assert not re.search(r'href="(javascript|data|vbscript):', out, re.IGNORECASE)


def test_fake_cve_id_is_not_turned_into_a_link():
    out = render_html([_host(risks=[_finding(cve='CVE-2024-1"><script>x</script>')])], scan_ctx=_ctx())
    assert "<script" not in out.lower() and "nvd.nist.gov/vuln/detail/CVE-2024-1" not in out


def test_safe_url_helper():
    assert report_html._safe_url("https://a.example/x") == "https://a.example/x"
    assert report_html._safe_url("javascript:alert(1)") is None
    assert report_html._safe_url(None) is None


# -------------------------------------------------------------------- export

def test_export_writes_utf8_file_and_unicode_survives(tmp_path):
    path = tmp_path / "r.html"
    export_html([_host(vendor="Siemens AG — Müller 工場")], path, scan_ctx=_ctx())
    text = path.read_text(encoding="utf-8")
    assert "Müller 工場" in text and text.startswith("<!DOCTYPE html>")


def test_risk_formula_in_appendix_matches_the_real_constants():
    from ot_recon.core.risk import SEVERITY_WEIGHTS
    out = render_html([_host()], scan_ctx=_ctx())
    for sev, weight in SEVERITY_WEIGHTS.items():
        assert f"{sev} = {weight}" in out


def test_generated_timestamp_includes_local_timezone():
    from datetime import datetime
    now = datetime.now().astimezone()
    tz_name = now.strftime("%Z") or now.strftime("%z")
    out = render_html([_host()], scan_ctx=_ctx())
    assert f"({tz_name})" in out


def test_html_renders_security_posture_and_chassis_modules():
    host = _host(
        ip="10.0.0.10",
        keyswitch_mode="REMOTE RUN (Logic download allowed across network)",
        protection_level="Level 1 (No Protection / Open)",
        mlfb="6ES7 511-1AK02-0AB0",
        component_name="Plant_Line_1",
        chassis_modules=[
            {"slot": 0, "model": "1756-L72", "device_type": "Programmable Logic Controller", "firmware": "32.11"},
            {"slot": 1, "model": "1756-EN2T", "device_type": "Communications Adapter", "firmware": "5.08"},
        ],
    )
    out = render_html([host], scan_ctx=_ctx())
    assert "Deep Protocol Inspection &amp; Security Posture" in out
    assert "Keyswitch Mode:" in out
    assert "REMOTE RUN" in out
    assert "Level 1 (No Protection / Open)" in out
    assert "Plant_Line_1" in out
    assert "6ES7 511-1AK02-0AB0" in out
    assert "Chassis / Backplane Rack Layout" in out
    assert "1756-L72" in out
    assert "1756-EN2T" in out
    assert "Slot 0" in out
    assert "Slot 1" in out


def test_html_renders_purdue_hierarchy_and_badges():
    hosts = [
        _host(ip="10.0.0.1", type="PLC"),
        _host(ip="10.0.0.2", type="Safety PLC"),
        _host(ip="10.0.0.3", type="HMI"),
        _host(ip="10.0.0.4", type="Industrial Server"),
    ]
    out = render_html(hosts, scan_ctx=_ctx())
    assert "Purdue Model Asset Hierarchy" in out
    assert "Level 1: Basic Control" in out
    assert "Level 2: Supervisory" in out
    assert "Level 3: Operations" in out
    assert "purdue-l1" in out
    assert "purdue-l1-safety" in out
    assert "purdue-l2" in out
    assert "purdue-l3" in out


def test_html_renders_iec62443_compliance_matrix():
    host = _host(
        ip="10.0.0.1",
        ot_ports=[{"port": 502, "state": "open", "protocol": "Modbus"}],
        keyswitch_mode="REMOTE RUN",
        protection_level="Level 1 (No Protection)",
        risks=[_finding(severity="High")],
    )
    out = render_html([host], scan_ctx=_ctx())
    assert "IEC 62443 Security Posture &amp; Compliance" in out
    assert "FR 1" in out
    assert "Identification &amp; Authentication Control" in out
    assert "FR 2" in out
    assert "Use Control" in out
    assert "FR 3" in out
    assert "System Integrity" in out
    assert "iec-status-noncompliant" in out


def test_html_renders_visual_chassis_rack():
    host = _host(
        ip="10.0.0.10",
        model="1756-EN2T",
        chassis_modules=[
            {"slot": 0, "model": "1756-L72", "device_type": "Programmable Logic Controller", "firmware": "32.11"},
            {"slot": 1, "model": "1756-EN2T", "device_type": "Communications Adapter", "firmware": "5.08"},
            {"slot": 2, "model": "1756-IB16", "device_type": "General Purpose Discrete I/O", "firmware": "3.01"},
        ],
    )
    out = render_html([host], scan_ctx=_ctx())
    assert "rack-enclosure" in out
    assert "rack-slots" in out
    assert "is-cpu" in out
    assert "is-comm" in out
    assert "is-io" in out
    assert "SLOT 0" in out
    assert "SLOT 1" in out
    assert "SLOT 2" in out
    assert "1756-IB16" in out


def test_html_renders_operational_risk_alerts():
    host = _host(
        ip="10.0.0.5",
        keyswitch_mode="REMOTE RUN",
        protection_level="Level 1 (No Protection / Open)",
    )
    out = render_html([host], scan_ctx=_ctx())
    assert "op-alert op-alert-danger" in out
    assert "CPU Keyswitch in REMOTE RUN Mode" in out
    assert "Hard Lock" in out
    assert "Controller Protection Level 1" in out


def test_html_renders_executive_header_and_navigation():
    out = render_html([_host()], scan_ctx=_ctx(target="192.168.10.0/24", operator="SecOps"))
    assert "report-nav" in out
    assert "exec-header" in out
    assert "OT / ICS Cybersecurity Assessment Report" in out
    assert "192.168.10.0/24" in out
    assert "SecOps" in out
    assert "#section-exec" in out
    assert "#section-inventory" in out
    assert "#section-iec62443" in out
    assert "#section-remediation" in out



