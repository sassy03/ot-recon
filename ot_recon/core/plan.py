# ot_recon/core/plan.py
#
# --dry-run: show exactly what a scan WOULD do, without doing it. The
# commands come from the same builders the real scan uses
# (scanner.build_*_cmd, fingerprinter.build_probe_cmd), so the plan cannot
# drift from reality. Sends no packets and writes no files.

from ot_recon.core import fingerprinter, profiles, scanner


def build_plan(target, settings, config, exclude, udp, local_ips, cve_live, tcp_ports=None, udp_ports=None, deep_inspection=False):
    """Return an ordered list of {"step", "when", "command"} dicts.
    `command` is a list (an nmap invocation) or None for non-nmap actions."""

    tcp_pacing = profiles.pacing_args(settings, "tcp")
    udp_pacing = profiles.pacing_args(settings, "udp")
    excludes = sorted(local_ips) + list(exclude)

    steps = [{
        "step": "Host discovery (ping sweep)",
        "when": "always",
        "command": scanner.build_discovery_cmd(target, excludes, tcp_pacing),
    }, {
        "step": "TCP port scan of OT/IT service ports",
        "when": "against each live host found by discovery",
        "command": scanner.build_tcp_scan_cmd(
            ["<live hosts>"], tcp_ports or config["scan"]["tcp_ports"], pacing=tcp_pacing),
    }]

    if udp:
        steps.append({
            "step": "UDP port scan",
            "when": "against each live host (needs root)",
            "command": scanner.build_udp_scan_cmd(
                ["<live hosts>"], udp_ports or config["scan"]["udp_ports"], pacing=udp_pacing),
        })

    if deep_inspection:
        steps.append({
            "step": "Native OT Protocol: Siemens S7comm SZL inspection (0x0011, 0x001C, 0x0132)",
            "when": "against live hosts with TCP 102 open (reads keyswitch mode & protection level)",
            "command": None,
        })
        steps.append({
            "step": "Native OT Protocol: Rockwell EtherNet/IP CIP Backplane Chassis Scan (Slots 0..16)",
            "when": "against live hosts with TCP 44818 open (enumerates rack modules behind adapters)",
            "command": None,
        })
        steps.append({
            "step": "Native OT Protocol: Modbus TCP MEI Read Device Identification (FC 43/14)",
            "when": "against live hosts with TCP 502 open",
            "command": None,
        })

    for name, spec in fingerprinter.PROBES.items():
        steps.append({
            "step": f"Fingerprint probe: {name}",
            "when": f"only if {spec['applies']}",
            "command": fingerprinter.build_probe_cmd(
                name, "<ip>", pacing=tcp_pacing,
                version_intensity=settings.get("version_intensity")),
        })

    if cve_live:
        steps.append({
            "step": "Live CVE lookup (NVD API)",
            "when": "once per distinct vendor+model (cached); needs internet",
            "command": None,
        })

    return steps


def format_plan(steps, settings, scope_info, exclude, local_ips):
    lines = [
        "[DRY RUN] Nothing will be sent and no files will be written.",
        "",
        f"Target        : {scope_info['target']}  "
        f"({scope_info.get('address_count', '?')} address(es))",
        f"Profile       : {settings['name']}",
    ]
    if scope_info.get("allowed"):
        lines.append(f"Allowed scope : {', '.join(scope_info['allowed'])}")
    if scope_info.get("overridden"):
        lines.append(f"Overridden    : {'; '.join(scope_info['overridden'])}  (via --force)")
    if local_ips:
        lines.append(f"Excluded      : this machine ({', '.join(sorted(local_ips))})")
    if exclude:
        lines.append(f"Do-not-scan   : {', '.join(exclude)}")
    lines.append("")
    lines.append("Planned steps:")

    for i, s in enumerate(steps, 1):
        lines.append(f"  {i}. {s['step']}  [{s['when']}]")
        if s["command"]:
            lines.append("       " + " ".join(str(c) for c in s["command"]))

    lines.append("")
    lines.append("Remove --dry-run to run it for real.")
    return "\n".join(lines)
