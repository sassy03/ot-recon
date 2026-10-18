from rich.console import Console
from rich.markup import escape as _e
from rich.table import Table
from rich import box

# Explicit width rather than auto-detecting the terminal: headless/CI
# environments and narrow terminals otherwise truncate IP/vendor columns
# into unreadable ellipses.
console = Console(width=140)

SEVERITY_STYLE = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim",
}


def generate_report(data):

    console.print("\n[bold cyan]=== OT Recon Report ===[/bold cyan]\n")

    # Sort hosts descending by risk_score for triage prioritization
    sorted_data = sorted(data, key=lambda h: h.get("risk_score", 0), reverse=True)

    table = Table(
        show_header=True,
        header_style="bold bright_cyan",
        border_style="cyan",
        box=box.ROUNDED,
    )

    table.add_column("IP")
    table.add_column("Type")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Firmware")
    table.add_column("Confidence")
    table.add_column("Protocols")
    table.add_column("Risk")
    table.add_column("Findings")

    ot_assets = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    for host in sorted_data:

        if host.get("type") != "Unknown":
            ot_assets += 1

        open_protos = list(dict.fromkeys(
            p["protocol"]
            for p in host.get("ot_ports", [])
            if p.get("state", "open") == "open" and p.get("protocol")
        ))
        protocols = ", ".join(open_protos) or "-"

        risks = host.get("risks", [])
        risk_severity = host.get("risk_severity", "None")

        counts_by_sev = {}
        for r in risks:
            if r["severity"] in severity_counts:
                severity_counts[r["severity"]] += 1
            counts_by_sev[r["severity"]] = counts_by_sev.get(r["severity"], 0) + 1

        risk_style = SEVERITY_STYLE.get(risk_severity, "green")

        findings_summary = ", ".join(
            f"[{SEVERITY_STYLE.get(sev, 'white')}]{counts_by_sev[sev]} {sev}[/{SEVERITY_STYLE.get(sev, 'white')}]"
            for sev in SEVERITY_STYLE
            if counts_by_sev.get(sev)
        ) or "-"

        score = host.get("risk_score")
        score_suffix = f" ({score})" if score is not None else ""
        risk_display = (
            f"[{risk_style}]{risk_severity}{score_suffix}[/{risk_style}]"
            if risk_severity != "None"
            else "[green]None[/green]"
        )

        # Vendor/model/firmware come straight from the device - escape them
        # so a banner like "Acme [/x]" can't be parsed as Rich markup (that
        # used to raise MarkupError and kill the report after a full scan).
        table.add_row(
            _e(str(host["ip"])),
            _e(str(host.get("type", "-"))),
            _e(str(host.get("vendor", "-") or "-")),
            _e(str(host.get("model", "-") or "-")),
            _e(str(host.get("firmware", "-") or "-")),
            _e(str(host.get("confidence", "-"))),
            _e(protocols),
            risk_display,
            findings_summary,
        )

    console.print(table)

    # --- Detailed findings, one block per host with any risk (sorted by risk_score) ---
    hosts_with_findings = [h for h in sorted_data if h.get("risks")]

    if hosts_with_findings:
        console.print("\n[bold]Detailed Findings[/bold]")

        for host in hosts_with_findings:
            score = host.get("risk_score", 0)
            console.print(
                f"\n[bold]{_e(str(host['ip']))}[/bold] ({_e(str(host.get('type', '-')))}, {_e(str(host.get('vendor') or 'vendor unknown'))}) "
                f"— [bold]Risk Score: {score}/100[/bold]"
            )
            if host.get("summary"):
                console.print(f"  [italic dim]{_e(str(host['summary']))}[/italic dim]")

            if host.get("keyswitch_mode") or host.get("protection_level"):
                ks = host.get("keyswitch_mode") or "-"
                prot = host.get("protection_level") or "-"
                console.print(f"  [bold]Security Posture:[/bold] Keyswitch: [yellow]{_e(ks)}[/yellow] | Protection: [cyan]{_e(prot)}[/cyan]")

            for r in sorted(
                host["risks"],
                key=lambda f: list(SEVERITY_STYLE.keys()).index(f["severity"])
                if f["severity"] in SEVERITY_STYLE else 99
            ):
                style = SEVERITY_STYLE.get(r["severity"], "white")
                prio = r.get("remediation_priority", "-")
                line = f"  [{style}]{_e('[' + r['severity'] + ' | ' + str(prio) + ']')}[/{style}] {_e(str(r['finding']))}"

                impact = r.get("impact")
                likelihood = r.get("likelihood")
                if impact or likelihood:
                    line += f"\n        [dim]Impact: {_e(str(impact or '-'))} | Likelihood: {_e(str(likelihood or '-'))}[/dim]"

                if r.get("detection"):
                    line += f"\n        [dim]Detection: {_e(str(r['detection']))}[/dim]"

                if r.get("recommendation"):
                    line += f"\n        [cyan]Action: {_e(str(r['recommendation']))}[/cyan]"

                if r.get("cve"):
                    line += f"\n        [dim]Ref: {_e(str(r['cve']))}"
                    if r.get("advisory"):
                        line += f" — {_e(str(r['advisory']))}"
                    line += "[/dim]"

                console.print(line)

    hosts_with_chassis = [h for h in sorted_data if h.get("chassis_modules")]
    if hosts_with_chassis:
        console.print("\n[bold]CIP Backplane Chassis Layouts[/bold]")
        for host in hosts_with_chassis:
            console.print(f"\n[bold]{_e(str(host['ip']))}[/bold] — {_e(str(host.get('model', 'Chassis Adapter')))} ({len(host['chassis_modules'])} module(s))")
            for m in host["chassis_modules"]:
                cpu_tag = " [bold green][CPU][/bold green]" if "Programmable Logic Controller" in m.get("device_type", "") else ""
                console.print(f"  Slot {m.get('slot', 0)}: {_e(m.get('model', '-'))}{cpu_tag} | {_e(m.get('device_type', '-'))} | FW {_e(m.get('firmware', '-'))}")

    console.print("\n[bold]Scan Summary[/bold]")

    console.print(
        f"Hosts discovered : {len(data)}"
    )

    console.print(
        f"OT Assets found  : {ot_assets}"
    )

    console.print(
        f"Findings by severity : "
        f"[bold white on red]Critical={severity_counts['Critical']}[/bold white on red] "
        f"[bold red]High={severity_counts['High']}[/bold red] "
        f"[yellow]Medium={severity_counts['Medium']}[/yellow] "
        f"[cyan]Low={severity_counts['Low']}[/cyan] "
        f"[dim]Info={severity_counts['Info']}[/dim]"
    )

    if ot_assets == 0:

        console.print(
            "[yellow]No OT-specific assets identified.[/yellow]"
        )


def generate_diff_report(diff, old_ts=None, new_ts=None):
    """Render a history diff produced by core.history.diff_snapshots()."""

    header = "=== OT Recon Diff Report ==="
    if old_ts and new_ts:
        header += f"\n{old_ts}  →  {new_ts}"

    console.print(f"\n[bold cyan]{header}[/bold cyan]\n")

    if diff["new_hosts"]:
        console.print(f"[bold green]+ New hosts ({len(diff['new_hosts'])})[/bold green]")
        for ip in diff["new_hosts"]:
            console.print(f"  [green]+ {ip}[/green]")

    if diff["removed_hosts"]:
        console.print(f"\n[bold red]- Hosts no longer seen ({len(diff['removed_hosts'])})[/bold red]")
        for ip in diff["removed_hosts"]:
            console.print(f"  [red]- {ip}[/red]")

    host_changes = diff.get("host_changes", {})

    if host_changes:
        console.print(f"\n[bold]Changed hosts ({len(host_changes)})[/bold]")

        for ip, change in host_changes.items():
            console.print(f"\n[bold]{ip}[/bold]")

            if "severity_change" in change:
                old_sev, new_sev = change["severity_change"]
                old_style = SEVERITY_STYLE.get(old_sev, "white")
                new_style = SEVERITY_STYLE.get(new_sev, "white")
                console.print(
                    f"  Risk severity: [{old_style}]{old_sev}[/{old_style}] "
                    f"→ [{new_style}]{new_sev}[/{new_style}]"
                )

            for field in ("vendor", "model", "firmware"):
                key = f"{field}_change"
                if key in change:
                    old_val, new_val = change[key]
                    console.print(f"  {field.capitalize()}: {old_val or '-'} → {new_val or '-'}")

            if change.get("new_ports"):
                ports = ", ".join(f"{p}/{t}" for p, t in change["new_ports"])
                console.print(f"  [green]+ New open ports: {ports}[/green]")

            if change.get("closed_ports"):
                ports = ", ".join(f"{p}/{t}" for p, t in change["closed_ports"])
                console.print(f"  [dim]- Closed ports: {ports}[/dim]")

            for f in change.get("new_findings", []):
                style = SEVERITY_STYLE.get(f["severity"], "white")
                cve = f" ({f['cve']})" if f.get("cve") else ""
                console.print(f"  [{style}]+ NEW [{f['severity']}][/{style}] {f['finding']}{cve}")

            for f in change.get("resolved_findings", []):
                cve = f" ({f['cve']})" if f.get("cve") else ""
                console.print(f"  [dim]- resolved: {f['finding']}{cve}[/dim]")

    if not diff["new_hosts"] and not diff["removed_hosts"] and not host_changes:
        console.print("[green]No changes detected since the previous scan.[/green]")


def print_coverage_summary(data, scan_ctx):
    """Short console note on what the scan did NOT assess. The full
    per-host breakdown is in the HTML report."""

    cov = scan_ctx.get("coverage") or {}
    counts = cov.get("host_status_counts", {})
    gaps = cov.get("gaps", [])

    console.print("\n[bold]Assessment Coverage[/bold]")
    console.print(
        f"Hosts: [green]{counts.get('full', 0)} fully assessed[/green], "
        f"[yellow]{counts.get('partial', 0)} partial[/yellow], "
        f"[red]{counts.get('limited', 0)} limited[/red], "
        f"[dim]{counts.get('n/a', 0)} no OT services[/dim]"
    )

    host_gaps = sum(len(h.get("coverage", {}).get("gaps", [])) for h in data)
    if host_gaps:
        console.print(f"[yellow]{host_gaps} per-host gap(s)[/yellow] - 'no findings' does not mean 'safe' for these hosts.")

    for g in gaps:
        console.print(f"  [yellow]![/yellow] {_e(g)}")

    console.print("[dim]Generate the full report with: --format html[/dim]")
