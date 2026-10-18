# main.py

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from ot_recon import __version__
from ot_recon.core.scanner import (
    discover_hosts, scan_live_hosts, clear_artifacts, get_nmap_version,
)
from ot_recon.core.parser import parse_results
from ot_recon.core.enricher import enrich
from ot_recon.core.reporter import generate_report, generate_diff_report, print_coverage_summary
from ot_recon.core.classifier import classify
from ot_recon.core.risk import assess_risk
from ot_recon.core.fingerprinter import fingerprint
from ot_recon.core.exporter import export_json, export_csv
from ot_recon.core.report_html import export_html
from ot_recon.core.paths import OUTPUT_DIR, AUDIT_DIR
from ot_recon.core.config import load_config
from ot_recon.core import history, runner, profiles, guardrails, coverage, plan


def banner():
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    console = Console()
    logo = (
        r"   ___ _____   ____  _____ ____ ___  _   _ " + "\n"
        r"  / _ \_   _| |  _ \| ____/ ___/ _ \| \ | |" + "\n"
        r" | | | || |   | |_) |  _|| |  | | | |  \| |" + "\n"
        r" | |_| || |   |  _ <| |__| |__| |_| | |\  |" + "\n"
        r"  \___/ |_|   |_| \_\_____\____\___/|_| \_|" + "\n"
    )
    t = Text()
    t.append(logo + "\n", style="bold cyan")
    t.append("  OT/ICS RECONNAISSANCE TOOL\n", style="bold white")
    t.append(f"  Version: v{__version__}  |  Safety Guardrails Active  |  Author: Abhinav\n", style="cyan")
    t.append("  Vendor Profiles: Siemens S7 | Rockwell EtherNet/IP | B&R Automation", style="dim white")

    console.print(Panel(t, border_style="cyan", box=box.ROUNDED, expand=False))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ot-recon",
        description="OT Network Recon Tool (Safe & OT-aware)",
        epilog=f"Author: Abhinav | Version: v{__version__}"
    )
    parser.add_argument("--version", action="version", version=f"ot-recon v{__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Discover and fingerprint OT assets on a subnet")
    scan_p.add_argument("target", help="Target subnet (e.g. 192.168.1.0/24)")
    scan_p.add_argument("--verbose", action="store_true", help="Show detailed scan output")
    scan_p.add_argument(
        "--udp", action="store_true",
        help="Also scan UDP OT ports (EtherNet/IP I/O, SNMP). Requires root/sudo."
    )
    scan_p.add_argument(
        "--workers", type=int, default=None,
        help="Concurrent fingerprinting workers (default: set by the scan profile)"
    )
    scan_p.add_argument(
        "--format", choices=["table", "json", "csv", "html", "all"], default=None,
        help="Output format(s). 'table' prints to console; 'json'/'csv'/'html'/'all' "
             "also write report file(s) to the output dir. (default: from config)"
    )
    scan_p.add_argument(
        "--report-name", type=str, default=None,
        help="Custom filename for exported report(s) without extension (saved under output/<name>.<ext>). "
             "Default: timestamped name (output/report_YYYYMMDD_HHMMSS.<ext>)."
    )
    scan_p.add_argument(
        "--outfile", type=str, default=None,
        help="Base path/name for exported report file(s) (extension is added "
             "automatically). Takes precedence over --report-name."
    )
    scan_p.add_argument(
        "--config", type=str, default=None,
        help="Path to a site-specific config YAML, layered on top of "
             "data/config.yaml (only needs to contain the keys you want to override)."
    )
    scan_p.add_argument(
        "--no-history", action="store_true",
        help="Don't save this run as a history snapshot (skips output/history/*.json)."
    )
    scan_p.add_argument(
        "--cve-live", action="store_true", default=None,
        help="Supplement local CVE correlation with a live NVD lookup (needs internet; "
             "requires 'pip install -e \".[cve-live]\"'). Set NVD_API_KEY env var for higher "
             "rate limits. Default: from config (cve.live_lookup)."
    )
    scan_p.add_argument(
        "--cve-timeout", type=int, default=None,
        help="Per-request HTTP timeout in seconds for live NVD API lookups (default: from config, 30s)."
    )
    scan_p.add_argument(
        "--profile", type=str, default=None,
        help="How hard to lean on the network: safe (default, gentle), standard, or fast "
             "(the original aggressive timing). Default: from config (scan.profile)."
    )
    scan_p.add_argument(
        "--scope", type=str, default=None,
        help="Refuse to run unless the target is entirely inside these comma-separated "
             "networks (a typo guard, e.g. --scope 192.168.10.0/24)."
    )
    scan_p.add_argument(
        "--exclude", type=str, default=None,
        help="Comma-separated IPs/CIDRs never to scan (added to scope.exclude in config)."
    )
    scan_p.add_argument(
        "--force", action="store_true",
        help="Override SANITY refusals (non-private target, oversized target, hostname). "
             "Cannot override the scope.allowed policy allowlist."
    )
    scan_p.add_argument(
        "--dry-run", action="store_true",
        help="Show exactly what would be run - no packets sent, no files written."
    )
    scan_p.add_argument(
        "--include-self", action="store_true",
        help="Include this machine's own IP address(es) in the scan. By default the "
             "scanning host is auto-detected and excluded, since it usually isn't the "
             "OT asset you're trying to survey."
    )
    scan_p.add_argument(
        "--deep", "--deep-inspection", action="store_true", default=None,
        dest="deep_inspection",
        help="Enable deep active OT protocol inspection (CIP Backplane Chassis enumeration, "
             "Siemens S7comm keyswitch & SZL security levels, Modbus TCP MEI device identification). "
             "Default: from config (false by default for standard/gentle operation)."
    )

    # --- diff ---
    diff_p = subparsers.add_parser("diff", help="Compare two saved scan snapshots")
    diff_p.add_argument(
        "--from", dest="from_snapshot", type=str, default=None,
        help="Path to the older snapshot (default: second-most-recent in output/history/)"
    )
    diff_p.add_argument(
        "--to", dest="to_snapshot", type=str, default=None,
        help="Path to the newer snapshot (default: most recent in output/history/)"
    )

    # --- history ---
    history_p = subparsers.add_parser("history", help="List saved scan snapshots")
    history_p.add_argument(
        "--limit", type=int, default=20,
        help="Max number of snapshots to list, most recent first (default: 20)"
    )

    # --- report ---
    report_p = subparsers.add_parser(
        "report", help="Render a detailed HTML report from a saved scan snapshot (no rescan)"
    )
    report_p.add_argument(
        "--snapshot", type=str, default=None,
        help="Snapshot to render (default: most recent in output/history/)"
    )
    report_p.add_argument(
        "--out", type=str, default=None,
        help="Where to write the HTML file (default: output/report.html)"
    )
    report_p.add_argument(
        "--no-diff", action="store_true",
        help="Don't include the 'changes since the previous scan' section."
    )

    return parser


def _local_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


# Backwards compatibility alias
_utcnow_iso = _local_iso


def _unique_path(path: Path) -> Path:
    """Ensure path does not overwrite an existing file by appending _1, _2, etc."""
    if not path.exists():
        return path
    parent = path.parent
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _resolve_output_base(base: Path, extensions: tuple[str, ...]) -> Path:
    """If any file with `base.<ext>` already exists, find base_1, base_2, etc.
    so all output formats for this scan share the exact same stem without overwriting."""
    parent = base.parent
    stem = base.stem if base.suffix in extensions else (base.name if not base.suffix else base.stem)
    base_candidate = parent / stem

    if not any((base_candidate.with_suffix(ext)).exists() for ext in extensions):
        return base_candidate

    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}"
        if not any((candidate.with_suffix(ext)).exists() for ext in extensions):
            return candidate
        counter += 1


def _open_audit(config):
    """Start the per-scan audit log. Returns its path, or None if disabled.

    If auditing is enabled but the log can't be created, the scan is
    REFUSED rather than run unaudited - for a safety feature, failing
    open would be worse than stopping."""

    if not config.get("audit", {}).get("enabled", True):
        return None

    ts = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    path = AUDIT_DIR / f"scan_{ts}.jsonl"

    try:
        runner.configure(path)
    except OSError as e:
        print(f"[-] Cannot write the audit log ({path}): {e}")
        print("    Refusing to scan unaudited. Fix the path, or set audit.enabled: false in config.")
        raise SystemExit(2)

    return path


def _refuse(config, args, reason):
    """Report a refused scan: message, audit entry, non-zero exit."""
    print(f"[-] Scan refused: {reason}")

    if not args.dry_run:
        _open_audit(config)
        runner.log_event("refused", target=args.target, reason=reason,
                         user=runner.current_user(), argv=sys.argv[1:])
        runner.reset()

    raise SystemExit(2)


def _diff_against_previous(data):
    """(diff, previous_timestamp) vs the most recent saved snapshot, or
    (None, None) if there isn't a usable one."""
    try:
        snapshots = history.list_snapshots()
        if not snapshots:
            return None, None
        prev = history.load_snapshot(snapshots[-1])
        return history.diff_snapshots(prev["hosts"], data), prev.get("timestamp")
    except Exception:
        return None, None


def run_scan(args):
    config = load_config(args.config)

    # --- scan profile (CLI > explicit config value > profile) ---
    try:
        settings = profiles.resolve(config, cli_profile=args.profile, cli_workers=args.workers)
    except ValueError as e:
        print(f"[-] {e}")
        raise SystemExit(2)

    out_format = args.format or config["output"]["format"]
    outfile = args.outfile or config["output"]["outfile"]

    cve_config = dict(config["cve"])
    if args.cve_live is not None:
        cve_config["live_lookup"] = args.cve_live
    if getattr(args, "cve_timeout", None) is not None:
        cve_config["request_timeout"] = args.cve_timeout

    exclude_self = config["scan"]["exclude_self"] and not args.include_self

    # --- guardrails: validated BEFORE any packet is sent ---
    scope_cfg = config["scope"]
    exclude = guardrails.split_list(scope_cfg.get("exclude")) + guardrails.split_list(args.exclude)

    try:
        scope_info = guardrails.check_target(
            args.target,
            allowed=scope_cfg.get("allowed"),
            cli_scope=args.scope,
            max_addresses=scope_cfg.get("max_addresses", guardrails.DEFAULT_MAX_ADDRESSES),
            force=args.force,
        )
        guardrails.parse_exclusions(exclude)
    except guardrails.ScopeError as e:
        _refuse(config, args, str(e))

    tcp_pacing = profiles.pacing_args(settings, "tcp")
    udp_pacing = profiles.pacing_args(settings, "udp")

    deep_mode = bool(args.deep_inspection) if getattr(args, "deep_inspection", None) is not None else bool(config.get("scan", {}).get("deep_inspection", False))

    # --- dry run: show the plan, touch nothing ---
    if args.dry_run:
        from ot_recon.core.netutils import get_local_ips
        local_ips = get_local_ips() if exclude_self else set()
        steps = plan.build_plan(
            args.target, settings, config, exclude, args.udp, local_ips,
            cve_config.get("live_lookup"),
            config["scan"]["tcp_ports"], config["scan"]["udp_ports"],
            deep_inspection=deep_mode,
        )
        print(plan.format_plan(steps, settings, scope_info, exclude, local_ips))
        return

    audit_path = _open_audit(config)

    try:
        started = _local_iso()
        runner.log_event(
            "scan_start", tool_version=__version__, user=runner.current_user(),
            target=args.target, profile=settings["name"], settings=settings,
            scope=scope_info, excluded=exclude, argv=sys.argv[1:],
            udp=bool(args.udp), cve_live=bool(cve_config.get("live_lookup")),
            deep_inspection=deep_mode,
        )

        for note in scope_info["overridden"]:
            print(f"[!] Guardrail overridden with --force: {note}")
        print(f"[+] Scan profile: {settings['name']} - {settings.get('description', '')}")
        if deep_mode:
            print("[+] Deep OT Protocol Inspection enabled (CIP Backplane, S7comm SZL, Modbus MEI)")

        # Start from a clean slate so this run can only ever see its own output.
        clear_artifacts()
        nmap_version = get_nmap_version()

        hosts = discover_hosts(
            args.target, args.verbose, exclude_self=exclude_self,
            pacing=tcp_pacing, exclude=exclude,
        )
        scan_live_hosts(
            hosts, args.verbose, udp=args.udp,
            tcp_ports=config["scan"]["tcp_ports"],
            udp_ports=config["scan"]["udp_ports"],
            pacing=tcp_pacing, udp_pacing=udp_pacing,
        )

        data = parse_results()
        # Only hosts discovered THIS run may enter the pipeline - the
        # fingerprinter actively probes everything it is handed.
        discovered = set(hosts)
        data = [h for h in data if h["ip"] in discovered]

        data = enrich(data)
        data = fingerprint(
            data, args.verbose, workers=settings["workers"],
            script_timeout=settings["nmap_script_timeout"],
            pacing=tcp_pacing, version_intensity=settings.get("version_intensity"),
            deep_inspection=deep_mode,
        )
        data = classify(data)
        data = assess_risk(data, cve_config=cve_config, verbose=args.verbose)

        scan_ctx = {
            "tool_version": __version__,
            "nmap_version": nmap_version,
            "operator": runner.current_user(),
            "target": args.target,
            "started": started,
            "finished": _local_iso(),
            "deep_inspection": deep_mode,
            "profile": {
                "name": settings["name"],
                "description": settings.get("description", ""),
                "settings": {k: settings.get(k) for k in (
                    "tcp_timing", "udp_timing", "scan_delay", "max_retries",
                    "version_intensity", "workers", "nmap_script_timeout")},
            },
            "tcp_ports": config["scan"]["tcp_ports"],
            "udp_ports": config["scan"]["udp_ports"],
            "udp_scanned": bool(args.udp),
            "cve_live": bool(cve_config.get("live_lookup")),
            "exclude_self": bool(exclude_self),
            "excluded": exclude,
            "scope": scope_info,
            "hosts_discovered": len(hosts),
            "commands_run": runner.command_count(),
            "audit_log": str(audit_path) if audit_path else None,
        }
        coverage.annotate(data, scan_ctx)

        # Console table is always shown, regardless of --format, so the
        # operator always gets immediate feedback even when exporting.
        generate_report(data)
        print_coverage_summary(data, scan_ctx)

        report_ts = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        report_name = getattr(args, "report_name", None)
        if report_name:
            r_path = Path(report_name)
            base = r_path if r_path.parent != Path(".") else OUTPUT_DIR / r_path.name
        elif outfile:
            base = Path(outfile)
        else:
            base = OUTPUT_DIR / f"report_{report_ts}"

        active_exts = []
        if out_format in ("json", "all"):
            active_exts.append(".json")
        if out_format in ("csv", "all"):
            active_exts.append(".csv")
        if out_format in ("html", "all"):
            active_exts.append(".html")

        if active_exts:
            base = _resolve_output_base(base, tuple(active_exts))

        base.parent.mkdir(parents=True, exist_ok=True)

        if out_format in ("json", "all"):
            export_json(data, base.with_suffix(".json"), scan=scan_ctx)

        if out_format in ("csv", "all"):
            export_csv(data, base.with_suffix(".csv"))

        if out_format in ("html", "all"):
            diff, prev_ts = _diff_against_previous(data)
            export_html(data, base.with_suffix(".html"), scan_ctx=scan_ctx,
                        diff=diff, previous_timestamp=prev_ts)

        if not args.no_history:
            history.save_snapshot(data, meta=scan_ctx)

        runner.log_event(
            "scan_end", hosts_discovered=len(hosts), hosts_reported=len(data),
            commands_run=runner.command_count(),
        )
        if audit_path:
            print(f"[+] Audit log: {audit_path}")
    finally:
        runner.reset()


def run_report(args):
    snapshots = history.list_snapshots()

    if args.snapshot:
        path = Path(args.snapshot)
    elif snapshots:
        path = snapshots[-1]
    else:
        print("[-] No saved snapshots yet. Run 'ot-recon scan <target>' first.")
        return

    try:
        snap = history.load_snapshot(path)
    except FileNotFoundError:
        print(f"[-] Snapshot file not found: {path}")
        return
    except ValueError as e:
        print(f"[-] Snapshot is not valid JSON ({path}): {e}")
        return

    hosts = snap.get("hosts", [])
    scan_ctx = snap.get("scan")

    diff = prev_ts = None
    if not args.no_diff:
        try:
            idx = [s.resolve() for s in snapshots].index(path.resolve())
        except ValueError:
            idx = -1
        if idx > 0:
            try:
                prev = history.load_snapshot(snapshots[idx - 1])
                diff = history.diff_snapshots(prev["hosts"], hosts)
                prev_ts = prev.get("timestamp")
            except Exception:
                diff = None

    out = _unique_path(Path(args.out) if args.out else OUTPUT_DIR / "report.html")
    out.parent.mkdir(parents=True, exist_ok=True)

    export_html(hosts, out, scan_ctx=scan_ctx, diff=diff,
                previous_timestamp=prev_ts, snapshot_timestamp=snap.get("timestamp"))


def run_diff(args):
    if args.from_snapshot and args.to_snapshot:
        old_path, new_path = Path(args.from_snapshot), Path(args.to_snapshot)
    else:
        snapshots = history.list_snapshots()

        if len(snapshots) < 2:
            print(
                "[-] Need at least 2 saved snapshots to diff "
                f"(found {len(snapshots)} in output/history/). Run 'ot-recon scan' at least twice first."
            )
            return

        old_path, new_path = snapshots[-2], snapshots[-1]

    try:
        old_snap = history.load_snapshot(old_path)
        new_snap = history.load_snapshot(new_path)
    except FileNotFoundError as e:
        print(f"[-] Snapshot file not found: {e}")
        return

    diff = history.diff_snapshots(old_snap["hosts"], new_snap["hosts"])
    generate_diff_report(diff, old_snap.get("timestamp"), new_snap.get("timestamp"))


def run_history(args):
    snapshots = history.list_snapshots()

    if not snapshots:
        print("[-] No saved snapshots yet. Run 'ot-recon scan <target>' first.")
        return

    print(f"[+] {len(snapshots)} snapshot(s) found (showing up to {args.limit}, most recent first):\n")

    for path in list(reversed(snapshots))[:args.limit]:
        snap = history.load_snapshot(path)
        ts = snap.get("timestamp", path.stem)
        count = snap.get("host_count", len(snap.get("hosts", [])))
        high_sev_hosts = sum(
            1 for h in snap.get("hosts", [])
            if h.get("risk_severity") in ("Critical", "High")
        )
        print(f"  {ts}  |  {count} host(s)  |  {high_sev_hosts} Critical/High  |  {path}")


def main():
    banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    elif args.command == "diff":
        run_diff(args)
    elif args.command == "history":
        run_history(args)
    elif args.command == "report":
        run_report(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
