# ot_recon/gui.py
#
# Optional GUI front-end for ot-recon, built with Gooey. Kept as a
# separate entry point from main.py so the plain CLI (`ot-recon ...`)
# never requires wxPython/Gooey as a dependency - only people who want
# the GUI (`ot-recon-gui`) need those installed.
#
# Reuses run_scan/run_diff/run_history from main.py directly, so there is
# exactly one implementation of the actual logic; this file only adds a
# GooeyParser-based argument form on top of it.

import sys

from gooey import Gooey, GooeyParser

from ot_recon.main import run_scan, run_diff, run_history, run_report


def make_gui_parser():
    """Build the GooeyParser form without launching any GUI. Separate from
    the @Gooey-decorated build_gui_parser() below so tests can construct
    it and check it stays in sync with main.build_parser()."""

    parser = GooeyParser(
        prog="ot-recon",
        description="OT Network Recon Tool (Safe & OT-aware)",
    )

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
        help="Concurrent fingerprinting workers (blank = set by the scan profile)"
    )
    scan_p.add_argument(
        "--format", choices=["table", "json", "csv", "html", "all"], default=None,
        help="Output format(s). 'table' prints to console; json/csv/html/all also write files. "
             "html = the full assessment report."
    )
    # FileSaver/FileChooser give native OS file dialogs instead of a plain
    # text box for anything path-shaped.
    scan_p.add_argument(
        "--report-name", type=str, default=None,
        help="Custom filename for exported report(s) without extension (saved under output/<name>.<ext>). "
             "Default: timestamped name (output/report_YYYYMMDD_HHMMSS.<ext>)."
    )
    scan_p.add_argument(
        "--outfile", widget="FileSaver",
        help="Base path/name for exported report file(s). Takes precedence over --report-name."
    )
    scan_p.add_argument(
        "--config", widget="FileChooser",
        help="Site-specific config YAML, layered on top of data/config.yaml."
    )
    scan_p.add_argument(
        "--no-history", action="store_true",
        help="Don't save this run as a history snapshot."
    )
    scan_p.add_argument(
        "--cve-live", action="store_true", default=None,
        help="Supplement local CVE correlation with a live NVD lookup (needs internet "
             "and the cve-live extra). Set the NVD_API_KEY env var for higher rate limits."
    )
    scan_p.add_argument(
        "--cve-timeout", type=int, default=None,
        help="Per-request HTTP timeout in seconds for live NVD API lookups (default: from config, 30s)."
    )
    scan_p.add_argument(
        "--profile", choices=["safe", "standard", "fast"], default=None,
        help="How hard to lean on the network. safe = gentle (recommended for live OT "
             "networks), standard, fast = original aggressive timing. Blank = use config."
    )
    scan_p.add_argument(
        "--scope", type=str, default=None,
        help="Refuse to run unless the target is inside these comma-separated networks "
             "(typo guard), e.g. 192.168.10.0/24"
    )
    scan_p.add_argument(
        "--exclude", type=str, default=None,
        help="Comma-separated IPs/CIDRs never to scan (fragile devices)."
    )
    scan_p.add_argument(
        "--force", action="store_true",
        help="Override sanity refusals (non-private / oversized / hostname target). "
             "Cannot override the configured allowlist."
    )
    scan_p.add_argument(
        "--dry-run", action="store_true",
        help="Show exactly what would be run. Nothing is sent, nothing is written."
    )
    scan_p.add_argument(
        "--include-self", action="store_true",
        help="Include this machine's own IP address(es) in the scan. By default the "
             "scanning host is auto-detected and excluded."
    )
    scan_p.add_argument(
        "--deep", "--deep-inspection", action="store_true", default=None,
        dest="deep_inspection",
        help="Enable deep active OT protocol inspection (CIP Backplane Chassis enumeration, "
             "Siemens S7comm keyswitch & SZL security levels, Modbus TCP MEI device identification)."
    )

    # --- diff ---
    diff_p = subparsers.add_parser("diff", help="Compare two saved scan snapshots")
    diff_p.add_argument(
        "--from", dest="from_snapshot", widget="FileChooser",
        help="Older snapshot (default: second-most-recent in output/history/)"
    )
    diff_p.add_argument(
        "--to", dest="to_snapshot", widget="FileChooser",
        help="Newer snapshot (default: most recent in output/history/)"
    )

    # --- history ---
    history_p = subparsers.add_parser("history", help="List saved scan snapshots")
    history_p.add_argument(
        "--limit", type=int, default=20,
        help="Max number of snapshots to list, most recent first"
    )

    # --- report ---
    report_p = subparsers.add_parser("report", help="Render an HTML report from a saved scan")
    report_p.add_argument(
        "--snapshot", widget="FileChooser", default=None,
        help="Snapshot to render (blank = most recent)"
    )
    report_p.add_argument(
        "--out", widget="FileSaver", default=None,
        help="Where to save the HTML file (blank = output/report.html)"
    )
    report_p.add_argument(
        "--no-diff", action="store_true",
        help="Leave out the 'changes since the previous scan' section."
    )

    return parser


@Gooey(
    program_name="OT-Recon",
    program_description="OT Network Reconnaissance Tool",
    default_size=(900, 700),
    tabbed_groups=True,
    target=f'"{sys.executable}" -u -m ot_recon.gui',
    # ot-recon's fingerprinter already prints "Fingerprinted N/M (ip)" as
    # each host finishes - Gooey can turn that straight into a real
    # progress bar with no changes to the scanning code itself.
    progress_regex=r"Fingerprinted (\d+)/(\d+)",
    progress_expr="x[0] / x[1] * 100",
    hide_progress_msg=False,
    # NOTE: do NOT set richtext_controls=True. It selects Gooey's
    # RichTextConsole, which calls colored.style.ESC - removed in recent
    # releases of the `colored` package - so the whole GUI crashed at
    # startup (AttributeError). The plain console is all this tool needs.
)
def build_gui_parser():
    return make_gui_parser().parse_args()


def gui_main():
    args = build_gui_parser()

    # run_scan/run_diff/run_history read args.config / args.outfile as
    # plain strings via Path(...); GooeyParser's FileChooser/FileSaver
    # widgets already hand back plain path strings (or None if left
    # blank), so these drop straight in with zero changes to main.py.
    if args.command == "scan":
        run_scan(args)
    elif args.command == "diff":
        run_diff(args)
    elif args.command == "history":
        run_history(args)
    elif args.command == "report":
        run_report(args)


if __name__ == "__main__":
    gui_main()
