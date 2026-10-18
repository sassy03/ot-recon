import sys
import pytest
from unittest.mock import patch

from ot_recon import main as main_module


def _run_main(argv, tmp_path):
    """Run main.main() with sys.argv patched, and every pipeline stage
    function mocked so no real nmap/network calls happen. Returns the mock
    objects so tests can assert on call args.
    """

    mocks = {}

    with patch.object(sys, "argv", ["ot-recon"] + argv), \
         patch.object(main_module, "discover_hosts", return_value=["10.0.0.1"]) as m_discover, \
         patch.object(main_module, "scan_live_hosts") as m_scan, \
         patch.object(main_module, "parse_results", return_value=[{"ip": "10.0.0.1", "ports": []}]) as m_parse, \
         patch.object(main_module, "enrich", side_effect=lambda d: d) as m_enrich, \
         patch.object(main_module, "fingerprint", side_effect=lambda d, *a, **kw: d) as m_fp, \
         patch.object(main_module, "classify", side_effect=lambda d: d) as m_classify, \
         patch.object(main_module, "assess_risk", side_effect=lambda d, *a, **kw: d) as m_risk, \
         patch.object(main_module, "generate_report") as m_report, \
         patch.object(main_module, "export_json") as m_json, \
         patch.object(main_module, "export_csv") as m_csv, \
         patch.object(main_module.history, "save_snapshot") as m_snapshot, \
         patch.object(main_module, "export_html") as m_html, \
         patch.object(main_module, "clear_artifacts") as m_clear, \
         patch.object(main_module, "get_nmap_version", return_value="7.94"), \
         patch.object(main_module, "OUTPUT_DIR", tmp_path):

        main_module.main()

        mocks.update(discover=m_discover, scan=m_scan, parse=m_parse, enrich=m_enrich,
                     fp=m_fp, classify=m_classify, risk=m_risk, report=m_report,
                     export_json=m_json, export_csv=m_csv, snapshot=m_snapshot,
                     export_html=m_html, clear=m_clear)

    return mocks


def test_scan_with_no_target_errors_via_argparse(capsys):
    """target is a required positional on the scan subparser now, so
    argparse itself rejects a missing target with a usage error and
    SystemExit(2), rather than a custom message."""

    with patch.object(sys, "argv", ["ot-recon", "scan"]), \
         patch.object(main_module, "discover_hosts") as m_discover:
        with pytest.raises(SystemExit):
            main_module.main()

    m_discover.assert_not_called()
    assert "usage" in capsys.readouterr().err.lower()


def test_unknown_command_errors_via_argparse(capsys):
    with patch.object(sys, "argv", ["ot-recon", "bogus"]):
        with pytest.raises(SystemExit):
            main_module.main()

    assert "invalid choice" in capsys.readouterr().err.lower()


def test_no_command_prints_help(capsys):
    with patch.object(sys, "argv", ["ot-recon"]):
        main_module.main()

    assert "usage" in capsys.readouterr().out.lower()


def test_default_scan_runs_full_pipeline_in_order(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    mocks["discover"].assert_called_once()
    mocks["scan"].assert_called_once()
    mocks["parse"].assert_called_once()
    mocks["enrich"].assert_called_once()
    mocks["fp"].assert_called_once()
    mocks["classify"].assert_called_once()
    mocks["risk"].assert_called_once()
    mocks["report"].assert_called_once()

    # default format is 'table' -> no export calls
    mocks["export_json"].assert_not_called()
    mocks["export_csv"].assert_not_called()


def test_workers_cli_flag_overrides_config(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--workers", "42"], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 42


def test_workers_falls_back_to_scan_profile_when_unset(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 2   # default profile is "safe"


def test_format_json_triggers_json_export_only(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "json"], tmp_path)

    mocks["export_json"].assert_called_once()
    mocks["export_csv"].assert_not_called()


def test_format_all_triggers_both_exports(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "all"], tmp_path)

    mocks["export_json"].assert_called_once()
    mocks["export_csv"].assert_called_once()


def test_udp_flag_is_forwarded_to_scan_live_hosts(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--udp"], tmp_path)

    _, kwargs = mocks["scan"].call_args
    assert kwargs["udp"] is True


def test_site_config_overrides_are_respected(tmp_path):
    site_yaml = tmp_path / "site.yaml"
    site_yaml.write_text("fingerprint:\n  workers: 77\n")

    mocks = _run_main(["scan", "10.0.0.0/24", "--config", str(site_yaml)], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 77


def test_scan_saves_history_snapshot_by_default(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)
    mocks["snapshot"].assert_called_once()


def test_no_history_flag_skips_snapshot(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--no-history"], tmp_path)
    mocks["snapshot"].assert_not_called()


def test_diff_with_fewer_than_two_snapshots_prints_message(tmp_path, capsys):
    with patch.object(sys, "argv", ["ot-recon", "diff"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[]):
        main_module.main()

    assert "at least 2 saved snapshots" in capsys.readouterr().out


def test_diff_compares_two_most_recent_snapshots_by_default(tmp_path):
    old_snap = {"timestamp": "old", "hosts": [{"ip": "10.0.0.1", "ot_ports": [], "risks": []}]}
    new_snap = {"timestamp": "new", "hosts": [{"ip": "10.0.0.1", "ot_ports": [], "risks": []},
                                               {"ip": "10.0.0.2", "ot_ports": [], "risks": []}]}

    fake_paths = [tmp_path / "old.json", tmp_path / "new.json"]

    with patch.object(sys, "argv", ["ot-recon", "diff"]), \
         patch.object(main_module.history, "list_snapshots", return_value=fake_paths), \
         patch.object(main_module.history, "load_snapshot",
                       side_effect=lambda p: old_snap if p == fake_paths[0] else new_snap), \
         patch.object(main_module, "generate_diff_report") as m_diff_report:
        main_module.main()

    m_diff_report.assert_called_once()
    diff_arg = m_diff_report.call_args[0][0]
    assert diff_arg["new_hosts"] == ["10.0.0.2"]


def test_diff_with_explicit_from_and_to(tmp_path):
    old_snap = {"timestamp": "old", "hosts": []}
    new_snap = {"timestamp": "new", "hosts": []}

    old_path = tmp_path / "a.json"
    new_path = tmp_path / "b.json"

    with patch.object(sys, "argv", ["ot-recon", "diff", "--from", str(old_path), "--to", str(new_path)]), \
         patch.object(main_module.history, "load_snapshot",
                       side_effect=lambda p: old_snap if str(p) == str(old_path) else new_snap) as m_load, \
         patch.object(main_module, "generate_diff_report") as m_diff_report:
        main_module.main()

    assert m_load.call_count == 2
    m_diff_report.assert_called_once()


def test_history_command_with_no_snapshots(capsys):
    with patch.object(sys, "argv", ["ot-recon", "history"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[]):
        main_module.main()

    assert "No saved snapshots" in capsys.readouterr().out


def test_history_command_lists_snapshots(tmp_path, capsys):
    snap = {"timestamp": "20260101T000000Z", "host_count": 3, "hosts": [
        {"risk_severity": "Critical"}, {"risk_severity": "Low"}, {"risk_severity": "None"},
    ]}
    fake_path = tmp_path / "snap.json"

    with patch.object(sys, "argv", ["ot-recon", "history"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[fake_path]), \
         patch.object(main_module.history, "load_snapshot", return_value=snap):
        main_module.main()

    out = capsys.readouterr().out
    assert "20260101T000000Z" in out
    assert "3 host(s)" in out
    assert "1 Critical/High" in out


# --- self-exclusion (--include-self / scan.exclude_self) ---

def test_scan_excludes_self_by_default(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    _, kwargs = mocks["discover"].call_args
    assert kwargs["exclude_self"] is True


def test_include_self_flag_disables_exclusion(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--include-self"], tmp_path)

    _, kwargs = mocks["discover"].call_args
    assert kwargs["exclude_self"] is False


def test_config_can_disable_self_exclusion_persistently(tmp_path):
    site_cfg = tmp_path / "site.yaml"
    site_cfg.write_text("scan:\n  exclude_self: false\n")

    mocks = _run_main(["scan", "10.0.0.0/24", "--config", str(site_cfg)], tmp_path)

    _, kwargs = mocks["discover"].call_args
    assert kwargs["exclude_self"] is False


def test_include_self_flag_with_config_already_false_stays_false(tmp_path):
    site_cfg = tmp_path / "site.yaml"
    site_cfg.write_text("scan:\n  exclude_self: false\n")

    mocks = _run_main(
        ["scan", "10.0.0.0/24", "--config", str(site_cfg), "--include-self"], tmp_path
    )

    _, kwargs = mocks["discover"].call_args
    assert kwargs["exclude_self"] is False


# =====================================================================
# Guardrails, profiles, dry-run, audit, report  (v1.3)
# =====================================================================

import json as _json


def _audit_events(main_module_):
    files = list(main_module_.AUDIT_DIR.glob("*.jsonl")) if main_module_.AUDIT_DIR.exists() else []
    assert len(files) <= 1
    return [_json.loads(l) for f in files for l in f.read_text().splitlines()]


# --- profiles ---

def test_default_profile_is_safe_and_reaches_the_scan_commands(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    _, scan_kw = mocks["scan"].call_args
    assert scan_kw["pacing"] == ["-T2", "--scan-delay", "200ms", "--max-retries", "1"]

    _, fp_kw = mocks["fp"].call_args
    assert fp_kw["pacing"] == scan_kw["pacing"]
    assert fp_kw["version_intensity"] == 0
    assert fp_kw["script_timeout"] == 60

    _, disc_kw = mocks["discover"].call_args
    assert disc_kw["pacing"] == scan_kw["pacing"]


def test_fast_profile_restores_the_original_aggressive_behaviour(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--profile", "fast"], tmp_path)

    assert mocks["scan"].call_args.kwargs["pacing"] == ["-T5"]
    assert mocks["scan"].call_args.kwargs["udp_pacing"] == ["-T4"]
    assert mocks["fp"].call_args.kwargs["workers"] == 10
    assert mocks["fp"].call_args.kwargs["version_intensity"] is None


def test_unknown_profile_exits_nonzero_before_scanning(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _run_main(["scan", "10.0.0.0/24", "--profile", "turbo"], tmp_path)

    assert exc.value.code == 2
    assert "Unknown scan profile" in capsys.readouterr().out


def test_profile_can_come_from_config(tmp_path):
    site = tmp_path / "site.yaml"
    site.write_text("scan:\n  profile: standard\n")
    mocks = _run_main(["scan", "10.0.0.0/24", "--config", str(site)], tmp_path)
    assert mocks["scan"].call_args.kwargs["pacing"][0] == "-T3"


# --- scope guardrails ---

def _assert_refused_without_touching_network(argv, tmp_path, capsys, fragment):
    mocks_holder = {}
    with pytest.raises(SystemExit) as exc:
        mocks_holder["m"] = _run_main(argv, tmp_path)
    assert exc.value.code == 2
    assert fragment in capsys.readouterr().out


def test_public_target_is_refused_before_any_scanning(tmp_path, capsys):
    from unittest.mock import patch as _patch
    with _patch.object(main_module, "discover_hosts") as disc:
        with pytest.raises(SystemExit) as exc:
            with _patch.object(sys, "argv", ["ot-recon", "scan", "8.8.8.0/24"]):
                main_module.main()
    assert exc.value.code == 2
    disc.assert_not_called()
    assert "Scan refused" in capsys.readouterr().out


def test_force_overrides_sanity_refusal_and_is_reported(tmp_path, capsys):
    mocks = _run_main(["scan", "8.8.8.8", "--force"], tmp_path)
    assert mocks["discover"].called
    assert "Guardrail overridden with --force" in capsys.readouterr().out


def test_force_cannot_override_allowlist_policy(tmp_path, capsys):
    site = tmp_path / "site.yaml"
    site.write_text("scope:\n  allowed: ['192.168.10.0/24']\n")
    _assert_refused_without_touching_network(
        ["scan", "192.168.20.0/24", "--config", str(site), "--force"],
        tmp_path, capsys, "outside the allowed scope")


def test_scope_flag_refuses_target_outside_it(tmp_path, capsys):
    _assert_refused_without_touching_network(
        ["scan", "192.168.11.0/24", "--scope", "192.168.10.0/24"], tmp_path, capsys, "--scope")


def test_oversized_target_refused_by_default(tmp_path, capsys):
    _assert_refused_without_touching_network(
        ["scan", "10.0.0.0/16"], tmp_path, capsys, "limit")


def test_max_addresses_configurable(tmp_path):
    site = tmp_path / "site.yaml"
    site.write_text("scope:\n  max_addresses: 70000\n")
    mocks = _run_main(["scan", "10.0.0.0/16", "--config", str(site)], tmp_path)
    assert mocks["discover"].called


def test_invalid_exclude_entry_is_refused(tmp_path, capsys):
    _assert_refused_without_touching_network(
        ["scan", "10.0.0.0/24", "--exclude", "not-an-ip"], tmp_path, capsys, "exclude")


def test_refusal_is_recorded_in_the_audit_log(tmp_path):
    with pytest.raises(SystemExit):
        _run_main(["scan", "8.8.8.0/24"], tmp_path)

    events = _audit_events(main_module)
    assert [e["event"] for e in events] == ["refused"]
    assert "private" in events[0]["reason"] or "address space" in events[0]["reason"]
    assert events[0]["target"] == "8.8.8.0/24"


# --- do-not-scan list ---

def test_exclude_flag_and_config_are_combined(tmp_path):
    site = tmp_path / "site.yaml"
    site.write_text("scope:\n  exclude: ['10.0.0.5']\n")
    mocks = _run_main(["scan", "10.0.0.0/24", "--config", str(site), "--exclude", "10.0.0.9,10.0.0.64/28"], tmp_path)

    assert mocks["discover"].call_args.kwargs["exclude"] == ["10.0.0.5", "10.0.0.9", "10.0.0.64/28"]


# --- dry run ---

def test_dry_run_sends_nothing_writes_nothing_and_shows_the_plan(tmp_path, capsys):
    before = set(tmp_path.rglob("*"))
    mocks = _run_main(["scan", "10.0.0.0/24", "--dry-run"], tmp_path)
    out = capsys.readouterr().out

    for stage in ("discover", "scan", "parse", "fp", "report", "export_json", "snapshot", "clear"):
        mocks[stage].assert_not_called()
    assert set(tmp_path.rglob("*")) == before            # no files, no audit dir
    assert "[DRY RUN]" in out and "Nothing will be sent" in out
    assert "nmap -sn" in out and "--scan-delay 200ms" in out
    assert "Fingerprint probe: s7-info" in out and "--version-intensity 0" in out


def test_dry_run_plan_shows_udp_and_live_cve_steps_only_when_enabled(tmp_path, capsys):
    _run_main(["scan", "10.0.0.0/24", "--dry-run"], tmp_path)
    plain = capsys.readouterr().out
    assert "-sU" not in plain and "NVD" not in plain

    _run_main(["scan", "10.0.0.0/24", "--dry-run", "--udp", "--cve-live"], tmp_path)
    full = capsys.readouterr().out
    assert "-sU" in full and "Live CVE lookup (NVD API)" in full


def test_dry_run_still_refuses_a_target_a_real_run_would_refuse(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _run_main(["scan", "8.8.8.0/24", "--dry-run"], tmp_path)
    assert exc.value.code == 2
    assert not main_module.AUDIT_DIR.exists()            # and still writes nothing


# --- audit log ---

def test_real_scan_writes_a_start_and_end_audit_record(tmp_path):
    _run_main(["scan", "10.0.0.0/24", "--profile", "standard"], tmp_path)

    events = _audit_events(main_module)
    kinds = [e["event"] for e in events]
    assert kinds[0] == "scan_start" and kinds[-1] == "scan_end"
    start = events[0]
    assert start["target"] == "10.0.0.0/24" and start["profile"] == "standard"
    assert start["tool_version"] and start["user"]
    assert "scan" in start["argv"] and "--profile" in start["argv"]


def test_audit_can_be_disabled_in_config(tmp_path):
    site = tmp_path / "site.yaml"
    site.write_text("audit:\n  enabled: false\n")
    _run_main(["scan", "10.0.0.0/24", "--config", str(site)], tmp_path)
    assert not main_module.AUDIT_DIR.exists()


def test_unwritable_audit_log_refuses_to_scan_rather_than_running_unaudited(tmp_path, capsys):
    blocker = tmp_path / "iam_a_file"
    blocker.write_text("x")

    from unittest.mock import patch as _patch
    with _patch.object(main_module, "AUDIT_DIR", blocker / "audit"):
        with pytest.raises(SystemExit) as exc:
            _run_main(["scan", "10.0.0.0/24"], tmp_path)

    assert exc.value.code == 2
    assert "Refusing to scan unaudited" in capsys.readouterr().out


def test_audit_logging_is_always_switched_off_after_the_scan(tmp_path):
    from ot_recon.core import runner as _runner
    _run_main(["scan", "10.0.0.0/24"], tmp_path)
    assert _runner.audit_path() is None


def test_audit_logging_is_switched_off_even_if_the_pipeline_crashes(tmp_path):
    from unittest.mock import patch as _patch
    from ot_recon.core import runner as _runner
    with _patch.object(sys, "argv", ["ot-recon", "scan", "10.0.0.0/24"]), \
         _patch.object(main_module, "discover_hosts", side_effect=RuntimeError("boom")), \
         _patch.object(main_module, "clear_artifacts"), \
         _patch.object(main_module, "get_nmap_version", return_value=None):
        with pytest.raises(RuntimeError):
            main_module.main()
    assert _runner.audit_path() is None


# --- stale output can't leak into a run ---

def test_artifacts_cleared_before_discovery(tmp_path):
    order = []
    from unittest.mock import patch as _patch
    with _patch.object(main_module, "clear_artifacts", side_effect=lambda: order.append("clear")), \
         _patch.object(main_module, "discover_hosts", side_effect=lambda *a, **k: order.append("discover") or []), \
         _patch.object(main_module, "scan_live_hosts"), \
         _patch.object(main_module, "parse_results", return_value=[]), \
         _patch.object(main_module, "get_nmap_version", return_value=None), \
         _patch.object(main_module, "generate_report"), \
         _patch.object(main_module.history, "save_snapshot"), \
         _patch.object(sys, "argv", ["ot-recon", "scan", "10.0.0.0/24"]):
        main_module.main()

    assert order == ["clear", "discover"]


def test_hosts_not_discovered_this_run_never_reach_the_fingerprinter(tmp_path):
    """Regression: with a stale scan.xml on disk, a run that discovered
    nothing used to actively probe the previous run's hosts."""
    from unittest.mock import patch as _patch
    leaked = {}
    with _patch.object(main_module, "discover_hosts", return_value=["10.0.0.1"]), \
         _patch.object(main_module, "scan_live_hosts"), \
         _patch.object(main_module, "clear_artifacts"), \
         _patch.object(main_module, "get_nmap_version", return_value=None), \
         _patch.object(main_module, "parse_results", return_value=[
             {"ip": "10.0.0.1", "ports": []}, {"ip": "10.9.9.9", "ports": []}]), \
         _patch.object(main_module, "fingerprint", side_effect=lambda d, *a, **k: leaked.setdefault("ips", [h["ip"] for h in d]) and d), \
         _patch.object(main_module, "generate_report"), \
         _patch.object(main_module.history, "save_snapshot"), \
         _patch.object(sys, "argv", ["ot-recon", "scan", "10.0.0.0/24"]):
        main_module.main()

    assert leaked["ips"] == ["10.0.0.1"]


# --- report data flows into snapshot / exports ---

def test_snapshot_receives_scan_context_with_profile_and_coverage(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    meta = mocks["snapshot"].call_args.kwargs["meta"]
    assert meta["profile"]["name"] == "safe"
    assert meta["target"] == "10.0.0.0/24" and meta["nmap_version"] == "7.94"
    assert meta["udp_scanned"] is False
    assert any("UDP was not scanned" in g for g in meta["coverage"]["gaps"])
    assert meta["scope"]["address_count"] == 256


def test_html_format_exports_html_only(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "html"], tmp_path)
    mocks["export_html"].assert_called_once()
    mocks["export_json"].assert_not_called()
    mocks["export_csv"].assert_not_called()
    assert mocks["export_html"].call_args.args[1].suffix == ".html"
    assert mocks["export_html"].call_args.kwargs["scan_ctx"]["target"] == "10.0.0.0/24"


def test_all_format_includes_html(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "all"], tmp_path)
    for k in ("export_html", "export_json", "export_csv"):
        mocks[k].assert_called_once()


def test_table_format_exports_nothing(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)
    mocks["export_html"].assert_not_called()


def test_json_export_receives_scan_context(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "json"], tmp_path)
    assert mocks["export_json"].call_args.kwargs["scan"]["profile"]["name"] == "safe"


# --- version ---

def test_version_flag_reports_the_real_package_version(capsys):
    from ot_recon import __version__
    with pytest.raises(SystemExit) as exc:
        from unittest.mock import patch as _patch
        with _patch.object(sys, "argv", ["ot-recon", "--version"]):
            main_module.main()
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_setup_py_and_package_agree_on_version():
    import re, pathlib
    from ot_recon import __version__
    setup_text = (pathlib.Path(main_module.__file__).parent.parent / "setup.py").read_text()
    assert "__version__" in setup_text            # read from the package, not duplicated
    assert not re.search(r'version\s*=\s*"\d', setup_text)


# --- `report` subcommand ---

def _write_snapshot(name, hosts, scan=None):
    d = main_module.history.HISTORY_DIR
    d.mkdir(parents=True, exist_ok=True)
    payload = {"timestamp": name, "host_count": len(hosts), "hosts": hosts}
    if scan:
        payload["scan"] = scan
    (d / f"{name}.json").write_text(_json.dumps(payload))
    return d / f"{name}.json"


def _run_report(argv, tmp_path):
    from unittest.mock import patch as _patch
    with _patch.object(sys, "argv", ["ot-recon", "report"] + argv), \
         _patch.object(main_module, "export_html") as m_html, \
         _patch.object(main_module, "OUTPUT_DIR", tmp_path):
        main_module.main()
    return m_html


def test_report_with_no_snapshots_explains_what_to_do(tmp_path, capsys):
    m = _run_report([], tmp_path)
    m.assert_not_called()
    assert "No saved snapshots" in capsys.readouterr().out


def test_report_renders_latest_snapshot_with_its_scan_context(tmp_path):
    _write_snapshot("20260101T000000Z", [{"ip": "10.0.0.1"}])
    _write_snapshot("20260102T000000Z", [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}], scan={"target": "x"})

    m = _run_report([], tmp_path)

    args, kwargs = m.call_args
    assert [h["ip"] for h in args[0]] == ["10.0.0.1", "10.0.0.2"]
    assert kwargs["scan_ctx"] == {"target": "x"}
    assert kwargs["snapshot_timestamp"] == "20260102T000000Z"
    assert args[1] == tmp_path / "report.html"


def test_report_includes_diff_against_the_previous_snapshot(tmp_path):
    _write_snapshot("20260101T000000Z", [{"ip": "10.0.0.1"}])
    _write_snapshot("20260102T000000Z", [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}])

    kwargs = _run_report([], tmp_path).call_args.kwargs

    assert kwargs["diff"]["new_hosts"] == ["10.0.0.2"]
    assert kwargs["previous_timestamp"] == "20260101T000000Z"


def test_report_no_diff_flag_omits_the_comparison(tmp_path):
    _write_snapshot("20260101T000000Z", [{"ip": "10.0.0.1"}])
    _write_snapshot("20260102T000000Z", [{"ip": "10.0.0.2"}])
    assert _run_report(["--no-diff"], tmp_path).call_args.kwargs["diff"] is None


def test_report_for_an_old_snapshot_without_scan_metadata_still_works(tmp_path):
    _write_snapshot("20250101T000000Z", [{"ip": "10.0.0.1"}])    # pre-1.3: no "scan" key
    kwargs = _run_report([], tmp_path).call_args.kwargs
    assert kwargs["scan_ctx"] is None


def test_report_explicit_snapshot_and_out_path(tmp_path):
    first = _write_snapshot("20260101T000000Z", [{"ip": "10.0.0.1"}])
    _write_snapshot("20260102T000000Z", [{"ip": "10.0.0.2"}])
    out = tmp_path / "custom" / "r.html"

    m = _run_report(["--snapshot", str(first), "--out", str(out)], tmp_path)

    assert m.call_args.args[0] == [{"ip": "10.0.0.1"}]
    assert m.call_args.args[1] == out and out.parent.exists()


def test_report_missing_or_corrupt_snapshot_is_a_clear_message(tmp_path, capsys):
    m = _run_report(["--snapshot", str(tmp_path / "nope.json")], tmp_path)
    assert "not found" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    m = _run_report(["--snapshot", str(bad)], tmp_path)
    assert "not valid JSON" in capsys.readouterr().out
    m.assert_not_called()


def test_cli_cve_timeout_overrides_config_timeout(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--cve-live", "--cve-timeout", "45"], tmp_path)
    cve_cfg = mocks["risk"].call_args.kwargs["cve_config"]
    assert cve_cfg["live_lookup"] is True
    assert cve_cfg["request_timeout"] == 45


def test_unique_path_handles_existing_files(tmp_path):
    file1 = tmp_path / "report.html"
    assert main_module._unique_path(file1) == file1

    file1.write_text("existing")
    file2 = main_module._unique_path(file1)
    assert file2 == tmp_path / "report_1.html"

    file2.write_text("existing 2")
    file3 = main_module._unique_path(file1)
    assert file3 == tmp_path / "report_2.html"


def test_resolve_output_base_preserves_synchronization_across_extensions(tmp_path):
    base = tmp_path / "scan_report"
    # None exist
    resolved = main_module._resolve_output_base(base, (".html", ".json", ".csv"))
    assert resolved == base

    # Create only the html file
    (tmp_path / "scan_report.html").write_text("dummy")
    resolved2 = main_module._resolve_output_base(base, (".html", ".json", ".csv"))
    assert resolved2 == tmp_path / "scan_report_1"


def test_default_scan_report_uses_timestamp_naming_and_does_not_overwrite(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "html"], tmp_path)
    out_html_path = mocks["export_html"].call_args.args[1]
    assert out_html_path.parent == tmp_path
    assert out_html_path.name.startswith("report_")
    assert out_html_path.suffix == ".html"


def test_custom_report_name_flag_and_non_overwriting(tmp_path):
    # First run creates custom_site.html
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "html", "--report-name", "custom_site"], tmp_path)
    out_path = mocks["export_html"].call_args.args[1]
    assert out_path == tmp_path / "custom_site.html"

    # Simulate that file existing on disk
    out_path.write_text("first report content")

    # Second run with same report name must not overwrite, but create custom_site_1.html
    mocks2 = _run_main(["scan", "10.0.0.0/24", "--format", "html", "--report-name", "custom_site"], tmp_path)
    out_path2 = mocks2["export_html"].call_args.args[1]
    assert out_path2 == tmp_path / "custom_site_1.html"


def test_deep_inspection_cli_flag_reaches_fingerprinter(tmp_path):
    # Without --deep: deep_inspection should be False by default
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)
    assert mocks["fp"].call_args.kwargs["deep_inspection"] is False

    # With --deep: deep_inspection should be True
    mocks_deep = _run_main(["scan", "10.0.0.0/24", "--deep"], tmp_path)
    assert mocks_deep["fp"].call_args.kwargs["deep_inspection"] is True

    # With --deep-inspection: deep_inspection should be True
    mocks_deep_long = _run_main(["scan", "10.0.0.0/24", "--deep-inspection"], tmp_path)
    assert mocks_deep_long["fp"].call_args.kwargs["deep_inspection"] is True



