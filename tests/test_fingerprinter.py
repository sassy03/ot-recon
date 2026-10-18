import pytest
import time
from unittest.mock import patch, MagicMock

from ot_recon.core import fingerprinter


@pytest.fixture(autouse=True)
def _mock_no_network(monkeypatch):
    """By default, simulate no socket connection to avoid 10.0.0.1 TCP timeouts during unit tests."""
    def fake_connect(*args, **kwargs):
        raise OSError("Unit test: no live network")
    monkeypatch.setattr("socket.create_connection", fake_connect)


def _run_result(stdout=""):
    return type("R", (), {"stdout": stdout, "returncode": 0})()


def _host(ports):
    return {
        "ip": "10.0.0.1",
        "ot_ports": [{"port": p, "protocol": proto} for p, proto in ports],
    }


def test_siemens_s7_extracts_vendor_model_firmware_evidence():
    host = _host([(102, "S7")])
    fake_output = (
        "Siemens S7 device\n"
        "Module: SIMATIC S7-1500\n"
        "Version: V2.9.3\n"
        "Module Type: CPU 1515-2 PN\n"
        "Basic Hardware: 6ES7 515-2AM01-0AB0\n"
        "Serial Number: S C-F0R1337\n"
        "System Name: Line1_PLC\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Siemens"
    assert result["model"] == "SIMATIC S7-1500"
    assert result["firmware"] == "V2.9.3"
    assert any("S7 Module Type: CPU 1515-2 PN" in e for e in result["evidence"])
    assert any("Basic Hardware: 6ES7 515-2AM01-0AB0" in e for e in result["evidence"])
    assert any("Serial Number: S C-F0R1337" in e for e in result["evidence"])
    assert any("System Name: Line1_PLC" in e for e in result["evidence"])
    assert "S7comm response confirmed (PLC/CPU)" in result["evidence"]
    assert result["fingerprint_method"] == "nse_script"


def test_siemens_hmi_via_http_title():
    host = _host([(80, "HTTP")])
    fake_output = "SIMATIC HMI\nhttp-title: Panel Login\n"

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Siemens"
    assert "SIMATIC HMI" in result["evidence"]
    assert any("Title: Panel Login" in e for e in result["evidence"])


def test_rockwell_enip_extracts_all_fields():
    host = _host([(44818, "EtherNet/IP")])
    fake_output = (
        "vendor: Rockwell Automation/Allen-Bradley\n"
        "productName: 1769-L33ER CompactLogix 5370\n"
        "revision: 33.011\n"
        "type: Programmable Logic Controller\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert result["model"] == "1769-L33ER CompactLogix 5370"
    assert result["firmware"] == "33.011"
    assert any("Programmable Logic Controller" in e for e in result["evidence"])


def test_br_sdm_confirmed_via_nse_probe():
    host = _host([(80, "HTTP")])

    fake_output = (
        "| br-info:\n"
        "|   Vendor: B&R Automation\n"
        "|   Component: System Diagnostics Manager (SDM) on port 80\n"
        "|_  Title (/sdm): System Diagnostics Manager\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "B&R Automation"
    assert any("System Diagnostics Manager" in e for e in result["evidence"])
    assert any("BR-Info Title: System Diagnostics Manager" in e for e in result["evidence"])


def test_br_port_signature_fallback_when_nse_probe_fails():
    """No NSE confirmation available (or nothing returned) but a B&R-specific
    port is open -> should still produce an 'unconfirmed' vendor hint via
    port-signature evidence rather than nothing at all."""

    host = _host([(11169, "B&R ANSL")])

    with patch("subprocess.run", return_value=_run_result("")):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "B&R Automation (unconfirmed - port signature only)"
    assert any("11169" in e for e in result["evidence"])
    assert result["fingerprint_method"] == "port_signature"


def test_no_ot_ports_produces_no_crash_and_no_vendor():
    host = _host([])

    result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] is None
    assert result["evidence"] == []
    assert result["fingerprint_method"] == "none"


def test_subprocess_exception_is_caught_and_does_not_crash():
    host = _host([(102, "S7")])

    with patch("subprocess.run", side_effect=Exception("nmap not found")):
        result = fingerprinter._fingerprint_host(host, verbose=True)

    # should not raise, and host still comes back with defaults
    assert result["vendor"] is None
    assert result["firmware"] is None


def test_timeouts_are_passed_through_to_subprocess():
    host = _host([(102, "S7")])

    with patch("subprocess.run", return_value=_run_result("")) as mock_run:
        fingerprinter._fingerprint_host(host, verbose=False, script_timeout=99)

    assert mock_run.call_args.kwargs["timeout"] == 99


def test_fingerprint_runs_hosts_concurrently():
    """With N workers and simulated per-host latency, wall time should be
    close to one unit of latency, not N units."""

    def slow_fake(host, verbose=False, script_timeout=30, **kw):
        time.sleep(0.3)
        host["evidence"] = []
        host["vendor"] = "Test"
        host["model"] = None
        host["firmware"] = None
        return host

    data = [{"ip": f"10.0.0.{i}", "ot_ports": []} for i in range(10)]

    with patch.object(fingerprinter, "_fingerprint_host", side_effect=slow_fake):
        start = time.time()
        result = fingerprinter.fingerprint(data, verbose=False, workers=10)
        elapsed = time.time() - start

    assert elapsed < 1.0  # would be ~3s if run serially
    assert all(h["vendor"] == "Test" for h in result)


def test_fingerprint_empty_data_returns_empty():
    assert fingerprinter.fingerprint([], verbose=False) == []


def test_fingerprint_continues_after_one_host_crashes():
    def maybe_crash(host, verbose=False, script_timeout=30, **kw):
        if host["ip"] == "10.0.0.2":
            raise RuntimeError("boom")
        host["evidence"] = []
        host["vendor"] = "ok"
        host["model"] = None
        host["firmware"] = None
        return host

    data = [{"ip": "10.0.0.1", "ot_ports": []}, {"ip": "10.0.0.2", "ot_ports": []}]

    with patch.object(fingerprinter, "_fingerprint_host", side_effect=maybe_crash):
        result = fingerprinter.fingerprint(data, verbose=False, workers=2)

    assert len(result) == 2  # both hosts still present despite one crashing


def test_filtered_ports_do_not_trigger_fingerprint_or_evidence():
    """Regression test: filtered ports (firewalled/dropped) must NOT trigger
    active scripts or port-signature evidence."""
    host = {
        "ip": "10.0.0.1",
        "ot_ports": [
            {"port": 102, "protocol": "S7", "state": "filtered"},
            {"port": 50000, "protocol": "B&R SafeDESIGNER", "state": "filtered"},
            {"port": 11159, "protocol": "B&R PVI", "state": "filtered"},
            {"port": 44818, "protocol": "EtherNet/IP", "state": "filtered"},
        ],
    }
    with patch("subprocess.run") as mock_run:
        result = fingerprinter._fingerprint_host(host, verbose=False)
        # Subprocess should not even be called for filtered S7/ENIP ports
        mock_run.assert_not_called()

    assert result["vendor"] is None
    assert result["evidence"] == []
    assert result["fingerprint_method"] == "none"


# --- evidence capture (host["probes"]) ---

import subprocess as _sp

REAL_S7_OUTPUT = (
    "Starting Nmap 7.94 ( https://nmap.org )\n"
    "PORT    STATE SERVICE\n"
    "102/tcp open  iso-tsap\n"
    "| s7-info:\n"
    "|   Module: 6ES7 315-2AG10-0AB0\n"
    "|   Version: 2.6.9\n"
    "|_  Copyright: Original Siemens Equipment\n"
)


def test_probe_record_captures_command_status_and_raw_output():
    host = _host([(102, "S7")])
    with patch("subprocess.run", return_value=_run_result(REAL_S7_OUTPUT)):
        fingerprinter._fingerprint_host(host)

    [probe] = host["probes"]
    assert probe["probe"] == "s7-info" and probe["status"] == "data"
    assert probe["ports"] == "102" and probe["returncode"] == 0
    assert "s7-info" in probe["command"] and "10.0.0.1" in probe["command"]
    assert "Original Siemens Equipment" in probe["output"]      # raw output kept as evidence
    assert probe["duration_s"] is not None


def test_probe_with_no_script_output_is_no_data_not_success():
    """nmap exits 0 and prints a header even when the device said nothing -
    that must not be reported as a successful probe."""
    host = _host([(102, "S7")])
    header_only = "Starting Nmap 7.94\nPORT STATE SERVICE\n102/tcp open iso-tsap\n"
    with patch("subprocess.run", return_value=_run_result(header_only)):
        fingerprinter._fingerprint_host(host)

    assert host["probes"][0]["status"] == "no_data"


def test_probe_timeout_is_recorded_not_lost():
    host = _host([(44818, "EtherNet/IP")])
    with patch("subprocess.run", side_effect=_sp.TimeoutExpired("nmap", 30)):
        fingerprinter._fingerprint_host(host, script_timeout=30)

    [probe] = host["probes"]
    assert probe["status"] == "timeout" and "30s" in probe["error"]
    assert host["vendor"] is None            # and nothing was invented


def test_probe_exception_is_recorded():
    host = _host([(102, "S7")])
    with patch("subprocess.run", side_effect=FileNotFoundError("nmap not installed")):
        fingerprinter._fingerprint_host(host)

    assert host["probes"][0]["status"] == "error"
    assert "nmap not installed" in host["probes"][0]["error"]


def test_nonzero_exit_is_an_error_with_stderr_captured():
    host = _host([(102, "S7")])
    bad = type("R", (), {"stdout": "", "stderr": "NSE: failed to initialize the script engine", "returncode": 1})()
    with patch("subprocess.run", return_value=bad):
        fingerprinter._fingerprint_host(host)

    probe = host["probes"][0]
    assert probe["status"] == "error" and "script engine" in probe["error"]


def test_oversized_output_is_truncated_in_evidence():
    host = _host([(102, "S7")])
    huge = "| s7-info:\n" + ("|   x\n" * 5000)
    with patch("subprocess.run", return_value=_run_result(huge)):
        fingerprinter._fingerprint_host(host)

    out = host["probes"][0]["output"]
    assert len(out) < fingerprinter.MAX_EVIDENCE_CHARS + 50 and out.endswith("[... truncated ...]")


def test_no_probes_recorded_when_nothing_applies():
    host = _host([(22, "SSH")])
    with patch("subprocess.run") as mock_run:
        fingerprinter._fingerprint_host(host)

    mock_run.assert_not_called()
    assert host["probes"] == []


def test_probes_do_not_accumulate_across_repeated_fingerprinting():
    host = _host([(102, "S7")])
    with patch("subprocess.run", return_value=_run_result(REAL_S7_OUTPUT)):
        fingerprinter._fingerprint_host(host)
        fingerprinter._fingerprint_host(host)

    assert len(host["probes"]) == 1


# --- probe command construction / safety flags ---

def test_every_probe_skips_redundant_host_discovery():
    for name in fingerprinter.PROBES:
        assert "-Pn" in fingerprinter.build_probe_cmd(name, "10.0.0.1")


def test_pacing_flags_are_applied_to_probes():
    cmd = fingerprinter.build_probe_cmd("enip-info", "10.0.0.1",
                                        pacing=["-T2", "--scan-delay", "200ms"])
    assert "-T2" in cmd and cmd[cmd.index("--scan-delay") + 1] == "200ms"
    assert cmd[cmd.index("-p") + 1] == "44818"


def test_version_intensity_only_added_to_service_detection_probes():
    s7 = fingerprinter.build_probe_cmd("s7-info", "10.0.0.1", version_intensity=0)
    assert "-sV" in s7 and s7[s7.index("--version-intensity") + 1] == "0"

    enip = fingerprinter.build_probe_cmd("enip-info", "10.0.0.1", version_intensity=0)
    assert "-sV" not in enip and "--version-intensity" not in enip


def test_default_version_intensity_leaves_nmap_default():
    assert "--version-intensity" not in fingerprinter.build_probe_cmd("s7-info", "10.0.0.1")


def test_pacing_reaches_the_real_nmap_invocation():
    host = _host([(102, "S7")])
    with patch("subprocess.run", return_value=_run_result(REAL_S7_OUTPUT)) as mock_run:
        fingerprinter._fingerprint_host(host, pacing=["-T2"], version_intensity=0)

    cmd = mock_run.call_args[0][0]
    assert "-T2" in cmd and "--version-intensity" in cmd


def test_probes_go_through_the_audited_runner():
    host = _host([(102, "S7")])
    with patch.object(fingerprinter.runner, "run", return_value=_run_result(REAL_S7_OUTPUT)) as mock_run:
        fingerprinter._fingerprint_host(host)

    assert mock_run.call_args.kwargs["purpose"] == "fingerprint:s7-info"


def test_fingerprint_native_s7_success():
    host = _host([(102, "S7")])
    fake_s7 = {
        "vendor": "Siemens",
        "model": "6ES7 511-1AK02-0AB0",
        "model_family": "S7-1500",
        "firmware": "V2.9.3",
        "mlfb": "6ES7 511-1AK02-0AB0",
        "component_name": "Line1_PLC",
        "keyswitch_mode": "REMOTE RUN (Logic download allowed across network)",
        "protection_level": "Level 1 (No Protection / Open)",
        "rack": 0,
        "slot": 1,
    }
    with patch("ot_recon.core.protocols.s7.query_s7_info", return_value=fake_s7):
        res = fingerprinter._fingerprint_host(host, deep_inspection=True)

    assert res["vendor"] == "Siemens"
    assert res["fingerprint_method"] == "native_s7comm"
    assert res["mlfb"] == "6ES7 511-1AK02-0AB0"
    assert res["keyswitch_mode"] == "REMOTE RUN (Logic download allowed across network)"
    assert res["protection_level"] == "Level 1 (No Protection / Open)"
    assert any("Siemens MLFB: 6ES7 511-1AK02-0AB0" in e for e in res["evidence"])
    assert any(p["probe"] == "native-s7-szl" for p in res["probes"])


def test_fingerprint_native_cip_with_backplane():
    host = _host([(44818, "EtherNet/IP")])
    fake_cip = {
        "vendor": "Rockwell Automation/Allen-Bradley",
        "model": "1756-EN2T",
        "firmware": "5.08",
        "device_type": "Communications Adapter",
        "serial_number": "AABBCCDD",
    }
    fake_chassis = [
        {"slot": 0, "model": "1756-L72", "device_type": "Programmable Logic Controller", "firmware": "32.11"},
        {"slot": 1, "model": "1756-EN2T", "device_type": "Communications Adapter", "firmware": "5.08"},
    ]
    with patch("ot_recon.core.protocols.cip.query_cip_identity", return_value=fake_cip):
        with patch("ot_recon.core.protocols.cip.scan_cip_backplane", return_value=fake_chassis):
            res = fingerprinter._fingerprint_host(host, deep_inspection=True)

    assert res["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert res["fingerprint_method"] == "native_cip"
    assert res["model"] == "1756-EN2T"
    assert len(res["chassis_modules"]) == 2
    assert res["controller_cpu"]["model"] == "1756-L72"
    assert any("Chassis Slot 0: 1756-L72" in e for e in res["evidence"])
    assert any(p["probe"] == "native-cip-identity" for p in res["probes"])


def test_fingerprint_native_modbus_mei():
    host = _host([(502, "Modbus")])
    fake_mb = {
        "vendor": "Schneider Electric",
        "product_code": "BMX P34 2020",
        "firmware": "02.30",
    }
    with patch("ot_recon.core.protocols.modbus.query_modbus_device_id", return_value=fake_mb):
        res = fingerprinter._fingerprint_host(host, deep_inspection=True)

    assert res["vendor"] == "Schneider Electric"
    assert res["fingerprint_method"] == "native_modbus"
    assert res["model"] == "BMX P34 2020"
    assert res["firmware"] == "02.30"
    assert any("Modbus Vendor: Schneider Electric" in e for e in res["evidence"])
    assert any(p["probe"] == "native-modbus-mei" for p in res["probes"])


def test_fingerprint_deep_inspection_disabled_by_default():
    host = _host([(102, "S7"), (44818, "EtherNet/IP")])
    with patch("ot_recon.core.protocols.s7.query_s7_info") as mock_s7, \
         patch("ot_recon.core.protocols.cip.query_cip_identity") as mock_cip:
        fingerprinter._fingerprint_host(host, deep_inspection=False)

    # Native deep queries must NOT be called when deep_inspection is False
    mock_s7.assert_not_called()
    mock_cip.assert_not_called()

