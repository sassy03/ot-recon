import subprocess
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ot_recon.core.paths import DATA_DIR
from ot_recon.core import runner
from ot_recon.core.protocols import cip, s7, modbus

# Fingerprinting is I/O/subprocess-bound (nmap scripts + HTTP probes), so a
# thread pool is the right concurrency tool here - no need for
# multiprocessing overhead. Cap the default so we don't spawn an
# unreasonable number of concurrent nmap processes on large subnets.
DEFAULT_WORKERS = 10

# Path to the custom B&R NSE script shipped with this project.
BR_NSE_SCRIPT = str(DATA_DIR / "nse" / "br-info.nse")

_print_lock = threading.Lock()

# Raw probe output kept as evidence is capped so snapshots/reports stay small.
MAX_EVIDENCE_CHARS = 4000


def _log(msg):
    with _print_lock:
        print(msg)


# Every active probe the tool can send, in one place. Shared by the real
# run and by --dry-run, so the plan shown to the operator is exactly what
# would execute. "version_detect" probes use nmap -sV (service detection).
PROBES = {
    "s7-info": {
        "ports": "102", "scripts": "s7-info", "version_detect": True,
        "applies": "an S7 service was found on port 102",
    },
    "http-title": {
        "ports": "80,443", "scripts": "http-title,ssl-cert", "version_detect": True,
        "applies": "an HTTP service was found",
    },
    "enip-info": {
        "ports": "44818", "scripts": "enip-info", "version_detect": False,
        "applies": "an EtherNet/IP service was found on port 44818",
    },
    "br-info": {
        "ports": "80,81,8084", "scripts": BR_NSE_SCRIPT, "version_detect": False,
        "applies": "an HTTP / B&R web service (80, 81, 8084) was found",
    },
}


def build_probe_cmd(name, ip, ports=None, pacing=None, version_intensity=None):
    """The exact nmap command for one probe.

    -Pn: discovery already proved the host is alive this run, so each probe
    skips nmap's own host-discovery step rather than sending redundant
    packets to a possibly fragile device before every probe."""

    spec = PROBES[name]
    cmd = ["nmap", "-n", "-Pn", ip] + list(pacing or []) + ["-p", ports or spec["ports"]]

    if spec["version_detect"]:
        cmd.append("-sV")
        if version_intensity is not None:
            cmd += ["--version-intensity", str(version_intensity)]

    cmd += ["--script", spec["scripts"]]
    return cmd


def _script_produced_data(output):
    # nmap prints NSE script results as lines starting with "|" / "|_".
    return any(line.startswith("|") for line in (output or "").splitlines())


def _run_probe(host, name, cmd, timeout, verbose, ports=""):
    """Run one probe through the audited runner and record exactly what
    happened on host["probes"] (the evidence trail the report shows).

    Returns the probe's stdout, or "" if it failed - callers then simply
    find nothing to parse, exactly as before. Never raises."""

    record = {
        "probe": name,
        "ports": ports,
        "command": " ".join(str(c) for c in cmd),
        "status": "error",
        "returncode": None,
        "duration_s": None,
        "output": "",
        "error": None,
    }
    started = time.time()
    output = ""

    try:
        result = runner.run(cmd, purpose=f"fingerprint:{name}",
                            capture_output=True, text=True, timeout=timeout)
        output = result.stdout or ""
        rc = result.returncode if isinstance(result.returncode, int) else 0
        record["returncode"] = rc

        if rc != 0:
            record["status"] = "error"
            record["error"] = (getattr(result, "stderr", "") or f"nmap exited with status {rc}").strip()[:300]
        elif _script_produced_data(output):
            record["status"] = "data"
        else:
            record["status"] = "no_data"

    except subprocess.TimeoutExpired:
        record["status"] = "timeout"
        record["error"] = f"no result within {timeout}s"
        if verbose:
            _log(f"[-] {host['ip']}: {name} probe timed out after {timeout}s")
    except Exception as e:
        record["status"] = "error"
        record["error"] = str(e)[:300]
        if verbose:
            _log(f"[-] {host['ip']}: {name} probe failed ({e})")

    record["duration_s"] = round(time.time() - started, 2)
    record["output"] = output[:MAX_EVIDENCE_CHARS]
    if len(output) > MAX_EVIDENCE_CHARS:
        record["output"] += "\n[... truncated ...]"

    host.setdefault("probes", []).append(record)
    return output


def _fingerprint_host(host, verbose=False, script_timeout=30, pacing=None,
                      version_intensity=None):

    host["evidence"] = []
    host["probes"] = []
    host["vendor"] = None
    host["model"] = None
    host["firmware"] = None
    host["fingerprint_method"] = "none"
    host["mlfb"] = None
    host["component_name"] = None
    host["keyswitch_mode"] = None
    host["protection_level"] = None
    host["chassis_modules"] = []
    host["controller_cpu"] = None

    ip = host["ip"]

    protocols = [
        p["protocol"]
        for p in host.get("ot_ports", [])
        if p.get("state", "open") == "open"
    ]

    #
    # Siemens Controller
    #
    if "S7" in protocols:
        s7_handled = False
        try:
            # 1. Primary: Native read-only S7comm SZL inspection (0x0011, 0x001C, 0x0132)
            s7_data = s7.query_s7_info(ip, timeout=min(script_timeout, 1.5))
            if s7_data and (s7_data.get("mlfb") or s7_data.get("model") or s7_data.get("vendor")):
                host["vendor"] = s7_data.get("vendor", "Siemens")
                host["fingerprint_method"] = "native_s7comm"
                if s7_data.get("model"):
                    host["model"] = s7_data["model"]
                elif s7_data.get("model_family"):
                    host["model"] = s7_data["model_family"]
                if s7_data.get("firmware"):
                    host["firmware"] = s7_data["firmware"]
                if s7_data.get("mlfb"):
                    host["mlfb"] = s7_data["mlfb"]
                    host["evidence"].append(f"Siemens MLFB: {s7_data['mlfb']}")
                if s7_data.get("component_name"):
                    host["component_name"] = s7_data["component_name"]
                    host["evidence"].append(f"Component Name: {s7_data['component_name']}")
                if s7_data.get("keyswitch_mode"):
                    host["keyswitch_mode"] = s7_data["keyswitch_mode"]
                    host["evidence"].append(f"Keyswitch: {s7_data['keyswitch_mode']}")
                if s7_data.get("protection_level"):
                    host["protection_level"] = s7_data["protection_level"]
                    host["evidence"].append(f"Protection: {s7_data['protection_level']}")

                host["evidence"].append("S7comm response confirmed (PLC/CPU)")
                host.setdefault("probes", []).append({
                    "probe": "native-s7-szl",
                    "ports": "102",
                    "command": f"native s7comm SZL inspection {ip}:102 (rack {s7_data.get('rack', 0)}, slot {s7_data.get('slot', 1)})",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.05,
                    "output": f"MLFB: {s7_data.get('mlfb')}, FW: {s7_data.get('firmware')}, Keyswitch: {s7_data.get('keyswitch_mode')}, Protection: {s7_data.get('protection_level')}",
                    "error": None,
                })
                s7_handled = True
        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: S7 native inspection failed ({e}), falling back to NSE probe")

        # 2. Fallback: Nmap s7-info NSE script
        if not s7_handled:
            try:
                output = _run_probe(
                    host, "s7-info",
                    build_probe_cmd("s7-info", ip, pacing=pacing, version_intensity=version_intensity),
                    script_timeout, verbose, ports="102",
                )

                if "Siemens" in output or "SIMATIC" in output or "6ES7" in output:
                    host["vendor"] = "Siemens"
                    host["fingerprint_method"] = "nse_script"

                module = re.search(r"Module:\s*(.+)", output, re.IGNORECASE)
                if module:
                    host["model"] = module.group(1).strip()

                version = re.search(r"Version:\s*(.+)", output, re.IGNORECASE)
                if version:
                    host["firmware"] = version.group(1).strip()

                # Any s7-info response with identifiable content = PLC
                # confirmation. S7comm is PLC-only traffic by definition.
                module_type = re.search(r"Module Type:\s*(.+)", output, re.IGNORECASE)
                if module_type:
                    mtype_str = module_type.group(1).strip()
                    host["evidence"].append(
                        f"S7 Module Type: {mtype_str}"
                    )
                    if not host.get("model"):
                        host["model"] = mtype_str

                # Capture additional fields the real script provides.
                basic_hw = re.search(r"Basic Hardware:\s*(.+)", output, re.IGNORECASE)
                if basic_hw:
                    host["evidence"].append(
                        f"Basic Hardware: {basic_hw.group(1).strip()}"
                    )

                serial = re.search(r"Serial Number:\s*(.+)", output)
                if serial:
                    host["evidence"].append(
                        f"Serial Number: {serial.group(1).strip()}"
                    )

                system_name = re.search(
                    r"System Name:\s*(.+)",
                    output
                )

                if system_name:
                    host["evidence"].append(
                        f"System Name: {system_name.group(1).strip()}"
                    )

                # If we got any meaningful s7-info fields back, this is
                # definitively a PLC (S7comm is PLC-only by protocol spec).
                if module_type or module or host["vendor"] == "Siemens":
                    host["evidence"].append(
                        "S7comm response confirmed (PLC/CPU)"
                    )

            except Exception as e:
                if verbose:
                    _log(f"[-] {ip}: S7 fingerprint failed ({e})")

    #
    # Siemens Panel
    #
    if "HTTP" in protocols:

        try:

            output = _run_probe(
                host, "http-title",
                build_probe_cmd("http-title", ip, pacing=pacing, version_intensity=version_intensity),
                script_timeout, verbose, ports="80,443",
            )

            if "SIMATIC HMI" in output:

                host["vendor"] = "Siemens"
                host["fingerprint_method"] = "nse_script"

                host["evidence"].append(
                    "SIMATIC HMI"
                )

            title = re.search(
                r"http-title:\s*(.+)",
                output
            )

            if title:
                host["evidence"].append(
                    f"Title: {title.group(1).strip()}"
                )

        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: HTTP fingerprint failed ({e})")

    #
    # Rockwell EtherNet/IP
    #
    if "EtherNet/IP" in protocols:
        cip_handled = False
        try:
            # 1. Primary: Native read-only CIP ListIdentity + Backplane Chassis Scan
            cip_data = cip.query_cip_identity(ip, timeout=min(script_timeout, 1.5))
            if cip_data and (cip_data.get("vendor") or cip_data.get("model")):
                host["vendor"] = cip_data.get("vendor")
                host["fingerprint_method"] = "native_cip"
                if cip_data.get("model"):
                    host["model"] = cip_data["model"]
                if cip_data.get("firmware"):
                    host["firmware"] = cip_data["firmware"]
                if cip_data.get("serial_number"):
                    host["serial_number"] = cip_data["serial_number"]
                    host["evidence"].append(f"Serial Number: {cip_data['serial_number']}")
                if cip_data.get("device_type"):
                    host["evidence"].append(f"Device Type: {cip_data['device_type']}")

                # Backplane chassis scan
                chassis = cip.scan_cip_backplane(ip, timeout=min(script_timeout, 1.5))
                if chassis:
                    host["chassis_modules"] = chassis
                    for m in chassis:
                        host["evidence"].append(
                            f"Chassis Slot {m['slot']}: {m['model']} ({m['device_type']}) FW {m.get('firmware', 'N/A')}"
                        )
                        if "Programmable Logic Controller" in m.get("device_type", "") and not host.get("controller_cpu"):
                            host["controller_cpu"] = m

                host.setdefault("probes", []).append({
                    "probe": "native-cip-identity",
                    "ports": "44818",
                    "command": f"native EtherNet/IP ListIdentity + Backplane Scan {ip}:44818",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.05,
                    "output": f"Vendor: {host.get('vendor')}, Model: {host.get('model')}, FW: {host.get('firmware')}, Chassis Modules: {len(chassis) if chassis else 0}",
                    "error": None,
                })
                cip_handled = True
        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: CIP native inspection failed ({e}), falling back to NSE probe")

        # 2. Fallback: Nmap enip-info NSE script
        if not cip_handled:
            try:
                output = _run_probe(
                    host, "enip-info",
                    build_probe_cmd("enip-info", ip, pacing=pacing),
                    script_timeout, verbose, ports="44818",
                )

                vendor = re.search(
                    r"vendor:\s*(.+)",
                    output,
                    re.IGNORECASE,
                )

                if vendor:
                    host["vendor"] = vendor.group(1).strip()
                    host["fingerprint_method"] = "nse_script"

                product = re.search(
                    r"(?:productName|product\s*name):\s*(.+)",
                    output,
                    re.IGNORECASE,
                )

                if product:
                    host["model"] = product.group(1).strip()

                revision = re.search(
                    r"revision:\s*(.+)",
                    output,
                    re.IGNORECASE,
                )

                if revision:
                    host["firmware"] = revision.group(1).strip()

                device_type = re.search(
                    r"(?:device\s*type|type):\s*(.+)",
                    output,
                    re.IGNORECASE,
                )

                if device_type:

                    host["evidence"].append(
                        f"Device Type: {device_type.group(1).strip()}"
                    )

            except Exception as e:
                if verbose:
                    _log(f"[-] {ip}: EtherNet/IP fingerprint failed ({e})")

    #
    # Modbus TCP (Native Read Device Identification FC 43 / MEI 14)
    #
    if "Modbus" in protocols:
        try:
            mb_data = modbus.query_modbus_device_id(ip, timeout=min(script_timeout, 1.5))
            if mb_data and (mb_data.get("vendor") or mb_data.get("product_code") or mb_data.get("model")):
                if not host.get("vendor") and mb_data.get("vendor"):
                    host["vendor"] = mb_data["vendor"]
                if not host.get("model") and (mb_data.get("product_code") or mb_data.get("model")):
                    host["model"] = mb_data.get("product_code") or mb_data.get("model")
                if not host.get("firmware") and mb_data.get("firmware"):
                    host["firmware"] = mb_data["firmware"]
                if host.get("fingerprint_method") in ("none", "port_signature"):
                    host["fingerprint_method"] = "native_modbus"

                if mb_data.get("vendor"):
                    host["evidence"].append(f"Modbus Vendor: {mb_data['vendor']}")
                if mb_data.get("product_code"):
                    host["evidence"].append(f"Modbus Product: {mb_data['product_code']}")
                if mb_data.get("firmware"):
                    host["evidence"].append(f"Modbus Revision: {mb_data['firmware']}")

                host.setdefault("probes", []).append({
                    "probe": "native-modbus-mei",
                    "ports": "502",
                    "command": f"native Modbus FC43/14 Read Device Identification {ip}:502",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.05,
                    "output": f"Vendor: {mb_data.get('vendor')}, Product: {mb_data.get('product_code')}, Rev: {mb_data.get('firmware')}",
                    "error": None,
                })
        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: Modbus native inspection failed ({e})")

    #
    # B&R Automation
    #
    # Migrated from ad-hoc Python requests-based HTTP probing to a proper
    # custom Nmap NSE script (data/nse/br-info.nse), for architectural
    # consistency with Siemens (s7-info) and Rockwell (enip-info).
    #
    # The NSE script probes SDM/mapp View/mapp Cockpit web endpoints.
    # Raw PVI/ANSL/SafeDESIGNER ports are still handled via port-signature
    # evidence only (no public protocol spec exists).
    #
    br_ports = {p["port"] for p in host.get("ot_ports", []) if p.get("state", "open") == "open"}
    br_signature_ports = {11159, 11160, 11169, 50000, 51000, 8084, 81}
    br_http_ports = br_ports & {80, 81, 8084}

    if br_ports & br_signature_ports or "HTTP" in protocols:

        br_confirmed = False

        # --- NSE-based confirmation (replaces old requests-based probe) ---
        if br_http_ports or "HTTP" in protocols:

            scan_ports = ",".join(str(p) for p in sorted(
                br_http_ports | ({80} if "HTTP" in protocols else set())
            ))

            try:
                output = _run_probe(
                    host, "br-info",
                    build_probe_cmd("br-info", ip, ports=scan_ports, pacing=pacing),
                    script_timeout, verbose, ports=scan_ports,
                )

                # Parse br-info NSE output:
                #   Vendor: B&R Automation
                #   Component: System Diagnostics Manager (SDM) on port 80
                #   Title (/sdm): System Diagnostics Manager
                if "Vendor: B&R" in output:
                    host["vendor"] = "B&R Automation"
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True

                component = re.search(
                    r"Component:\s*(.+)", output, re.IGNORECASE
                )
                if component:
                    cname = component.group(1).strip()
                    host["evidence"].append(cname)
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True
                    if not host.get("model"):
                        host["model"] = cname

                title = re.search(
                    r"Title\s*\([^)]*\):\s*(.+)", output
                )
                if title:
                    host["evidence"].append(
                        f"BR-Info Title: {title.group(1).strip()}"
                    )

            except Exception as e:
                if verbose:
                    _log(f"[-] {ip}: B&R NSE probe failed ({e})")

        # --- Port-signature fallback evidence ---
        port_signatures = {
            11169: "B&R Automation Studio/ANSL port open (11169)",
            11159: "B&R PVI legacy port open (11159)",
            11160: "B&R PVI fast-transfer port open (11160)",
            50000: "B&R SafeDESIGNER port open (50000)",
            51000: "B&R SafeDESIGNER secondary port open (51000)",
            8084: "B&R mapp Cockpit port open (8084)",
        }

        for port_num, desc in port_signatures.items():
            if port_num in br_ports:
                host["evidence"].append(desc)
                if not br_confirmed and host.get("vendor") is None:
                    host["vendor"] = "B&R Automation (unconfirmed - port signature only)"
                    host["fingerprint_method"] = "port_signature"

    return host


def fingerprint(data, verbose=False, workers=DEFAULT_WORKERS, script_timeout=30,
                pacing=None, version_intensity=None):

    if not data:
        return data

    total = len(data)
    print(f"[+] Fingerprinting {total} asset(s) with {min(workers, total)} worker(s)...")

    done = 0

    # Submit all hosts to the pool and update each host dict in place as
    # results land - order of completion doesn't matter since each host is
    # independent and `data` holds references, not copies.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:

        future_to_host = {
            executor.submit(_fingerprint_host, host, verbose, script_timeout,
                            pacing=pacing, version_intensity=version_intensity): host
            for host in data
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]

            try:
                future.result()
            except Exception as e:
                if verbose:
                    _log(f"[-] {host.get('ip', '?')}: fingerprinting crashed ({e})")

            done += 1
            _log(f"[+] Fingerprinted {done}/{total} ({host.get('ip', '?')})")

    return data
