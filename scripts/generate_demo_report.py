"""
scripts/generate_demo_report.py
Generates a comprehensive demonstration HTML report showcasing all OT-Recon
capabilities: Purdue ISA-95 model, IEC 62443 compliance matrix, visual chassis
rack layout, native protocol deep inspection (CIP, S7comm, Modbus MEI), and
operational risk alerts.
"""

from datetime import datetime, timezone
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ot_recon.core.report_html import export_html
from ot_recon.core.risk import assess_risk

def build_demo_data():
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    scan_ctx = {
        "tool_version": "1.3.0",
        "nmap_version": "7.94",
        "operator": "OT Cybersecurity Specialist",
        "target": "10.10.40.0/24 (Plant Area 4: High-Pressure Packaging & Filling Line)",
        "started": "2026-10-20T08:15:00Z",
        "finished": "2026-10-20T08:21:45Z",
        "profile": {
            "name": "safe",
            "description": "Safe Industrial Scan Profile (gentle pacing, non-disruptive)",
            "settings": {
                "tcp_timing": "T2",
                "udp_timing": "T2",
                "scan_delay": "200ms",
                "max_retries": 1,
                "version_intensity": 0,
                "workers": 2,
                "nmap_script_timeout": 60,
            },
        },
        "tcp_ports": "80,102,443,502,4840,44818,2222,21,22,23,5900",
        "udp_ports": "161,47808",
        "udp_scanned": True,
        "cve_live": True,
        "deep_inspection": True,
        "exclude_self": True,
        "excluded": ["10.10.40.100 (Historian Active Mirror)"],
        "hosts_discovered": 5,
        "commands_run": 24,
        "audit_log": "output/audit/audit_20261020_081500.jsonl",
        "scope": {
            "address_count": 254,
            "allowed": ["10.10.40.0/24"],
            "overridden": [],
        },
        "coverage": {
            "gaps": [
                "Safety PLC 10.10.40.10 was inspected using non-intrusive CIP ListIdentity and Module discovery only; intrusive diagnostics omitted per policy.",
            ],
            "notes": [
                "Deep protocol inspection enabled (--deep): native CIP backplane walking, S7comm SZL diagnostics, and Modbus MEI readout executed safely.",
                "Zero exploit payloads delivered; all communications strictly conformed to vendor protocol specifications.",
            ],
            "host_status_counts": {"full": 4, "partial": 1, "limited": 0, "n/a": 0},
        },
    }

    hosts = [
        # 1. Rockwell GuardLogix Safety PLC (L1 Safety / SIS)
        {
            "ip": "10.10.40.10",
            "type": "Safety PLC",
            "vendor": "Rockwell Automation",
            "model": "1756-L83ES GuardLogix 5580 Safety Controller",
            "firmware": "33.011",
            "confidence": "Very High",
            "confidence_score": 98,
            "detection_method": "active_probe",
            "evidence_based": True,
            "evidence": [
                "EtherNet/IP (CIP) ListIdentity response confirmed Rockwell Automation 1756-L83ES",
                "CIP Backplane Slot walk enumerated 5 rack modules",
            ],
            "ot_ports": [
                {"port": 44818, "state": "open", "protocol": "EtherNet/IP", "transport": "tcp"},
                {"port": 2222, "state": "open", "protocol": "EtherNet/IP", "transport": "udp"},
                {"port": 80, "state": "open", "protocol": "HTTP", "transport": "tcp"},
            ],
            "services": [
                {"port": 44818, "state": "open", "protocol": "EtherNet/IP", "category": "ot", "transport": "tcp", "authentication": "none"},
                {"port": 2222, "state": "open", "protocol": "EtherNet/IP", "category": "ot", "transport": "udp", "authentication": "none"},
                {"port": 80, "state": "open", "protocol": "HTTP", "category": "it", "transport": "tcp", "authentication": "none"},
            ],
            "keyswitch_mode": "REMOTE RUN",
            "chassis_modules": [
                {"slot": 0, "model": "1756-L83ES", "device_type": "Programmable Logic Controller", "firmware": "33.011"},
                {"slot": 1, "model": "1756-L8SP", "device_type": "Safety Partner", "firmware": "33.011"},
                {"slot": 2, "model": "1756-EN2TR", "device_type": "Communications Adapter", "firmware": "5.008"},
                {"slot": 3, "model": "1756-IB16S", "device_type": "Digital Safety Input Module", "firmware": "2.003"},
                {"slot": 4, "model": "1756-OBV8S", "device_type": "Digital Safety Output Module", "firmware": "2.001"},
            ],
            "summary": "Allen-Bradley GuardLogix 5580 Safety Controller governing high-pressure safety interlocks on Packaging Line 4. Backplane slot inventory completed with 5 modules detected.",
            "probes": [
                {
                    "probe": "enip-info / native-cip",
                    "ports": "44818",
                    "command": "native cip identity & backplane walk (10.10.40.10:44818)",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.42,
                    "output": (
                        "Vendor: Rockwell Automation/Allen-Bradley (1)\n"
                        "Product Name: 1756-L83ES/B GuardLogix 5580 Safety Controller\n"
                        "Serial Number: 0x4A81E290\n"
                        "Revision: 33.11\n"
                        "Slot 0: 1756-L83ES [Safety Controller] Rev 33.011\n"
                        "Slot 1: 1756-L8SP  [Safety Partner] Rev 33.011\n"
                        "Slot 2: 1756-EN2TR [Dual-Port EtherNet/IP] Rev 5.008\n"
                        "Slot 3: 1756-IB16S [Safety Input 16-pt] Rev 2.003\n"
                        "Slot 4: 1756-OBV8S [Safety Output 8-pt] Rev 2.001"
                    ),
                    "error": None,
                }
            ],
            "coverage": {
                "status": "full",
                "gaps": [],
                "checks": [
                    {"check": "CIP Identity probe (port 44818)", "status": "completed", "detail": "Identity block retrieved"},
                    {"check": "CIP Chassis Slot Enumeration", "status": "completed", "detail": "5 modules read"},
                ],
            },
        },

        # 2. Siemens SIMATIC S7-300 PLC (L1 Basic Control)
        {
            "ip": "10.10.40.20",
            "type": "PLC",
            "vendor": "Siemens",
            "model": "SIMATIC S7-300 (CPU 315-2 PN/DP)",
            "firmware": "3.3.12",
            "confidence": "Very High",
            "confidence_score": 96,
            "detection_method": "active_probe",
            "evidence_based": True,
            "evidence": [
                "ISO-on-TCP (port 102) S7comm SZL response verified",
                "MLFB 6ES7 315-2EH14-0AB0 retrieved from Module Identification SZL 0x0011",
            ],
            "ot_ports": [
                {"port": 102, "state": "open", "protocol": "S7", "transport": "tcp"},
                {"port": 80, "state": "open", "protocol": "HTTP", "transport": "tcp"},
            ],
            "services": [
                {"port": 102, "state": "open", "protocol": "S7", "category": "ot", "transport": "tcp", "authentication": "none"},
                {"port": 80, "state": "open", "protocol": "HTTP", "category": "it", "transport": "tcp", "authentication": "none"},
            ],
            "mlfb": "6ES7 315-2EH14-0AB0",
            "component_name": "LINE4_FILLING_PAC",
            "keyswitch_mode": "REMOTE RUN",
            "protection_level": 1,
            "summary": "Siemens S7-300 PLC controlling filling valves and dosing actuators. Native SZL query extracted MLFB part number, firmware v3.3.12, and PLC component name.",
            "probes": [
                {
                    "probe": "s7-info / native-szl",
                    "ports": "102",
                    "command": "native s7comm SZL read (10.10.40.20:102)",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.28,
                    "output": (
                        "System Name: LINE4_FILLING_PAC\n"
                        "Module Type: CPU 315-2 PN/DP\n"
                        "Order Number (MLFB): 6ES7 315-2EH14-0AB0\n"
                        "Firmware Revision: V 3.3.12\n"
                        "Keyswitch Position: REMOTE RUN\n"
                        "Protection Level: 1 (Open / No Password Required)"
                    ),
                    "error": None,
                }
            ],
            "coverage": {
                "status": "full",
                "gaps": [],
                "checks": [
                    {"check": "S7comm COTP Connection", "status": "completed", "detail": "COTP connection confirmed"},
                    {"check": "SZL 0x0011 Module Identification", "status": "completed", "detail": "MLFB and firmware extracted"},
                    {"check": "SZL 0x0132 CPU Protection & State", "status": "completed", "detail": "Protection level 1, REMOTE RUN"},
                ],
            },
        },

        # 3. Schneider Electric Modicon M340 PLC (L1 Basic Control)
        {
            "ip": "10.10.40.30",
            "type": "PLC",
            "vendor": "Schneider Electric",
            "model": "Modicon M340 (BMX P34 2020)",
            "firmware": "02.80",
            "confidence": "Very High",
            "confidence_score": 94,
            "detection_method": "active_probe",
            "evidence_based": True,
            "evidence": [
                "Modbus TCP function 43/14 (Read Device Identification) response received",
                "Vendor: Schneider Electric, ProductCode: BMX P34 2020",
            ],
            "ot_ports": [
                {"port": 502, "state": "open", "protocol": "Modbus", "transport": "tcp"},
                {"port": 80, "state": "open", "protocol": "HTTP", "transport": "tcp"},
                {"port": 21, "state": "open", "protocol": "FTP", "transport": "tcp"},
            ],
            "services": [
                {"port": 502, "state": "open", "protocol": "Modbus", "category": "ot", "transport": "tcp", "authentication": "none"},
                {"port": 80, "state": "open", "protocol": "HTTP", "category": "it", "transport": "tcp", "authentication": "none"},
                {"port": 21, "state": "open", "protocol": "FTP", "category": "it", "transport": "tcp", "authentication": "none"},
            ],
            "component_name": "BMX P34 2020 CPU 20",
            "summary": "Schneider Electric Modicon M340 PLC managing pneumatic conveyor distribution. Native Modbus MEI readout verified CPU hardware model and firmware version.",
            "probes": [
                {
                    "probe": "modbus-discover / native-mei",
                    "ports": "502",
                    "command": "native modbus mei read (10.10.40.30:502)",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.15,
                    "output": (
                        "VendorName: Schneider Electric\n"
                        "ProductCode: BMX P34 2020\n"
                        "MajorMinorRevision: 02.80\n"
                        "UserApplicationName: CONVEYOR_DISPATCH"
                    ),
                    "error": None,
                }
            ],
            "coverage": {
                "status": "full",
                "gaps": [],
                "checks": [
                    {"check": "Modbus TCP MEI 43/14 Discovery", "status": "completed", "detail": "Vendor identity confirmed"},
                ],
            },
        },

        # 4. Siemens SIMATIC Comfort Panel HMI (L2 Supervisory / HMI)
        {
            "ip": "10.10.40.50",
            "type": "HMI",
            "vendor": "Siemens",
            "model": "SIMATIC HMI TP1200 Comfort",
            "firmware": "16.0.0.0",
            "confidence": "High",
            "confidence_score": 90,
            "detection_method": "active_probe",
            "evidence_based": True,
            "evidence": [
                "HTTP Title: 'SIMATIC WinCC flexible Runtime / Start Center'",
                "Port 5900 VNC (SmartServer) service banner identified",
            ],
            "ot_ports": [
                {"port": 102, "state": "open", "protocol": "S7", "transport": "tcp"},
                {"port": 80, "state": "open", "protocol": "HTTP", "transport": "tcp"},
                {"port": 443, "state": "open", "protocol": "HTTPS", "transport": "tcp"},
                {"port": 5900, "state": "open", "protocol": "VNC", "transport": "tcp"},
            ],
            "services": [
                {"port": 102, "state": "open", "protocol": "S7", "category": "ot", "transport": "tcp", "authentication": "none"},
                {"port": 80, "state": "open", "protocol": "HTTP", "category": "it", "transport": "tcp", "authentication": "none"},
                {"port": 443, "state": "open", "protocol": "HTTPS", "category": "it", "transport": "tcp", "authentication": "tls"},
                {"port": 5900, "state": "open", "protocol": "VNC", "category": "it", "transport": "tcp", "authentication": "vnc_auth"},
            ],
            "summary": "12-inch operator touchscreen HMI located at operator station 4. Enables line operators to observe tank levels, set dosing setpoints, and acknowledge alarms.",
            "probes": [
                {
                    "probe": "http-title / vnc-info",
                    "ports": "80, 5900",
                    "command": "nmap banner/http title (10.10.40.50)",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 0.85,
                    "output": "HTTP Title: SIMATIC Comfort Panel Webserver\nVNC Banner: RFB 003.008 (SmartServer)",
                    "error": None,
                }
            ],
            "coverage": {
                "status": "full",
                "gaps": [],
                "checks": [
                    {"check": "HMI Webserver Title Inspection", "status": "completed", "detail": "Matched Comfort Panel"},
                    {"check": "SmartServer VNC probe", "status": "completed", "detail": "Remote desktop port active"},
                ],
            },
        },

        # 5. Plant Supervisory SCADA / Historian Server (L3 Operations)
        {
            "ip": "10.10.40.100",
            "type": "SCADA Server",
            "vendor": "Inductive Automation / Microsoft",
            "model": "Ignition Gateway 8.1 on Windows Server 2022",
            "firmware": "8.1.28",
            "confidence": "High",
            "confidence_score": 88,
            "detection_method": "banner",
            "evidence_based": True,
            "evidence": [
                "OPC UA TCP endpoint discovered on port 4840",
                "HTTP banner: 'Ignition Gateway Web Portal'",
            ],
            "ot_ports": [
                {"port": 4840, "state": "open", "protocol": "OPC UA", "transport": "tcp"},
                {"port": 80, "state": "open", "protocol": "HTTP", "transport": "tcp"},
                {"port": 443, "state": "open", "protocol": "HTTPS", "transport": "tcp"},
                {"port": 3389, "state": "open", "protocol": "RDP", "transport": "tcp"},
            ],
            "services": [
                {"port": 4840, "state": "open", "protocol": "OPC UA", "category": "ot", "transport": "tcp", "authentication": "opc_token"},
                {"port": 80, "state": "open", "protocol": "HTTP", "category": "it", "transport": "tcp", "authentication": "none"},
                {"port": 443, "state": "open", "protocol": "HTTPS", "category": "it", "transport": "tcp", "authentication": "tls"},
                {"port": 3389, "state": "open", "protocol": "RDP", "category": "it", "transport": "tcp", "authentication": "credssp"},
            ],
            "summary": "Plant-wide SCADA gateway centralizing process data acquisition, historical logging, and batch recipes for packaging lines 1 through 6.",
            "probes": [
                {
                    "probe": "opcua-browse",
                    "ports": "4840",
                    "command": "nmap opcua-browse (10.10.40.100)",
                    "status": "data",
                    "returncode": 0,
                    "duration_s": 1.12,
                    "output": "OPC UA Server: Ignition OPC-UA Server\nEndpoint: opc.tcp://10.10.40.100:4840\nSecurity Policy: None, Basic256Sha256",
                    "error": None,
                }
            ],
            "coverage": {
                "status": "partial",
                "gaps": ["Active SQL Historian mirror excluded from active TCP port discovery to prevent database connection pool exhaustion."],
                "checks": [
                    {"check": "OPC UA Endpoint Discovery", "status": "completed", "detail": "OPC UA server response OK"},
                ],
            },
        },
    ]

    # Run the core risk engine to calculate quantitative risk scores,
    # severity ranks, CVE correlations, and actionable engineering recommendations.
    hosts = assess_risk(hosts)

    return hosts, scan_ctx

def main():
    output_dir = os.path.abspath("output")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "demonstration_ot_recon_report.html")

    print("[*] Generating industrial reconnaissance dataset with full capabilities...")
    hosts, scan_ctx = build_demo_data()

    print(f"[*] Assessed {len(hosts)} industrial assets across Purdue Levels 1, 2, and 3.")
    for h in hosts:
        print(f"    - {h['ip']} ({h.get('type')}) -> Risk Score: {h.get('risk_score')}/100, Sev: {h.get('risk_severity')}")

    print(f"[*] Rendering HTML report to: {report_path}")
    export_html(hosts, report_path, scan_ctx=scan_ctx)
    print(f"[+] Demonstration report successfully written: {report_path}")
    print(f"[+] File size: {os.path.getsize(report_path):,} bytes")

if __name__ == "__main__":
    main()
