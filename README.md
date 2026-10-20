# OT-Recon: Industrial Cybersecurity Reconnaissance & Vulnerability Assessment

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![Standard](https://img.shields.io/badge/standard-IEC%2062443-green.svg)](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series)
[![Architecture](https://img.shields.io/badge/architecture-Purdue%20ISA--95-orange.svg)]()

**OT-Recon** is a deterministic, safety-first Operational Technology (OT), Industrial Control Systems (ICS), and SCADA reconnaissance and vulnerability assessment platform. It provides deep protocol inspection for **Siemens S7**, **Rockwell Automation / Allen-Bradley EtherNet/IP**, and **Schneider Electric Modbus TCP** without the catastrophic hazards of offensive exploit suites or aggressive IT port scanners.

For detailed operational specifications, protocol packet flows, and architectural deep-dives, see the [Full Technical Documentation & Operations Manual](docs/DOCUMENTATION.md).

---

## Key Capabilities

* **Native Read-Only Deep Protocol Inspection (`--deep`)**:
  * **Siemens S7comm (Port 102)**: Direct ISO-on-TCP COTP handshake, SZL `0x0011` module identification (MLFB part numbers, firmware versions), SZL `0x001C` component name, and SZL `0x0132` CPU keyswitch state (`RUN` vs `REMOTE RUN`) and protection levels (Level 1 Open vs Level 2/3 Password).
  * **Rockwell EtherNet/IP & CIP (Port 44818 / 2222)**: CIP `ListIdentity` discovery and full **Chassis Backplane Walking** (Slot 0-16 enumeration of Controllers, Safety Partners, Communication Bridges, and I/O modules).
  * **Modbus TCP (Port 502)**: Modbus Encapsulated Interface (MEI) Function Code 43 / Sub-function 14 reading VendorName, ProductCode, MajorMinorRevision, and UserApplicationName.
* **Purdue Model (ISA-95) Hierarchy Mapping**:
  * Automatically classifies discovered industrial nodes into **L1 Safety (SIS)**, **L1 Basic Process Control**, **L2 Supervisory / HMI**, **L3 Operations / SCADA**, or **Unclassified / IT Hosts**.
* **IEC 62443 Security Compliance Matrix**:
  * Evaluates discovered exposures against **IEC 62443-3-3** and **IEC 62443-4-2** Foundational Requirements:
    * **FR 1 (IAC)**: Unauthenticated industrial protocols.
    * **FR 2 (UC)**: Keyswitch in `REMOTE RUN` or controller `Protection Level 1`.
    * **FR 3 (SI)**: Correlated Critical/High firmware CVEs.
    * **FR 4 (DC)**: Unencrypted HTTP/Telnet/FTP management services.
    * **FR 5 (RDF)**: Multi-protocol bridging and conduit separation risks.
* **Visual Modular Chassis Rack Enclosure**:
  * Renders physical modular backplanes (e.g. Rockwell ControlLogix 1756) directly in reports with color-coded slots (CPU, COMM, I/O) and active status LEDs.
* **High-Impact Operational Risk Alerts**:
  * Dedicated alert callouts flagging critical OT conditions: physical keyswitch set to `REMOTE RUN` (over-the-wire logic overwrite exposure) and `Protection Level 1` (unrestricted memory access).
* **Multi-Layer Safety Guardrails**:
  * Strict CIDR scope whitelisting, non-routable private space validation, automated scanner exclusion, polite timing profiles (`T2`, 200ms delay), and fail-closed JSONL audit logging (`output/audit/`).
* **Air-Gap Ready, Zero-Script HTML Reports**:
  * Self-contained HTML reports adhering strictly to `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`. Safe to open on air-gapped engineering workstations or email directly to stakeholders.

---

## Quick Start

### Installation

```bash
# Clone the repository and install dependencies
git clone https://github.com/your-org/ot-recon.git
cd ot-recon
pip install -e .

# Optional: Install GUI and live NVD API support
pip install -e ".[gui,cve-live]"
```

### Basic Commands

```bash
# Standard polite scan of a plant subnet (safe profile by default)
python -m ot_recon.main scan 192.168.1.0/24

# Full-capability deep scan: native CIP backplane, S7comm SZL, and HTML report export
python -m ot_recon.main scan 192.168.1.0/24 --deep --format html

# Dry-run execution: previews all planned probes without sending any network packets
python -m ot_recon.main scan 192.168.1.0/24 --dry-run

# Re-render the latest scan snapshot into an updated HTML report (no rescan required)
python -m ot_recon.main report

# Inspect scan history and compute deltas between scans
python -m ot_recon.main history
python -m ot_recon.main diff snapshot_1.json snapshot_2.json

# Launch the desktop graphical interface
python -m ot_recon.main gui
```

---

## Demonstration Report

Want to explore an audit-grade report with full capabilities (Purdue hierarchy, visual chassis rack, operational alerts, and IEC 62443 matrix) without needing a live PLC rack?

Run the included demonstration generator:
```powershell
python scripts/generate_demo_report.py
```
Open the generated report in any browser:
```powershell
Start-Process "output\demonstration_ot_recon_report.html"
```

---

## Safety Guardrails Summary

| Guardrail | Enforcement | Purpose | Override |
| :--- | :--- | :--- | :--- |
| **Allowed Scope** | `scope.allowed` | Verifies target subnet is inside client allowlist. | **Cannot be overridden.** |
| **Sanity Guard** | `guardrails.py` | Forbids public IPs, subnets > 1024 IPs, and argument injection. | Overridable via `--force`. |
| **Exclude List** | `--exclude` | Hard exclusion for sensitive SIS controllers / governors. | Scanner auto-excluded. |
| **Safe Profile** | `--profile safe` | Restricts timing to `T2`, 200ms delay, 1 retry, 2 concurrent workers. | Selectable profiles. |
| **Audit Log** | `output/audit/` | Records every command, argument, probe timestamp, and target IP. | Fail-closed policy. |

---

## Documentation Index

* 📖 **[Full Operations & Technical Documentation](docs/DOCUMENTATION.md)**: Exhaustive manual detailing protocol packet structures, scoring algorithms, configuration parameters, and compliance references.
* 📋 **[Configuration Reference](docs/DOCUMENTATION.md#12-configuration-reference-configyaml)**: Reference for `config.yaml` options, port lists, and safety settings.
* 🖥️ **[GUI User Manual](docs/DOCUMENTATION.md#11-desktop-gui-guide)**: Graphical user interface walkthrough.
* ❓ **[Troubleshooting & FAQ](docs/DOCUMENTATION.md#14-troubleshooting--operational-faq)**: Frequently asked operational questions.

---

## License & Support

Maintained for industrial asset owners, plant operations, and OT cybersecurity teams.  
Author: Abhinav
