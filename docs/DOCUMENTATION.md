# OT-Recon: Industrial Cybersecurity Reconnaissance & Vulnerability Assessment Platform
## Technical Documentation & Comprehensive Operations Manual

---

## 1. Executive Overview & Mission

**OT-Recon** is an industrial-grade, safety-first network reconnaissance, asset discovery, deep protocol inspection, and vulnerability management platform designed specifically for Operational Technology (OT), Industrial Control Systems (ICS), and Supervisory Control and Data Acquisition (SCADA) environments.

### The OT Cybersecurity Challenge
Traditional IT security scanners (e.g., Nessus, Qualys, OpenVAS, aggressive Nmap scripts) operate on assumptions that are catastrophic in industrial control systems:
* **Fragile Embedded Stacks**: Programmable Logic Controllers (PLCs), Remote Terminal Units (RTUs), and safety relays often utilize lightweight, real-time operating systems (RTOS) with minimal TCP/IP buffers. Volumetric scans, SYN floods, or malformed packets can trigger unhandled CPU faults, hard lockups, or safety trips that halt multi-million-dollar production lines.
* **The "Exploit Framework" Danger**: Offensive exploit frameworks (e.g., Metasploit, ISF/Industrial Exploitation Framework) deliver active payload injections and memory corruption sequences. Executing exploit payloads in live production environments presents intolerable risks to human life, equipment safety, and environmental integrity.
* **Lack of OT Context**: IT vulnerability scanners assess systems purely based on open ports and generic CVE numbers without understanding physical consequences, keyswitch positions, backplane architectures, or ISA-95/Purdue operational layers.

### The OT-Recon Philosophy
OT-Recon solves this paradigm by enforcing **deterministic, passive-where-possible, read-only active inspection**:
1. **Safety-First Non-Disruptive Operations**: All queries adhere strictly to vendor protocol specifications (RFC 1006 / ISO-on-TCP, CIP Specification Volume 1, Modbus Application Protocol v1.1b). No write requests, no force-coil commands, and no exploit payloads are ever generated.
2. **Deterministic Deep Protocol Telemetry**: Interacts directly with controllers at the native protocol layer to extract hardware order numbers (MLFB), physical rack backplanes, firmware revisions, and hardware keyswitch states.
3. **Operational Risk Grounding**: Evaluates risks not merely by software vulnerabilities, but by physical operational postures (e.g., CPU keyswitches left in `REMOTE RUN`, unauthenticated controller access levels).
4. **Transparent Limitation Reporting**: Embraces an honest assessment model. The report explicitly documents what was *not* assessed, ensuring operators never mistake "no findings" for "secure".

---

## 2. System Architecture & Processing Pipeline

OT-Recon executes a deterministic 9-stage assessment pipeline:

```
               [ Operator CLI / Desktop GUI ]
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 1. Guardrail Verification & Scope Validation               │
│    • Validate Private CIDR & Address Count                 │
│    • Enforce Allowed Scope Allowlist                       │
│    • Auto-Exclude Scanner IP & Do-Not-Scan Assets          │
│    • Audit Log Initialization                              │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 2. Safe Host Discovery (Ping Sweep)                        │
│    • Polite ICMP Echo / TCP ACK Pings                      │
│    • Identifies Active Hosts on Target Subnet              │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 3. Paced Service Enumeration                               │
│    • TCP Connect Scanning (Polite Pacing / T2 Timing)      │
│    • Targeted OT Ports: 102, 502, 44818, 4840, 20000, etc. │
│    • Selective UDP Discovery (Port 161, 47808)             │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 4. Read-Only Fingerprinting & Native Deep Inspection       │
│    • Standard Fingerprinting: Nmap safe NSE scripts        │
│    • [Unified --deep Option]: Native Python Scapy Probes   │
│      - S7comm: SZL 0x0011 (MLFB/FW) & SZL 0x0132 (Key/Prot)│
│      - EtherNet/IP: CIP Identity & Chassis Backplane Walk  │
│      - Modbus TCP: Function 43/14 MEI Device Readout       │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 5. Evidence-Based Device Classification                    │
│    • Rule-based heuristics evaluating port combinations,   │
│      vendor banners, and native protocol attributes        │
│    • Purdue Model Mapping: L1 Safety, L1 Control, L2, L3   │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 6. Asset Metadata Enrichment                               │
│    • Synthesize component names, hardware models, serials  │
│    • Cross-reference vendor identity dictionaries          │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 7. Quantitative Risk Engine & CVE Correlation              │
│    • Curated Local ICS Advisory Database Matching          │
│    • Optional Live NVD API v2 Lookups (7-Day Cache)        │
│    • Physical Operational Risk Evaluation                  │
│    • Asset Criticality Weighting (Safety PLC > Standard)   │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 8. Historical Tracking & Delta Engine                      │
│    • Snapshot Archiving (JSON)                             │
│    • Scan-to-Scan Diffing: New/Lost Hosts, Port Changes    │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│ 9. Audit-Grade Reporting & Visualization                   │
│    • Self-Contained Air-Gap HTML Assessment Report         │
│    • Visual Modular Chassis Rack Layout Rendering          │
│    • IEC 62443 Security Compliance Matrix                  │
│    • Prioritized Engineering Remediation Plan (P1 - P5)    │
│    • Interactive Rich Terminal Table & JSON Export         │
└────────────────────────────────────────────────────────────┘
```

---

## 3. Native Deep Protocol Inspection Engine (`--deep`)

When the `--deep` flag is enabled (via CLI or GUI), OT-Recon engages custom, native Python protocol clients built with raw packet constructs. These modules interact safely with industrial controllers without relying on intrusive third-party exploit suites.

### 3.1 Siemens S7comm & S7comm-Plus (Port 102 / TCP)
Siemens S7-300, S7-400, S7-1200, and S7-1500 controllers communicate over ISO-on-TCP (RFC 1006 / TPKT) and COTP (ISO 8073 Class 0).

* **Protocol Handshake**:
  1. Establishes TCP connection to port 102.
  2. Sends COTP Connection Request (`CR`) with destination TSAP `0x0102` (CPU rack 0, slot 2) or `0x0100`.
  3. Receives COTP Connection Confirm (`CC`).
  4. Issues S7comm Job Header: `Setup Communication` negotiating Maximum PDU length (typically 240, 480, or 960 bytes).
* **SZL Diagnostics (System Status List / Teilsysteme)**:
  - **SZL ID `0x0011` / Index `0x0001` (Module Identification)**: Extracts exact Siemens order code (MLFB), e.g., `6ES7 315-2EH14-0AB0`, hardware release version, and exact firmware revision (e.g., `v3.3.12`).
  - **SZL ID `0x001C` (Component Identification)**: Extracts the plant engineer's configured system name, project identifier, and module installation location.
  - **SZL ID `0x0132` / Index `0x0004` (CPU Protection & Operational State)**:
    - **Keyswitch Position**: Reads the physical or logical front-panel switch:
      - `RUN`: Hardware execution locked; remote logic upload/download is physically inhibited.
      - `REMOTE RUN`: Remote engineering stations can initiate firmware uploads, stop/pause CPU execution, and modify ladder logic over the wire.
      - `STOP`: Controller halted; process outputs disabled.
    - **Protection Level**:
      - `Level 1`: No password protection configured. Any workstation on the network can read/write data blocks, force coils, and stop the PLC.
      - `Level 2`: Write protection enabled; read access unrestricted.
      - `Level 3`: Full read/write password protection enabled.

### 3.2 Rockwell Automation EtherNet/IP & CIP (Port 44818 / TCP, Port 2222 / UDP)
Allen-Bradley ControlLogix, CompactLogix, and MicroLogix PLCs utilize the Common Industrial Protocol (CIP) encapsulated within EtherNet/IP.

* **CIP Identity Registration**:
  1. Issues EtherNet/IP `ListIdentity` command (`0x0063`) to broadcast/unicast address.
  2. Extracts Vendor ID (`1` = Rockwell Automation), Device Type (`0x0E` = Programmable Logic Controller), Product Code, Major/Minor Firmware Revision, Serial Number, and Device Name (e.g., `1756-L83ES/B GuardLogix 5580`).
* **Multi-Slot Chassis & Backplane Enumeration**:
  1. Establishes an explicit messaging session via `RegisterSession` (`0x0065`).
  2. Traverses backplane slots (Slots 0 through 16) by sending CIP `GetAttributeList` / `GetAttributeAll` queries to Class `0x01` (Identity Object), Instance `0x01`, routed across the local chassis backplane (`Path: [0x01, Slot]`).
  3. Maps every plugged module into a physical rack:
     - **CPU Controllers**: e.g., `1756-L83E`, `1756-L73`.
     - **Safety Partners**: e.g., `1756-L8SP`.
     - **Communications Adapters**: e.g., `1756-EN2T`, `1756-EN2TR`, `1756-CNBR`.
     - **Digital & Analog I/O Cards**: e.g., `1756-IB16`, `1756-OB16E`, `1756-IF8`.

### 3.3 Schneider Electric & Modbus TCP (Port 502 / TCP)
Modbus TCP communicates in cleartext using standard Function Codes.

* **Modbus Encapsulated Interface (MEI) - Function Code 43 / Sub-function 14**:
  1. Issues Read Device Identification request with `ReadDeviceID code 0x01` (Basic Device Identification).
  2. Conforms strictly to Modbus Application Protocol Specification v1.1b.
  3. Extracts vendor-authenticated object values:
     - `Object ID 0x00`: **VendorName** (e.g., `Schneider Electric`, `WAGO`, `Advantech`).
     - `Object ID 0x01`: **ProductCode** (e.g., `BMX P34 2020`, `750-881`).
     - `Object ID 0x02`: **MajorMinorRevision** (e.g., `02.80`).
     - `Object ID 0x04`: **UserApplicationName** (Configured project title).

---

## 4. Safety Guardrails & Defensive Controls

To guarantee that OT-Recon can be deployed on sensitive live production networks without incident, five concentric rings of safety guardrails are permanently enforced in the core engine:

| Guardrail Ring | Implementation | Operational Mechanism | Override Policy |
| :--- | :--- | :--- | :--- |
| **Ring 1: Scope Whitelist** | `scope.allowed` in `config.yaml` | Strictly verifies that target CIDR lies within the client-approved industrial subnet. | **CANNOT be overridden.** The tool terminates immediately if target is outside scope. |
| **Ring 2: Target Sanity Checks** | `guardrails.py` | Forbids public routable IPs, targets exceeding `max_addresses` (default 1024), and argument injection patterns (`-sS`, `;`, `&&`). | Overridable only with explicit `--force` flag (audit log records override). |
| **Ring 3: Do-Not-Scan Exclusion** | `--exclude` & auto-exclusion | Hard exclusion list for delicate SIS controllers, turbine governors, or fragile legacy RTUs. Scanner's own host IP is automatically excluded. | Overrideable via `--include-self`. |
| **Ring 4: Paced Timing Profiles** | `--profile safe` | Restricts Nmap timing to `T2` (polite), inserts 200ms inter-probe delays, caps max retries to 1, and limits concurrent workers to 2. | Selectable profiles: `safe` (default), `standard`, `fast`. |
| **Ring 5: Mandatory Audit Log** | `output/audit/` | Every executed command line, argument list, probe timestamp, and target IP is written to a JSONL audit log before execution. | **Fail-Closed**: If audit disk path is unwritable, scan aborts. |

---

## 5. Purdue Model (ISA-95) Hierarchy Categorization

OT-Recon maps every discovered asset into the **ISA-95 / Purdue Enterprise Reference Architecture**:

```
[ Level 4: Enterprise Network / ERP / Corporate IT ] (Out of Scope)
───────────────────────────────▲───────────────────────────────
                               │ Industrial DMZ / Firewalls
───────────────────────────────▼───────────────────────────────
[ Level 3: Site Operations & Manufacturing Infrastructure ]
  • Historians, SCADA Gateways, Engineering Workstations, MES
  • Protocols: OPC UA (4840), RDP (3389), HTTPS, SQL
───────────────────────────────▲───────────────────────────────
                               │ Zone Boundary / Conduits
───────────────────────────────▼───────────────────────────────
[ Level 2: Supervisory & Local Area Control ]
  • Operator Touchscreens, HMIs (PanelView, WinCC Comfort Panels)
  • Protocols: S7comm Tag Read, CIP Messaging, VNC (SmartServer)
───────────────────────────────▲───────────────────────────────
                               │ Zone Boundary / Conduits
───────────────────────────────▼───────────────────────────────
[ Level 1: Basic Process Control & Safety Systems (SIS) ]
  • Safety PLCs (GuardLogix, Triconex, HIMA)
  • Standard PLCs (S7-1500, ControlLogix, Modicon M580)
  • Field Bus Couplers, Remote I/O Racks, Variable Frequency Drives
  • Protocols: CIP I/O (2222), Modbus TCP (502), S7comm (102), Profinet
───────────────────────────────▲───────────────────────────────
[ Level 0: Physical Process & Actuation ]
  • Sensors, Actuators, Valves, Motors (Hardwired to L1 I/O modules)
```

### Visual Representation in Reports:
- **`L1: Safety / SIS`** (Purple Badge): Highest criticality; weighted with a 1.3x risk factor multiplier.
- **`L1: Basic Control`** (Blue Badge): Direct controller controlling field processes.
- **`L2: Supervisory (HMI)`** (Emerald Badge): Operator station interfaces.
- **`L3: Operations Infrastructure`** (Amber Badge): Supervisory servers and plant historians.
- **`Unclassified / IT Host`** (Slate Badge): General IT hosts, printers, or unclassified nodes.

---

## 6. IEC 62443 Security Posture & Compliance Matrix

OT-Recon evaluates scan telemetry against the international standard for industrial automation cybersecurity, **IEC 62443-3-3** (System Security Requirements) and **IEC 62443-4-2** (Technical Security Requirements for IACS Components):

### Foundational Requirements (FR) Evaluated:

#### FR 1: Identification & Authentication Control (IAC)
- **Standard Reference**: `IEC 62443-3-3 SR 1.1 / 1.2`
- **Assessment Condition**: Detects cleartext OT protocols (Modbus TCP, standard S7comm, standard EtherNet/IP) active without cryptographic identity.
- **Primary Risk**: Anyone connected to the VLAN can craft unauthenticated commands to open valves or stop pumps.
- **Recommended Control**: Deploy OT micro-segmentation; migrate to secure protocol extensions (**CIP Security**, **S7comm Plus with TLS**, **Modbus Security**) where supported.

#### FR 2: Use Control & Mode Authorization (UC)
- **Standard Reference**: `IEC 62443-3-3 SR 2.1 / 2.3`
- **Assessment Condition**: Keyswitch in `REMOTE RUN` or controller configured with `Protection Level 1` (open memory).
- **Primary Risk**: Network-borne ladder logic overwrites, diagnostic force-coils, and CPU halt commands can occur without physical cabinet access.
- **Recommended Control**: Enforce physical keyswitch rotation to **`RUN (Hard Lock)`** during active plant production. Enforce memory block read/write protection passwords.

#### FR 3: System Integrity & Vulnerability Management (SI)
- **Standard Reference**: `IEC 62443-4-2 EDR 3.1 / 3.2`
- **Assessment Condition**: Discovered hardware/firmware correlates with cataloged Critical/High CVEs in the local database or NVD.
- **Primary Risk**: Memory corruption, buffer overflows, or remote denial of service impacting plant operations.
- **Recommended Control**: Establish a validated firmware patch schedule for upcoming plant turnarounds; implement virtual patching via industrial intrusion prevention signatures.

#### FR 4: Data Confidentiality & Cleartext Control (DC)
- **Standard Reference**: `IEC 62443-3-3 SR 4.1`
- **Assessment Condition**: Plaintext management protocols exposed (HTTP port 80, Telnet port 23, FTP port 21).
- **Primary Risk**: Unencrypted transmission of setpoints, recipes, and administrative credentials.
- **Recommended Control**: Disable HTTP/Telnet/FTP; enforce TLS-encrypted HTTPS and SSHv2 with strict cipher suites.

#### FR 5: Restricted Data Flow & Conduit Separation (RDF)
- **Standard Reference**: `IEC 62443-3-2 Zone & Conduit Architecture`
- **Assessment Condition**: Discovered controllers bridging IT management services (HTTP, SSH) directly with real-time field control services (S7comm, CIP, Modbus) on the same interface.
- **Primary Risk**: Lack of conduit segmentation allows lateral movement from enterprise malware directly into process loops.
- **Recommended Control**: Isolate control loops into dedicated VLANs; terminate supervisory connections on an intermediate Industrial DMZ.

---

## 7. Quantitative Risk Engine & CVE Correlation

OT-Recon avoids subjective risk scores by calculating a quantitative, mathematically grounded risk score ($0 - 100$):

$$\text{Risk Score} = \min\left(100, \;\sum (\text{Severity Weights}) \times \text{Asset Multiplier}\right)$$

### Finding Severity Weights:
- **Critical Finding**: 40 points (e.g., RCE vulnerability, keyswitch in REMOTE RUN with known exploit path)
- **High Finding**: 20 points (e.g., Unauthenticated Modbus TCP control, VNC exposed without encryption)
- **Medium Finding**: 10 points (e.g., Cleartext HTTP administrative interface, SNMP default community)
- **Low Finding**: 3 points (e.g., SSH management open, banner info disclosure)
- **Info Finding**: 0 points (e.g., Asset type identified)

### Asset Criticality Multipliers:
- **Safety PLC (SIS)**: $1.3\times$ (Failure directly impacts life, health, or environmental safety)
- **Standard PLC / RTU**: $1.2\times$ (Failure halts production or damages mechanical assets)
- **Human-Machine Interface (HMI)**: $1.1\times$ (Operator visibility and supervisory control)
- **SCADA / Operations Server**: $1.0\times$
- **General Network / Unclassified Host**: $1.0\times$

### CVE Correlation Architecture:
1. **Local Curated Database (`data/cve_db.yaml`)**: An air-gap-safe offline database containing curated advisories from CISA, Siemens CERT, and Rockwell Product Security.
2. **Live NVD API v2 Client (`--cve-live`)**: When enabled, queries the National Vulnerability Database using exact CPE 2.3 identifiers and product vendor strings.
3. **Smart Local Caching (`output/cve_cache.json`)**: Live queries are cached locally with a 7-day Time-To-Live (TTL), minimizing API quota usage and accelerating repeat scans.

---

## 8. Audit-Grade HTML Assessment Reporting & Visual Chassis

Reports generated by OT-Recon (`--format html` or `ot-recon report`) are designed to bridge the communication gap between executive management, OT engineers, and cybersecurity auditors.

### Key Architectural Characteristics:
* **Air-Gap Ready**: Single standalone file with inline CSS. Operates without an internet connection.
* **Zero Script Vulnerabilities**: Strictly enforces `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`. No external scripts, no tracking pixels, and no embedded JavaScript.
* **Industrial Color-Coded Chassis**:
  For modular PLCs (e.g., Rockwell ControlLogix 1756), the report synthesizes a physical rack visualization:
  - Slate enclosure container simulating an industrial backplane.
  - Active green LED indicators.
  - Blue-accented **CPU Controller** cards.
  - Slate-accented **Communications** bridges.
  - Light-slate **Digital & Analog I/O** cards with slot indices, part numbers, and firmware revisions.
* **High-Impact Operational Callouts**:
  Special alert banners highlight critical physical conditions:
  - 🚨 **`REMOTE RUN` Alert**: Warns of network ladder logic rewrite exposure.
  - ⚠️ **`Protection Level 1` Alert**: Warns of open memory access without password validation.
* **Print & PDF Optimized**: Integrated `@media print` rules strip sticky navigation bars and format clean page-breaks suitable for formal engineering submissions.

---

## 9. Historical Tracking & Delta Engine (Scan Diffs)

Industrial environments are static by nature; unauthorized changes are primary indicators of compromise or rogue devices.

OT-Recon automatically stores every completed scan snapshot in `output/history/history_<timestamp>.json`:
- **`ot-recon history`**: Lists all recorded historical snapshots with discovered asset counts and risk scores.
- **`ot-recon diff <older_snapshot> <newer_snapshot>`**: Calculates precise delta changes:
  - **New Hosts Discovered**: Rogue controllers or unauthorized laptops connected to the plant floor.
  - **Decommissioned / Missing Hosts**: Devices that have lost connectivity or gone offline.
  - **Port & Service Deltas**: Newly opened management ports (e.g., someone enabled Telnet or HTTP).
  - **Vulnerability Changes**: Newly detected or remediated CVEs.

---

## 10. CLI Command Reference Guide

### 10.1 `ot-recon scan <target>`
Executes network discovery and vulnerability assessment.

```bash
ot-recon scan [OPTIONS] TARGET
```

#### Arguments:
- `TARGET`: Target CIDR subnet (e.g., `192.168.1.0/24`), IP range (`10.0.0.1-50`), or single host (`192.168.1.50`).

#### Options:
| Flag | Description | Default |
| :--- | :--- | :--- |
| **`--deep`** | **Enables native read-only OT protocol inspection (S7comm SZL, CIP backplane, Modbus MEI).** | Disabled |
| `--profile <name>` | Select scan pacing profile: `safe`, `standard`, `fast`. | `safe` |
| `--dry-run` | Prints all commands that would execute without sending a single packet. | False |
| `--format <type>` | Output format: `console`, `html`, `json`, or `all`. | `console` |
| `--html <path>` | Custom file path for the exported HTML report. | Auto-generated |
| `--cve-live` | Enables live NVD API lookups for newly discovered firmware strings. | False (local DB only) |
| `--udp` | Enables UDP port scanning (BACnet, SNMP, CIP I/O). Requires root/admin. | False |
| `--exclude <ips>` | Comma-separated list of IP addresses to exclude from the scan. | None |
| `--scope <cidr>` | Confirms execution only if target resides within specified CIDR (typo guard). | None |
| `--force` | Overrides non-fatal sanity warnings (recorded in audit log). | False |
| `--include-self` | Allows scanning the host IP executing OT-Recon. | Excluded |

---

### 10.2 `ot-recon report`
Re-renders the most recent scan snapshot into an audit-grade HTML report without re-scanning the network.

```bash
ot-recon report [--output <path>]
```

---

### 10.3 `ot-recon history`
Displays historical scan inventory stored in the local archive.

```bash
ot-recon history
```

---

### 10.4 `ot-recon diff`
Compares two scan snapshots and outputs differences.

```bash
ot-recon diff snapshot_20261020_080000.json snapshot_20261020_140000.json
```

---

### 10.5 `ot-recon gui`
Launches the standalone WxPython desktop application for visual operations.

```bash
ot-recon gui
```

---

## 11. Desktop GUI Guide

The OT-Recon graphical interface provides an industrial-themed control dashboard:

1. **Target Specification & Scope Configuration**:
   - Subnet input field with automated private IP verification.
   - Pacing profile dropdown selector (`Safe`, `Standard`, `Fast`).
2. **Unified Feature Toggles**:
   - **`[x] Enable Deep Protocol Inspection (--deep)`**: Engages CIP backplane traversal, S7comm SZL readout, and Modbus MEI identification.
   - **`[x] Enable Live NVD Correlation (--cve-live)`**: Performs online CVE lookup.
   - **`[x] Scan UDP OT Ports`**: Toggles BACnet and SNMP scanning.
   - **`[x] Export HTML Report`**: Generates and prompts to launch the HTML report upon completion.
3. **Execution Console & Live Activity Stream**:
   - Real-time terminal output displaying current probe phase and progress.
   - Emergency **Abort** button to instantly terminate scanning processes.
4. **Interactive Asset Table**:
   - Sortable columns for IP, Device Type, Vendor, Model, Firmware, Risk Score, and Severity.
   - Double-clicking an asset row opens the detailed findings inspector.

---

## 12. Configuration Reference (`config.yaml`)

The primary configuration file governs default timeouts, port lists, and safety boundaries:

```yaml
# ==============================================================================
# OT-Recon Master Configuration File
# ==============================================================================

# Core Scope Boundaries
scope:
  # Mandatory allowlist: scans outside these subnets are ALWAYS rejected
  allowed:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  
  # Maximum allowed addresses in a single scan run
  max_addresses: 1024
  
  # Default excluded IP addresses (critical infrastructure / SIS controllers)
  exclude:
    - "10.10.40.100"

# Timing & Safety Profiles
profiles:
  safe:
    tcp_timing: "T2"              # Polite Nmap timing
    udp_timing: "T2"
    scan_delay: "200ms"           # 200 milliseconds between packet transmissions
    max_retries: 1                # Minimum retry count to prevent packet floods
    version_intensity: 0          # Minimal banner probes
    workers: 2                    # Capped concurrent background threads
    nmap_script_timeout: 60       # Maximum seconds per probe script

  standard:
    tcp_timing: "T3"
    udp_timing: "T3"
    scan_delay: "50ms"
    max_retries: 2
    version_intensity: 2
    workers: 4
    nmap_script_timeout: 45

  fast:                           # LAB / IT TESTBENCH USE ONLY
    tcp_timing: "T5"
    udp_timing: "T5"
    scan_delay: "0ms"
    max_retries: 3
    version_intensity: 5
    workers: 8
    nmap_script_timeout: 30

# Industrial Port Groups
ports:
  tcp:
    - 102     # Siemens S7comm / ISO-on-TCP
    - 502     # Modbus TCP
    - 44818   # Rockwell EtherNet/IP / CIP Explicit
    - 4840    # OPC UA Binary Protocol
    - 20000   # DNP3 (Distributed Network Protocol)
    - 80      # Embedded Web HMI / HTTP
    - 443     # Secure Web HMI / HTTPS
    - 21      # File Transfer Protocol (Legacy PLC Firmware)
    - 22      # SSH Management
    - 23      # Telnet Management
    - 5900    # VNC (SmartServer HMI Remote Access)
  udp:
    - 161     # SNMP Management
    - 2222    # EtherNet/IP CIP I/O Implicit Messaging
    - 47808   # BACnet / IP Building Automation
```

---

## 13. Demonstration & Verification Suite

To verify report aesthetics, chassis rendering, and compliance matrix logic without requiring a physical PLC testbench, OT-Recon includes a demonstration generator:

```powershell
python scripts/generate_demo_report.py
```

This generates `output/demonstration_ot_recon_report.html`, synthesizing a complete multi-vendor industrial environment:
1. **Rockwell GuardLogix 5580 Safety Controller** (`10.10.40.10`) with 5-slot backplane chassis rack.
2. **Siemens SIMATIC S7-300 PLC** (`10.10.40.20`) with MLFB `6ES7 315-2EH14-0AB0` and keyswitch in `REMOTE RUN`.
3. **Schneider Electric Modicon M340 PLC** (`10.10.40.30`) with Modbus MEI identification.
4. **Siemens Comfort Panel HMI** (`10.10.40.50`) with VNC remote access.
5. **Plant SCADA / Historian Gateway** (`10.10.40.100`) running OPC UA.

---

## 14. Troubleshooting & Operational FAQ

#### Q: Why does Nmap report "Host seems down" during ping sweeps?
**A**: Many hardened PLCs and industrial firewall conduits intentionally drop ICMP Echo requests. Use the `--profile safe` profile; OT-Recon automatically includes TCP SYN pings to port 80 and port 443 to detect hosts that ignore ICMP pings.

#### Q: Can running `--deep` trip or fault a running PLC?
**A**: No. The `--deep` engine generates strictly standard read queries:
- For Siemens: COTP CR + Setup Communication + Read SZL (read-only diagnostic list).
- For Rockwell: ListIdentity + GetAttributeList (standard CIP browse commands used by RSLinx/FactoryTalk).
- For Modbus: Function 43/14 (standard device identification).
No write requests, memory overwrites, or malformed packets are ever transmitted.

#### Q: How do I export reports directly to PDF?
**A**: Open the generated HTML file in Google Chrome, Microsoft Edge, or Firefox, and select **Print &rarr; Save as PDF**. The built-in `@media print` CSS rules automatically optimize page breaks, suppress navigation bars, and apply print-friendly light backgrounds.
