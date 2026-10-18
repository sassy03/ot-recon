# ot_recon/core/protocols/s7.py
#
# Native, read-only Siemens S7comm protocol implementation over RFC 1006 (ISO-on-TCP).
# Queries SZL (System Status Lists) to extract exact MLFB hardware catalog numbers,
# component names, firmware revisions, CPU keyswitch states (RUN/STOP/REM-RUN),
# and protection security levels.

import socket
import struct


def _build_tpkt_cotp_cr(rack: int = 0, slot: int = 1) -> bytes:
    """Build RFC 1006 TPKT + ISO 8073 COTP Connection Request (CR)."""
    # Called TSAP: connection type 0x01 (PG), rack/slot encoded as (rack * 32) + slot
    called_tsap = bytes([0x01, (rack * 32) + slot])
    calling_tsap = bytes([0x01, 0x00])

    cotp_body = bytes([
        0x11,        # Length indicator (17 bytes follow)
        0xE0,        # PDU Type: CR (Connection Request)
        0x00, 0x00,  # Destination reference
        0x00, 0x01,  # Source reference
        0x00,        # Class 0
        0xC1, 0x02, calling_tsap[0], calling_tsap[1],  # Parameter C1: Calling TSAP
        0xC2, 0x02, called_tsap[0], called_tsap[1],    # Parameter C2: Called TSAP
        0xC0, 0x01, 0x0A                               # Parameter C0: TPDU size (1024)
    ])

    tpkt_len = 4 + len(cotp_body)
    tpkt_hdr = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    return tpkt_hdr + cotp_body


def _build_s7_setup_comm(pdu_size: int = 480) -> bytes:
    """Build S7comm Setup Communication Job packet."""
    s7_header = struct.pack(
        ">BBHHHH",
        0x32,        # Protocol ID (S7comm)
        0x01,        # Message Type: Job
        0x0000,      # Reserved
        0x0001,      # PDU Reference
        0x0008,      # Parameter Length (8 bytes)
        0x0000,      # Data Length (0 bytes)
    )
    s7_params = struct.pack(
        ">BBHHH",
        0xF0,        # Function: Setup Communication
        0x00,        # Reserved
        0x0001,      # Max AMQ Caller
        0x0001,      # Max AMQ Callee
        pdu_size,    # Negotiated PDU Length
    )
    s7_pdu = s7_header + s7_params

    # COTP DT (Data Transfer): Len 2, Type 0xF0, EOT=0x80
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    tpkt_hdr = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_dt) + len(s7_pdu))
    return tpkt_hdr + cotp_dt + s7_pdu


def _build_s7_read_szl(szl_id: int, szl_index: int = 0x0000, pdu_ref: int = 0x0002) -> bytes:
    """Build S7comm Read SZL (Userdata) Job packet."""
    s7_header = struct.pack(
        ">BBHHHH",
        0x32,        # S7comm Protocol ID
        0x07,        # Message Type: Userdata
        0x0000,      # Reserved
        pdu_ref,     # PDU Reference
        0x0008,      # Parameter Length
        0x0008,      # Data Length
    )
    s7_params = bytes([
        0x00, 0x01, 0x12,  # Header (type 0x12)
        0x04,              # Parameter length
        0x11,              # Request method: Read
        0x44,              # Function: SZL request
        0x01, 0x00         # Subfunction: Read SZL
    ])
    s7_data = struct.pack(
        ">BBHHH",
        0xFF,              # Return code: Success
        0x09,              # Transport size: Octet string
        0x0004,            # Data length (4 bytes)
        szl_id,            # SZL-ID (e.g. 0x0011, 0x001C, 0x0132)
        szl_index,         # SZL-Index
    )
    s7_pdu = s7_header + s7_params + s7_data
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    tpkt_hdr = struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp_dt) + len(s7_pdu))
    return tpkt_hdr + cotp_dt + s7_pdu


def _recv_tpkt(sock: socket.socket) -> bytes:
    """Read a complete RFC 1006 TPKT frame."""
    hdr = sock.recv(4)
    if len(hdr) < 4 or hdr[0] != 0x03:
        return b""
    total_len = struct.unpack(">H", hdr[2:4])[0]
    payload = b""
    remaining = total_len - 4
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        payload += chunk
        remaining -= len(chunk)
    return hdr + payload


def query_s7_info(ip: str, port: int = 102, timeout: float = 3.0) -> dict:
    """Connect to Siemens S7 controller on TCP port 102 and query SZL metadata.
    Tries Rack 0 / Slot 1 (S7-1200 / S7-1500) then Slot 2 (S7-300 / S7-400).
    Returns structured dictionary with exact MLFB, firmware, component name,
    keyswitch operating state, and security protection level."""
    for slot in (1, 2):
        info = _try_query_s7(ip, port, timeout=timeout, rack=0, slot=slot)
        if info:
            info["rack"] = 0
            info["slot"] = slot
            return info
    return {}


def _try_query_s7(ip: str, port: int, timeout: float, rack: int, slot: int) -> dict:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # 1. COTP Connection Request
            s.sendall(_build_tpkt_cotp_cr(rack=rack, slot=slot))
            resp = _recv_tpkt(s)
            # Response must have COTP CC (0xD0) at byte 5
            if len(resp) < 6 or resp[5] != 0xD0:
                return {}

            # 2. S7 Setup Communication
            s.sendall(_build_s7_setup_comm())
            resp = _recv_tpkt(s)
            if len(resp) < 17:
                return {}

            # 3. Read SZL 0x0011 (Module Identification)
            s.sendall(_build_s7_read_szl(0x0011, pdu_ref=2))
            resp = _recv_tpkt(s)

            res = {
                "vendor": "Siemens",
                "type": "PLC",
                "mlfb": None,
                "model": None,
                "firmware": None,
                "component_name": None,
                "keyswitch_mode": None,
                "protection_level": None,
            }

            if len(resp) > 30:
                _parse_szl_0011(resp, res)

            # 4. Read SZL 0x001C (Component Identification - Project Name)
            try:
                s.sendall(_build_s7_read_szl(0x001C, pdu_ref=3))
                resp_1c = _recv_tpkt(s)
                if len(resp_1c) > 30:
                    _parse_szl_001c(resp_1c, res)
            except OSError:
                pass

            # 5. Read SZL 0x0132 (Protection Level & Keyswitch State)
            try:
                s.sendall(_build_s7_read_szl(0x0132, pdu_ref=4))
                resp_132 = _recv_tpkt(s)
                if len(resp_132) > 30:
                    _parse_szl_0132(resp_132, res)
            except OSError:
                pass

            if res.get("mlfb") or res.get("model"):
                return res

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return {}


def _parse_szl_0011(data: bytes, res: dict):
    """Extract MLFB order code and firmware revision from SZL 0x0011 data."""
    # Look for standard 6ES7 MLFB order codes inside the SZL payload
    mlfb_pos = data.find(b"6ES7")
    if mlfb_pos == -1:
        mlfb_pos = data.find(b"6GK7")
    if mlfb_pos == -1:
        mlfb_pos = data.find(b"6AV6")

    if mlfb_pos != -1:
        mlfb = data[mlfb_pos : mlfb_pos + 20].decode("latin-1", errors="replace").strip()
        # Clean trailing non-alphanumeric chars
        res["mlfb"] = mlfb
        res["model"] = mlfb

        # Model family resolution
        if "6ES7 5" in mlfb or "6ES75" in mlfb:
            res["model_family"] = "S7-1500"
        elif "6ES7 2" in mlfb or "6ES72" in mlfb:
            res["model_family"] = "S7-1200"
        elif "6ES7 3" in mlfb or "6ES73" in mlfb:
            res["model_family"] = "S7-300"
        elif "6ES7 4" in mlfb or "6ES74" in mlfb:
            res["model_family"] = "S7-400"

        # Firmware version bytes typically follow at offset +20 or +22
        # (3 bytes: major, minor, build)
        if len(data) >= mlfb_pos + 24:
            fw_bytes = data[mlfb_pos + 20 : mlfb_pos + 24]
            if any(b != 0 for b in fw_bytes[:3]):
                res["firmware"] = f"V{fw_bytes[0]}.{fw_bytes[1]}.{fw_bytes[2]}"


def _parse_szl_001c(data: bytes, res: dict):
    """Extract component/plant name from SZL 0x001C."""
    # Look for printable strings of reasonable length in SZL 0x001C data
    # Last chunk of SZL 0x001C contains the text name
    text_data = data[32:]
    for length in (24, 32):
        for i in range(0, len(text_data) - 8, 4):
            candidate = text_data[i : i + length]
            printable = "".join(chr(c) for c in candidate if 32 <= c <= 126).strip()
            if len(printable) >= 4 and not printable.startswith("6ES7"):
                res["component_name"] = printable
                return


def _apply_s7_security(prot_level: int, state_byte: int, res: dict):
    if prot_level == 1:
        res["protection_level"] = "Level 1 (No Protection / Open)"
    elif prot_level == 2:
        res["protection_level"] = "Level 2 (Write Protected)"
    elif prot_level == 3:
        res["protection_level"] = "Level 3 (Read/Write Protected)"

    if state_byte == 1:
        res["keyswitch_mode"] = "RUN"
    elif state_byte == 2:
        res["keyswitch_mode"] = "STOP"
    elif state_byte in (3, 4):
        res["keyswitch_mode"] = "REMOTE RUN (Logic download allowed across network)"


def _parse_szl_0132(data: bytes, res: dict):
    """Extract protection level and keyswitch operating state from SZL 0x0132."""
    pos = data.find(b"\x01\x32")
    if pos != -1 and len(data) >= pos + 12:
        # SZL header: 2 (ID) + 2 (Index) + 2 (Item Len) + 2 (Count) = 8 bytes
        rec = data[pos + 8 :]
        if len(rec) >= 6:
            prot_level = rec[3] if rec[2] == 0 else rec[2]
            state_byte = rec[5] if rec[4] == 0 else rec[4]
            if prot_level in (1, 2, 3):
                _apply_s7_security(prot_level, state_byte, res)
                return

    # Fallback to scanning payload for protection and keyswitch bytes
    for i in range(20, len(data) - 1):
        if data[i] in (1, 2, 3) and data[i + 1] in (1, 2, 3, 4):
            _apply_s7_security(data[i], data[i + 1], res)
            return


