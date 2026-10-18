# ot_recon/core/protocols/cip.py
#
# Native, read-only EtherNet/IP (CIP) protocol implementation.
# Provides deep, active identification of industrial controllers, communication
# adapters, drives, and backplane chassis modules without spawning external processes.

import socket
import struct

CIP_VENDORS = {
    1: "Rockwell Automation/Allen-Bradley",
    40: "Phoenix Contact",
    50: "WAGO",
    243: "Beckhoff Automation",
    282: "Schneider Electric",
    517: "Endress+Hauser",
    808: "OMRON",
    1070: "HMS Networks (Anybus)",
}

CIP_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x07: "General Purpose Discrete I/O",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x10: "Position Controller",
    0x15: "Human-Machine Interface",
    0x2B: "Generic Device (Keyable)",
    0x2C: "Managed Ethernet Switch",
}


def parse_identity_item(data: bytes) -> dict:
    """Parse a CIP Identity Object buffer (as returned by ListIdentity or Get_Attributes_All)."""
    if len(data) < 18:
        return {}

    # Header in ListIdentity item includes encap version (2) + sockaddr (16) = 18 bytes
    offset = 0
    if len(data) >= 34 and data[0:2] == b"\x01\x00":  # encap version 1
        offset = 18  # skip encap version + sockaddr

    if len(data) < offset + 14:
        return {}

    vendor_id, device_type_id, product_code, rev_maj, rev_min, status, serial = struct.unpack_from(
        "<HHHBBHI", data, offset
    )
    offset += 14

    product_name = ""
    if len(data) > offset:
        name_len = data[offset]
        offset += 1
        if len(data) >= offset + name_len:
            product_name = data[offset : offset + name_len].decode("utf-8", errors="replace").strip()
            offset += name_len

    state = data[offset] if len(data) > offset else None

    vendor_name = CIP_VENDORS.get(vendor_id, f"Vendor {vendor_id}")
    device_type_name = CIP_DEVICE_TYPES.get(device_type_id, f"Type {device_type_id}")

    return {
        "vendor_id": vendor_id,
        "vendor": vendor_name,
        "device_type_id": device_type_id,
        "device_type": device_type_name,
        "product_code": product_code,
        "firmware": f"{rev_maj}.{rev_min:02d}",
        "revision": {"major": rev_maj, "minor": rev_min},
        "status": status,
        "serial_number": f"{serial:08X}",
        "product_name": product_name,
        "model": product_name,
        "state": state,
    }


def query_cip_identity(ip: str, port: int = 44818, timeout: float = 3.0) -> dict:
    """Send a read-only EtherNet/IP ListIdentity command (0x0004) directly to port 44818.
    Returns structured device metadata dictionary or empty dict if unreachable."""
    # ListIdentity Encapsulation Header (24 bytes)
    # Command: 0x0004 (ListIdentity), Length: 0, Session: 0, Status: 0, SenderContext: 8 bytes, Options: 0
    req = struct.pack("<HHII8sI", 0x0004, 0, 0, 0, b"OT-RECON", 0)

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            resp = s.recv(4096)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {}

    if len(resp) < 24:
        return {}

    cmd, length, session, status = struct.unpack_from("<HHII", resp, 0)
    if cmd != 0x0004 or status != 0 or len(resp) < 26:
        return {}

    item_count = struct.unpack_from("<H", resp, 24)[0]
    offset = 26

    for _ in range(item_count):
        if len(resp) < offset + 4:
            break
        item_type, item_len = struct.unpack_from("<HH", resp, offset)
        offset += 4
        if item_type == 0x000C:  # Identity item
            item_data = resp[offset : offset + item_len]
            parsed = parse_identity_item(item_data)
            if parsed:
                return parsed
        offset += item_len

    return {}


def scan_cip_backplane(ip: str, port: int = 44818, max_slots: int = 8, timeout: float = 2.0) -> list[dict]:
    """Inspect modules installed in a modular chassis backplane (e.g. Allen-Bradley ControlLogix 1756
    or CompactLogix). Probes slots 0 through max_slots-1 using read-only CIP Get_Attributes_All routing.
    Returns list of discovered module dicts with slot numbers."""
    modules = []

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # Step 1: RegisterSession (0x0065)
            reg_req = struct.pack("<HHII8sIHH", 0x0065, 4, 0, 0, b"OT-RECON", 0, 1, 0)
            s.sendall(reg_req)
            reg_resp = s.recv(1024)
            if len(reg_resp) < 24:
                return []
            _, _, session_handle, status = struct.unpack_from("<HHII", reg_resp, 0)
            if status != 0:
                return []

            try:
                for slot in range(max_slots):
                    # Step 2: SendRRData (0x006F) with backplane route to Slot
                    # Route path: Port 1 (Backplane), Link Address = slot, Class 0x01, Instance 0x01
                    # Path bytes: [0x01, slot, 0x20, 0x01, 0x24, 0x01] (3 words = 6 bytes)
                    cip_payload = bytes([
                        0x01,              # Service: Get_Attributes_All
                        0x03,              # Request path size: 3 16-bit words
                        0x01, slot,        # Port segment: Port 1 (Backplane), Address = slot
                        0x20, 0x01,        # Logical segment: Class 0x01 (Identity)
                        0x24, 0x01,        # Logical segment: Instance 0x01
                    ])

                    # Encapsulation SendRRData data frame:
                    # Interface handle (4) = 0, Timeout (2) = 10, Item count (2) = 2
                    # Item 1: Null Address (type 0, len 0)
                    # Item 2: Connected/Unconnected Data (type 0x00B2, len = len(cip_payload))
                    encap_body = struct.pack(
                        "<IHHHHHH",
                        0, 10, 2,
                        0x0000, 0,
                        0x00B2, len(cip_payload)
                    ) + cip_payload

                    encap_hdr = struct.pack(
                        "<HHII8sI",
                        0x006F, len(encap_body), session_handle, 0, b"OT-RECON", 0
                    )
                    s.sendall(encap_hdr + encap_body)
                    resp = s.recv(2048)

                    if len(resp) < 24:
                        continue

                    r_cmd, r_len, _, r_status = struct.unpack_from("<HHII", resp, 0)
                    if r_status != 0 or len(resp) < 40:
                        continue

                    # Parse items in SendRRData response (offset 30 is where items start)
                    # 24 encap hdr + 4 interface + 2 timeout + 2 item count = 32
                    if len(resp) >= 36:
                        item_offset = 32
                        num_items = struct.unpack_from("<H", resp, 30)[0] if len(resp) >= 32 else 0
                        for _ in range(num_items):
                            if len(resp) < item_offset + 4:
                                break
                            itype, ilen = struct.unpack_from("<HH", resp, item_offset)
                            item_offset += 4
                            if itype == 0x00B2 and ilen >= 4:
                                cip_resp = resp[item_offset : item_offset + ilen]
                                reply_service = cip_resp[0]
                                gen_status = cip_resp[2]
                                if reply_service == 0x81 and gen_status == 0x00:
                                    # Success: Attributes follow from byte 4 (or 2+add_status_len)
                                    add_stat_words = cip_resp[3]
                                    attr_offset = 4 + (add_stat_words * 2)
                                    parsed = parse_identity_item(cip_resp[attr_offset:])
                                    if parsed:
                                        parsed["slot"] = slot
                                        modules.append(parsed)
                            item_offset += ilen
            finally:
                # Step 3: UnRegisterSession (0x0066)
                unreg_req = struct.pack("<HHII8sI", 0x0066, 0, session_handle, 0, b"OT-RECON", 0)
                try:
                    s.sendall(unreg_req)
                except OSError:
                    pass

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return modules
