# ot_recon/core/protocols/modbus.py
#
# Native, read-only Modbus TCP protocol implementation.
# Uses standard Function Code 43 / 14 (Read Device Identification) to extract
# Vendor Name, Product Code, Revision, and Application Name without brute-forcing registers.

import socket
import struct

OBJECT_NAMES = {
    0x00: "vendor",
    0x01: "product_code",
    0x02: "firmware",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model",
    0x06: "application_name",
}


def query_modbus_device_id(ip: str, port: int = 502, unit_id: int = 1, timeout: float = 3.0) -> dict:
    """Send Modbus Function Code 43 (0x2B) / MEI 14 (Read Device Identification) to port 502.
    Returns structured dictionary with vendor, model, and firmware version."""
    # Build Modbus MBAP + Encapsulated Interface Transport frame
    # Transaction ID = 1, Protocol = 0, Length = 5, Unit ID
    mbap_hdr = struct.pack(">HHHB", 0x0001, 0x0000, 0x0005, unit_id)
    # Function Code 43, MEI Type 14, Read Device ID code 1 (Basic), Object ID 0
    pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
    req = mbap_hdr + pdu

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            resp = s.recv(1024)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {}

    if len(resp) < 14:
        return {}

    # Check MBAP header and function code
    _, proto, length, r_unit = struct.unpack_from(">HHHB", resp, 0)
    if proto != 0 or len(resp) < 6 + length:
        return {}

    fc, mei_type = struct.unpack_from(">BB", resp, 7)
    if fc != 0x2B or mei_type != 0x0E:
        return {}

    read_dev_id, conformity, more, next_obj, num_objects = struct.unpack_from(">BBBBB", resp, 9)
    offset = 14

    info = {
        "type": "Field Device",
    }

    for _ in range(num_objects):
        if len(resp) < offset + 2:
            break
        obj_id, obj_len = struct.unpack_from(">BB", resp, offset)
        offset += 2
        if len(resp) < offset + obj_len:
            break
        val = resp[offset : offset + obj_len].decode("latin-1", errors="replace").strip()
        offset += obj_len

        field_key = OBJECT_NAMES.get(obj_id)
        if field_key:
            info[field_key] = val

    if "product_name" in info and "model" not in info:
        info["model"] = info["product_name"]

    return info if (info.get("vendor") or info.get("model")) else {}
