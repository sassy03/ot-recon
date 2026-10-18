# tests/test_protocols.py
#
# Comprehensive tests for native OT protocol clients (CIP, S7comm, Modbus TCP).

import struct
from unittest.mock import patch, MagicMock

from ot_recon.core.protocols import cip, s7, modbus


# =====================================================================
# CIP / EtherNet/IP Tests
# =====================================================================

def test_cip_parse_identity_item_valid():
    # Construct raw CIP Identity Object payload
    # vendor_id=1 (Rockwell), device_type=0x0E (PLC), prod_code=100, rev=32.11, status=0x0060, serial=0x12345678
    # name="1756-L73"
    encap_sockaddr = b"\x01\x00" + (b"\x00" * 16)
    name_bytes = b"1756-L73"
    ident_body = struct.pack(
        "<HHHBBHI",
        1,       # Rockwell
        0x0E,    # PLC
        100,     # Product code
        32, 11,  # Rev 32.11
        0x0060,  # Status
        0x12345678,
    ) + bytes([len(name_bytes)]) + name_bytes + bytes([0x03])  # State 0x03

    parsed = cip.parse_identity_item(encap_sockaddr + ident_body)
    assert parsed["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert parsed["device_type"] == "Programmable Logic Controller"
    assert parsed["model"] == "1756-L73"
    assert parsed["firmware"] == "32.11"
    assert parsed["serial_number"] == "12345678"
    assert parsed["state"] == 3


def test_cip_parse_identity_item_too_short():
    assert cip.parse_identity_item(b"\x00" * 5) == {}


def test_cip_query_identity_success():
    name_bytes = b"1756-EN2T"
    ident_body = struct.pack(
        "<HHHBBHI",
        1, 0x0C, 50, 5, 8, 0x0020, 0xAABBCCDD
    ) + bytes([len(name_bytes)]) + name_bytes

    # Encapsulation ListIdentity response: 24 bytes header + item_count (2) + item type (2) + item len (2) + item body
    item_payload = b"\x01\x00" + (b"\x00" * 16) + ident_body
    resp_body = struct.pack("<HHH", 1, 0x000C, len(item_payload)) + item_payload
    encap_hdr = struct.pack("<HHII8sI", 0x0004, len(resp_body), 0, 0, b"OT-RECON", 0)
    fake_socket_data = encap_hdr + resp_body

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.recv.return_value = fake_socket_data

    with patch("socket.create_connection", return_value=mock_sock):
        res = cip.query_cip_identity("10.0.0.1")

    assert res["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert res["device_type"] == "Communications Adapter"
    assert res["model"] == "1756-EN2T"
    assert res["firmware"] == "5.08"


def test_cip_scan_backplane_discovers_slots():
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock

    # 1. RegisterSession response
    reg_resp = struct.pack("<HHII8sI", 0x0065, 4, 0x1234, 0, b"OT-RECON", 0) + struct.pack("<HH", 1, 0)

    # 2. Slot 0 response (Controller: 1756-L72)
    name0 = b"1756-L72"
    attr0 = struct.pack("<HHHBBHI", 1, 0x0E, 99, 30, 2, 0x0060, 0x11112222) + bytes([len(name0)]) + name0
    cip_reply0 = bytes([0x81, 0x00, 0x00, 0x00]) + attr0
    encap_body0 = struct.pack("<IHHHHHH", 0, 10, 2, 0, 0, 0x00B2, len(cip_reply0)) + cip_reply0
    encap_hdr0 = struct.pack("<HHII8sI", 0x006F, len(encap_body0), 0x1234, 0, b"OT-RECON", 0)
    slot0_resp = encap_hdr0 + encap_body0

    # 3. Slot 1 response (empty slot: generic status 0x05)
    cip_reply1 = bytes([0x81, 0x00, 0x05, 0x00])
    encap_body1 = struct.pack("<IHHHHHH", 0, 10, 2, 0, 0, 0x00B2, len(cip_reply1)) + cip_reply1
    encap_hdr1 = struct.pack("<HHII8sI", 0x006F, len(encap_body1), 0x1234, 0, b"OT-RECON", 0)
    slot1_resp = encap_hdr1 + encap_body1

    mock_sock.recv.side_effect = [reg_resp, slot0_resp, slot1_resp] + [slot1_resp] * 10

    with patch("socket.create_connection", return_value=mock_sock):
        modules = cip.scan_cip_backplane("10.0.0.1", max_slots=2)

    assert len(modules) == 1
    assert modules[0]["slot"] == 0
    assert modules[0]["model"] == "1756-L72"
    assert modules[0]["device_type"] == "Programmable Logic Controller"


# =====================================================================
# Siemens S7comm Tests
# =====================================================================

def test_s7_build_packets():
    cr = s7._build_tpkt_cotp_cr(rack=0, slot=1)
    assert cr[0] == 0x03  # TPKT version 3
    assert len(cr) == 4 + 18  # 4 TPKT + 18 COTP

    setup = s7._build_s7_setup_comm()
    assert b"\x32\x01" in setup  # S7comm Job

    szl = s7._build_s7_read_szl(0x0011)
    assert b"\x32\x07" in szl  # S7comm Userdata


def test_s7_query_info_success():
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock

    # 1. COTP CC (total len 7 = 4 + 3)
    cotp_cc = struct.pack(">BBH", 3, 0, 7) + bytes([2, 0xD0, 0x00])

    # 2. S7 Setup response (total len 25 = 4 + 3 + 18)
    setup_ack = struct.pack(">BBH", 3, 0, 25) + bytes([2, 0xF0, 0x80]) + (b"\x32\x03" + b"\x00" * 16)

    # 3. SZL 0x0011 response with 6ES7 511-1AK02-0AB0
    szl_data = (
        b"\x00" * 30 +
        b"6ES7 511-1AK02-0AB0 " +
        bytes([2, 9, 3, 0])  # FW 2.9.3
    )
    szl_resp = struct.pack(">BBH", 3, 0, 4 + len(szl_data)) + szl_data

    # 4. SZL 0x001C response with Project Name
    szl_1c = b"\x00" * 32 + b"Plant_Line_01_PLC               "
    szl_1c_resp = struct.pack(">BBH", 3, 0, 4 + len(szl_1c)) + szl_1c

    # 5. SZL 0x0132 response (Protection 1 = Open, Keyswitch 3 = REM-RUN)
    szl_132 = b"\x00" * 34 + bytes([1, 3]) + b"\x00" * 10
    szl_132_resp = struct.pack(">BBH", 3, 0, 4 + len(szl_132)) + szl_132

    # Provide chunks to _recv_tpkt: hdr first then payload
    mock_sock.recv.side_effect = [
        cotp_cc[:4], cotp_cc[4:],
        setup_ack[:4], setup_ack[4:],
        szl_resp[:4], szl_resp[4:],
        szl_1c_resp[:4], szl_1c_resp[4:],
        szl_132_resp[:4], szl_132_resp[4:],
    ]

    with patch("socket.create_connection", return_value=mock_sock):
        info = s7.query_s7_info("10.0.0.1")

    assert info["vendor"] == "Siemens"
    assert info["model_family"] == "S7-1500"
    assert "6ES7 511" in info["mlfb"]
    assert info["firmware"] == "V2.9.3"
    assert "Level 1" in info["protection_level"]
    assert "REMOTE RUN" in info["keyswitch_mode"]


# =====================================================================
# Modbus TCP Device Identification Tests
# =====================================================================

def test_modbus_query_device_id_success():
    obj0 = b"\x00" + bytes([18]) + b"Schneider Electric"
    obj1 = b"\x01" + bytes([12]) + b"BMX P34 2020"
    obj2 = b"\x02" + bytes([5]) + b"02.30"
    pdu = bytes([0x2B, 0x0E, 0x01, 0x83, 0x00, 0x00, 0x03]) + obj0 + obj1 + obj2
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.recv.return_value = mbap + pdu

    with patch("socket.create_connection", return_value=mock_sock):
        res = modbus.query_modbus_device_id("10.0.0.1")

    assert res["vendor"] == "Schneider Electric"
    assert res["product_code"] == "BMX P34 2020"
    assert res["firmware"] == "02.30"
