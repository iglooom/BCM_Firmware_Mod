#!/usr/bin/env python3
"""Minimal UDS-over-ISOTP client for the BCM on can0 using the Linux can-isotp
kernel module (CAN_ISOTP socket). Tester ID 0x726 (tx), ECU 0x72E (rx)."""
import socket, struct, sys, time

CAN_ISOTP = 6
SOL_CAN_ISOTP = 106
CAN_ISOTP_OPTS = 1
CAN_ISOTP_LL_OPTS = 5

def open_isotp(iface="can0", txid=0x726, rxid=0x72E, timeout=2.0):
    s = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, CAN_ISOTP)
    # default flags = 0; standard 11-bit addressing, padding off by default.
    # Enable TX padding with 0x00 (typical for Ford) via isotp options.
    # struct can_isotp_options: flags(u32) frame_txtime(u32) ext_address(u8)
    #   txpad_content(u8) rxpad_content(u8) rx_ext_address(u8) = 4+4+1+1+1+1 = 12
    CAN_ISOTP_TX_PADDING = 0x004
    CAN_ISOTP_RX_PADDING = 0x008
    flags = CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING
    opts = struct.pack("=IIBBBB", flags, 0, 0, 0x00, 0x00, 0)
    s.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_OPTS, opts)
    s.bind((iface, rxid, txid))  # (iface, rx_id, tx_id) for isotp
    s.settimeout(timeout)
    return s

def req(s, payload_hex, timeout=2.0, retries=2):
    data = bytes.fromhex(payload_hex)
    last=None
    for attempt in range(retries+1):
        s.send(data)
        try:
            s.settimeout(timeout)
            resp = s.recv(4096)
            return resp
        except socket.timeout:
            last="timeout"
            time.sleep(0.05)
    return None

if __name__ == "__main__":
    s = open_isotp()
    # 1. TesterPresent (send twice to wake if asleep)
    for _ in range(2):
        r = req(s, "3E00", timeout=1.0)
        print("TesterPresent ->", r.hex().upper() if r else None)
        time.sleep(0.05)
    # 2. ReadDataByID F111 (part number) as connectivity/identity check
    r = req(s, "22F111", timeout=2.0)
    print("RDBI F111    ->", r.hex().upper() if r else None)
    if r and r[0]==0x62:
        try: print("   ascii:", r[3:].decode('latin1'))
        except: pass
