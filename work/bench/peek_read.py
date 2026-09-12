#!/usr/bin/env python3
"""Read the peek service on the FLASHED bench BCM.

Wire format (built + verified in work/peek/):
    22 DE AD <A3> <A2> <A1> <A0>   ->   62 DE AD <4 bytes at 0xA3A2A1A0>

ACCEPTANCE ORDER -- do not skip, do not reorder:

  1. KNOWN-TRUTH control.  Peek 0x000DE278, which the owner backup
     (backups/.../cflash.bin) says is 70 E8 E0 00.  Ground truth external to
     this tool and impossible to fake by reasoning (AGENTS.md rule 31).
     If this fails, NOTHING else the service returns may be believed.

  2. OUT-OF-RANGE control.  Peek 0xFFFFFFFF, which must return the four 0xEE
     markers -- proving the range check fires instead of dereferencing.

  3. STOCK-PATH control.  A plain 22 0631 must still work, proving the hook
     did not displace OEM behaviour.

  4. Only then, live peeks.

Modes:
  python3 work/bench/peek_read.py accept          the 3 controls above
  python3 work/bench/peek_read.py read <hex-addr> [count]
  python3 work/bench/peek_read.py dump <hex-addr> <nbytes>
"""
import os
import socket
import struct
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
BACKUP = os.path.join(ROOT, "backups", "owner-backup-20260911T090300Z",
                      "cflash.bin")
IFACE = "can0"
TESTER = 0x726
ECU = 0x72E
MAGIC = 0xDEAD

NRC = {0x11: "serviceNotSupported", 0x13: "incorrectMessageLength",
       0x22: "conditionsNotCorrect", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x78: "responsePending"}


def open_sock():
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((IFACE,))
    s.settimeout(0.05)
    return s


def send(s, cid, data):
    d = bytes(data) + b"\x00" * (8 - len(data))
    s.send(struct.pack("=IB3x8s", cid, 8, d))


def drain(s, max_s=0.25):
    t0 = time.time()
    while time.time() - t0 < max_s:
        try:
            s.recv(16)
        except socket.timeout:
            return


def rx(s, timeout=0.7):
    out, t0 = [], time.time()
    while time.time() - t0 < timeout:
        try:
            f = s.recv(16)
        except socket.timeout:
            continue
        cid, dlc, data = struct.unpack("=IB3x8s", f)
        if (cid & 0x7FF) == ECU:
            out.append(data[:dlc])
    return out


def wake(s):
    for _ in range(25):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.2)
    drain(s)


def uds(s, body, timeout=0.8):
    """Send one request, reassemble a single- or multi-frame reply."""
    send(s, TESTER, [0x02, 0x3E, 0x80])
    time.sleep(0.04)
    drain(s, 0.08)
    send(s, TESTER, [len(body)] + list(body))
    frames = rx(s, timeout)
    if not frames:
        return None, "NO_RESPONSE"
    d = frames[0]
    pci = d[0] >> 4
    if pci == 0:
        n = d[0] & 0x0F
        return d[1:1 + n], None
    if pci == 1:
        total = ((d[0] & 0x0F) << 8) | d[1]
        buf = bytearray(d[2:])
        send(s, TESTER, [0x30, 0x00, 0x00])
        time.sleep(0.05)
        for f in rx(s, 0.8):
            if f[0] >> 4 == 2:
                buf += f[1:]
        return bytes(buf[:total]), None
    return None, "UNEXPECTED_PCI_%X" % pci


def peek(s, addr, want=4):
    body = [0x22, (MAGIC >> 8) & 0xFF, MAGIC & 0xFF,
            (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF, addr & 0xFF]
    resp, err = uds(s, body)
    if err:
        return None, err
    if resp[0] == 0x7F:
        n = resp[2] if len(resp) > 2 else 0
        return None, "NRC 0x%02X %s" % (n, NRC.get(n, "?"))
    if resp[0] != 0x62:
        return None, "unexpected SID 0x%02X" % resp[0]
    if len(resp) < 3 or ((resp[1] << 8) | resp[2]) != MAGIC:
        return None, "DID echo mismatch: %s" % resp[:3].hex()
    return resp[3:3 + want], None


def accept(s):
    fails = []

    def chk(name, ok, detail=""):
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                               ("  -- " + detail) if detail else ""))
        if not ok:
            fails.append(name)

    print("== 1. KNOWN-TRUTH control ==")
    addr = 0x000DE278
    truth = open(BACKUP, "rb").read()[addr:addr + 4]
    got, err = peek(s, addr)
    print("     backup says 0x%06X = %s" % (addr, truth.hex().upper()))
    print("     peek returns            %s"
          % (got.hex().upper() if got else "ERR " + str(err)))
    chk("peek matches the owner backup at 0x%06X" % addr, got == truth)

    # a second, different known-truth address -- one match could be luck
    addr2 = 0x00100000
    truth2 = open(BACKUP, "rb").read()[addr2:addr2 + 4]
    got2, err2 = peek(s, addr2)
    print("     backup says 0x%06X = %s   peek %s"
          % (addr2, truth2.hex().upper(),
             got2.hex().upper() if got2 else "ERR " + str(err2)))
    chk("peek matches the owner backup at 0x%06X" % addr2, got2 == truth2)

    print("\n== 2. OUT-OF-RANGE control (must NOT dereference) ==")
    got3, err3 = peek(s, 0xFFFFFFFF)
    print("     peek 0xFFFFFFFF -> %s"
          % (got3.hex().upper() if got3 else "ERR " + str(err3)))
    chk("out-of-range returns the EE marker", got3 == b"\xEE\xEE\xEE\xEE")

    print("\n== 3. STOCK-PATH control (OEM behaviour intact) ==")
    resp, err = uds(s, [0x22, 0x06, 0x31])
    ok = resp is not None and resp[0] == 0x62 and len(resp) == 4
    print("     22 0631 -> %s" % (resp.hex().upper() if resp else err))
    chk("stock single-DID read still works", ok)

    resp, err = uds(s, [0x22, 0x06, 0x31, 0x40, 0x1B])
    ok2 = resp is not None and resp[0] == 0x62
    print("     22 0631 401B -> %s" % (resp.hex().upper() if resp else err))
    chk("stock multi-DID read still works", ok2)

    print("\n" + "=" * 56)
    if fails:
        print("ACCEPTANCE FAILED: %s" % ", ".join(fails))
        print("=> the peek service is NOT trustworthy; believe nothing it returns")
        return 1
    print("ACCEPTANCE PASSED -- the peek service reads real memory")
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "accept"
    s = open_sock()
    print("waking...")
    wake(s)
    resp, err = uds(s, [0x22, 0xF1, 0x90])
    if resp is None:
        print("!! ECU silent -- INCONCLUSIVE, not a negative (rule 27)")
        sys.exit(2)
    print("liveness OK\n")

    if mode == "accept":
        sys.exit(accept(s))
    if mode == "read":
        addr = int(sys.argv[2], 16)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 4
        got, err = peek(s, addr, n)
        print("0x%08X: %s" % (addr, got.hex().upper() if got else "ERR " + str(err)))
        return
    if mode == "dump":
        addr, n = int(sys.argv[2], 16), int(sys.argv[3])
        out = bytearray()
        for off in range(0, n, 4):
            got, err = peek(s, addr + off)
            if not got:
                print("0x%08X: ERR %s" % (addr + off, err))
                break
            out += got
        for i in range(0, len(out), 16):
            print("0x%08X  %s" % (addr + i,
                                  " ".join("%02X" % b for b in out[i:i + 16])))
        return
    print("unknown mode %r" % mode)


if __name__ == "__main__":
    main()
