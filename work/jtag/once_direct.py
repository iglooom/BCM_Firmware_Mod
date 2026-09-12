#!/usr/bin/env python3
"""Read OnCE registers directly over CMSIS-DAP, bypassing xpc56.c entirely.

WHY: instrumentation showed the fork WRITES the 192-bit CPUSCR chain correctly
(the e_ori GPR sweep is textbook) but every READ returns all zeros.  The USB
transport is proven good (IDCODE reads correctly at 32..256-bit scan lengths,
192 included, repeatably) and the struct scan_field field order in this tree is
correct, so the C code looks right.  That leaves a HARDWARE/protocol question:
does the OnCE TAP return data for a read at all, and under what preconditions?

This drives the TAP by hand so nothing is hidden:
    JTAGC IR (5 bits)  = 0x11  ACCESS_AUX_TAP_ONCE     (AN4365 Table 2)
    OnCE  IR (10 bits) = command
    then a DR scan of the appropriate width.

Registers probed (e200z0 OnCE):
    0x00  DBCR0      32-bit   (known readable - the fork prints it fine)
    0x02  DBSR       32-bit   (ditto)
    0x10  CPUSCR    192-bit   (the one returning zeros)
    0x7E  EN_ONCE
    0x12  OCR

The DBCR0/DBSR reads are the POSITIVE CONTROL: the fork already reads those
successfully via the same helper, so if they return data here and CPUSCR does
not, the difference is specific to CPUSCR - not to reading in general.

SAFETY: this only shifts bits; it does not enter debug mode. But EN_ONCE may
be required before CPUSCR is accessible, which is itself part of the finding.
"""
import glob, sys, time

VID_MARK = ("2E8A", "000C")


def node():
    for n in sorted(glob.glob("/dev/hidraw*")):
        nm = n.split("/")[-1]
        try:
            u = open("/sys/class/hidraw/%s/device/uevent" % nm).read().upper()
        except OSError:
            continue
        if all(m in u for m in VID_MARK):
            return n
    return None


class Dap:
    def __init__(self, n):
        self.f = open(n, "rb+", buffering=0)

    def _x(self, payload):
        pkt = bytes([0x00]) + bytes(payload)
        pkt += b"\x00" * (65 - len(pkt))
        self.f.write(pkt)
        return self.f.read(64)

    def connect(self):
        r = self._x([0x02, 0x02])
        return r[1]

    def seq(self, items):
        """items: list of (tms, tdo_capture, nbits, data_bytes)."""
        req = [0x14, len(items)]
        for tms, cap, nbits, data in items:
            info = (nbits & 0x3F) | (0x40 if tms else 0) | (0x80 if cap else 0)
            req.append(info)
            req.extend(data)
        r = self._x(req)
        return r[2:]

    # --- TAP primitives -------------------------------------------------
    def tlr(self):
        self.seq([(1, 0, 6, [0x3F])])          # 6x TMS=1 -> Test-Logic-Reset

    def to_shift_ir(self):
        # TLR -> RTI -> SelDR -> SelIR -> CapIR -> ShiftIR
        self.seq([(0, 0, 1, [0x00]),           # TLR->RTI   (TMS=0)
                  (1, 0, 2, [0x03]),           # RTI->SelDR->SelIR (TMS=1,1)
                  (0, 0, 2, [0x00])])          # ->CapIR->ShiftIR  (TMS=0,0)

    def to_shift_dr(self):
        self.seq([(0, 0, 1, [0x00]),           # ->RTI
                  (1, 0, 1, [0x01]),           # ->SelDR
                  (0, 0, 2, [0x00])])          # ->CapDR->ShiftDR

    def shift(self, nbits, value, capture=True):
        """Shift nbits LSB-first; last bit with TMS=1 to exit. Returns int."""
        nbytes = (nbits + 7) // 8
        data = [(value >> (8 * i)) & 0xFF for i in range(nbytes)]
        out = b""
        if nbits > 1:
            head = nbits - 1
            hb = (head + 7) // 8
            out += self.seq([(0, capture, head, data[:hb] + [0] * (hb - len(data[:hb])))])
        last = (value >> (nbits - 1)) & 1
        out += self.seq([(1, capture, 1, [last])])
        # reassemble
        bits = 0
        idx = 0
        val = 0
        for byte in out:
            for b in range(8):
                if idx < nbits:
                    val |= ((byte >> b) & 1) << idx
                    idx += 1
        return val

    def rti(self):
        self.seq([(1, 0, 2, [0x03]),           # exit1 -> update
                  (0, 0, 1, [0x00])])          # -> RTI


def main():
    n = node()
    if not n:
        print("no probe")
        return 1
    d = Dap(n)
    print("connect(JTAG) -> 0x%02X" % d.connect())

    def jtagc_ir(v):
        d.tlr(); d.to_shift_ir(); d.shift(5, v); d.rti()

    def once_ir(v):
        jtagc_ir(0x11)                          # ACCESS_AUX_TAP_ONCE
        d.to_shift_ir(); r = d.shift(10, v); d.rti()
        return r

    def dr(nbits, v=0):
        d.to_shift_dr(); r = d.shift(nbits, v); d.rti()
        return r

    # Control 1: IDCODE must read correctly.
    jtagc_ir(0x01)
    idc = dr(32)
    print("\nCONTROL  IDCODE            : 0x%08X  %s"
          % (idc, "OK" if idc == 0x4AE43041 else "*** WRONG ***"))
    if idc != 0x4AE43041:
        print("  instrument not trustworthy - stopping.")
        return 1

    RW = 1 << 9
    for name, cmd, width in [("DBCR0", 0x00, 32),
                             ("DBSR",  0x02, 32),
                             ("OCR",   0x12, 32),
                             ("CPUSCR", 0x10, 192)]:
        once_ir(cmd | RW)
        v = dr(width)
        print("READ %-7s (ir=0x%03X, %3d bits) : 0x%0*X"
              % (name, cmd | RW, width, width // 4, v))

    print("\nNow with EN_ONCE (0x7E) asserted first:")
    once_ir(0x7E)
    for name, cmd, width in [("DBCR0", 0x00, 32), ("CPUSCR", 0x10, 192)]:
        once_ir(cmd | RW)
        v = dr(width)
        print("READ %-7s (ir=0x%03X, %3d bits) : 0x%0*X"
              % (name, cmd | RW, width, width // 4, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
