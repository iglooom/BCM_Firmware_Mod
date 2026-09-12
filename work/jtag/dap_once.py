#!/usr/bin/env python3
"""Direct CMSIS-DAP v2 JTAG driver -> MPC5607B OnCE TAP.

WHY THIS EXISTS (all three prior options are blocked):

  1. Stock OpenOCD 0.12 speaks CMSIS-DAP v2 but has NO e200 target, and more
     fundamentally cannot hold an aux-TAP transaction: it hardcodes
     SHIFT-DR -> EXIT1 -> PAUSE after every scan, and on MPC56xx passing
     through DR-PAUSE returns control to the JTAGC, tearing the OnCE sequence
     apart mid-transaction.  Measured: with no OCMD the OnCE DR reads
     0x07C1C01D; after any OCMD it reads 0x00000000.
  2. calandoa/openocd HAS a working `xpc56` e200z0 target - built fine here -
     but its CMSIS-DAP driver is HID-ONLY (2 hidapi calls, 0 libusb/bulk).
     Our probe exposes ONLY a v2 bulk interface (class 255, EP 0x04/0x85) and
     no HID interface at all, so that fork literally cannot see it.
  3. The probe firmware offers no v1/HID fallback mode.

So: drive the probe ourselves.  CMSIS-DAP's DAP_JTAG_Sequence command takes an
explicit list of (TMS, TDI, count, capture) tuples, which gives EXACT control
of the TAP state machine - including the ability to move SHIFT-DR -> EXIT1 ->
UPDATE-DR -> SELECT-DR without ever entering PAUSE.  That is precisely the
capability OpenOCD lacks and the MPC56xx aux TAP requires.

PROTOCOL NOTES (CMSIS-DAP v2, bulk):
  * command byte, then command-specific payload, on EP OUT; response on EP IN.
  * DAP_JTAG_Sequence (0x14): [0x14][count][seq_info, tdi_bytes...] x count
      seq_info: bit[5:0]=tck cycles (0 => 64), bit6=TMS value, bit7=capture TDO
  * DAP_Connect (0x02) with port=2 selects JTAG.
  * DAP_SWJ_Clock (0x11) sets clock in Hz (LE32).

MPC5607B specifics (NXP AN4365):
  * JTAGC IR = 5 bits.  ACCESS_AUX_TAP_ONCE = 0b10001 = 0x11.
  * After that opcode the e200z0 OnCE TAP owns the pins; its IR is 10 BITS.
  * OCMD layout: [9]=R/W [8]=GO [7]=EX [6:0]=RS

Read-only: this script only READS.  It never asserts GO/EX, so it cannot make
the core execute anything.
"""
import struct
import sys
import time

import usb.core
import usb.util

VID, PID = 0x2E8A, 0x000C
EP_OUT, EP_IN = 0x04, 0x85

# ---- TAP state machine: TMS sequences between states -----------------------
# Each entry: list of TMS bits to clock, LSB first in time order.
TMS_RESET = [1, 1, 1, 1, 1]            # any state -> TEST-LOGIC-RESET
TMS_RTI = [0]                          # TLR -> RUN-TEST/IDLE
TMS_RTI_TO_SHIFTIR = [1, 1, 0, 0]      # RTI -> SELECT-DR -> SELECT-IR -> CAPTURE-IR -> SHIFT-IR
TMS_RTI_TO_SHIFTDR = [1, 0, 0]         # RTI -> SELECT-DR -> CAPTURE-DR -> SHIFT-DR
TMS_EXIT_TO_RTI = [1, 1, 0]            # EXIT1 -> UPDATE -> RTI   (NO PAUSE!)


class Dap:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise SystemExit("CMSIS-DAP probe %04x:%04x not found" % (VID, PID))
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        usb.util.claim_interface(self.dev, 0)

    def xfer(self, data, rxlen=512, timeout=2000):
        self.dev.write(EP_OUT, bytes(data), timeout)
        return bytes(self.dev.read(EP_IN, rxlen, timeout))

    def info(self):
        r = self.xfer([0x00, 0xF0])          # DAP_Info: capabilities
        caps = r[2] if len(r) > 2 else 0
        return caps

    def connect_jtag(self):
        r = self.xfer([0x02, 0x02])          # DAP_Connect, port 2 = JTAG
        if r[1] != 0x02:
            raise SystemExit("DAP_Connect JTAG failed: %s" % r.hex())
        return True

    def disconnect(self):
        self.xfer([0x03])

    def set_clock(self, hz):
        self.xfer([0x11] + list(struct.pack("<I", hz)))

    # ---- the primitive everything is built from ----
    def jtag_sequence(self, seqs):
        """seqs = [(tms:int, tdi_bits:list[int], capture:bool), ...]
        Returns captured TDO bits as a flat list (only for captured seqs)."""
        payload = bytearray([0x14, len(seqs)])
        ncap_bits = 0
        for tms, bits, cap in seqs:
            n = len(bits)
            assert 1 <= n <= 64
            info = (n & 0x3F) | (0x40 if tms else 0) | (0x80 if cap else 0)
            payload.append(info)
            nbytes = (n + 7) // 8
            v = 0
            for i, b in enumerate(bits):
                if b:
                    v |= (1 << i)
            payload += v.to_bytes(nbytes, "little")
            if cap:
                ncap_bits += n
        r = self.xfer(payload)
        if r[0] != 0x14 or r[1] != 0x00:
            raise RuntimeError("DAP_JTAG_Sequence error: %s" % r.hex())
        out = r[2:]
        bits = []
        for byte in out:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits[:ncap_bits]

    # ---- convenience wrappers ----
    def tms(self, seq):
        self.jtag_sequence([(t, [0], False) for t in seq])

    def reset_tap(self):
        self.tms(TMS_RESET)
        self.tms(TMS_RTI)

    def shift(self, nbits, value, to_rti=True):
        """Shift nbits of `value` (LSB first), capturing TDO. Assumes the TAP is
        already in SHIFT-IR or SHIFT-DR. Leaves via EXIT1->UPDATE->RTI, which
        AVOIDS the DR-PAUSE that hands the MPC56xx TAP back to the JTAGC.

        ⚠ ATOMICITY: the whole scan - body bits, final bit with TMS=1, and the
        EXIT->UPDATE->RTI moves - is emitted as ONE DAP_JTAG_Sequence packet.
        An earlier version split it across three separate USB transfers, and the
        driver then returned a DIFFERENT value at the same point on every run
        (0xFFFFFFFF / 0x07C1C01D / 0x4AE43041).  Splitting a scan across packets
        lets TAP state drift between transfers; OpenOCD never does it.
        """
        bits = [(value >> i) & 1 for i in range(nbits)]
        seqs = []
        if nbits > 1:
            seqs.append((0, bits[:-1], True))
        seqs.append((1, [bits[-1]], True))      # last bit exits SHIFT -> EXIT1
        if to_rti:
            for t in TMS_EXIT_TO_RTI:
                seqs.append((t, [0], False))
        got = self.jtag_sequence(seqs)
        val = 0
        for i, b in enumerate(got[:nbits]):
            if b:
                val |= (1 << i)
        return val

    def ir(self, nbits, value, to_rti=True):
        """IR scan.  The navigation to SHIFT-IR is issued in the SAME packet as
        the shift itself, for the atomicity reason documented in shift()."""
        bits = [(value >> i) & 1 for i in range(nbits)]
        seqs = [(t, [0], False) for t in TMS_RTI_TO_SHIFTIR]
        if nbits > 1:
            seqs.append((0, bits[:-1], True))
        seqs.append((1, [bits[-1]], True))
        if to_rti:
            for t in TMS_EXIT_TO_RTI:
                seqs.append((t, [0], False))
        got = self.jtag_sequence(seqs)
        val = 0
        for i, b in enumerate(got[:nbits]):
            if b:
                val |= (1 << i)
        return val

    def dr(self, nbits, value=0, to_rti=True):
        """DR scan, navigation + shift in one packet (see shift())."""
        bits = [(value >> i) & 1 for i in range(nbits)]
        seqs = [(t, [0], False) for t in TMS_RTI_TO_SHIFTDR]
        if nbits > 1:
            seqs.append((0, bits[:-1], True))
        seqs.append((1, [bits[-1]], True))
        if to_rti:
            for t in TMS_EXIT_TO_RTI:
                seqs.append((t, [0], False))
        got = self.jtag_sequence(seqs)
        val = 0
        for i, b in enumerate(got[:nbits]):
            if b:
                val |= (1 << i)
        return val


def main():
    d = Dap()
    print("== CMSIS-DAP v2 direct driver ==")
    caps = d.info()
    print("   capabilities byte: 0x%02X (bit1 = JTAG)" % caps)
    d.connect_jtag()
    d.set_clock(1_000_000)
    print("   connected, JTAG, 1 MHz\n")

    # ---- control 1: JTAGC IDCODE must match what OpenOCD saw ----
    d.reset_tap()
    idcode = d.dr(32, 0)
    print("== control: JTAGC IDCODE ==")
    print("   0x%08X   %s" % (idcode, "MATCH" if idcode == 0x4AE43041 else
                              "MISMATCH - expected 0x4AE43041"))
    if idcode != 0x4AE43041:
        print("   driver disagrees with OpenOCD; stopping before drawing")
        print("   any conclusion (the instrument must be right first).")
        d.disconnect()
        return 1

    # ---- select the OnCE aux TAP ----
    print("\n== select OnCE (JTAGC IR = 0x11 = ACCESS_AUX_TAP_ONCE) ==")
    d.reset_tap()
    d.ir(5, 0x11)
    once_dr = d.dr(32, 0)
    print("   OnCE DR(32) after select = 0x%08X" % once_dr)

    # ---- now the thing OpenOCD could not do: a 10-bit IR on the aux TAP ----
    print("\n== 10-bit OnCE IR (OCMD) + 32-bit data pass, no DR-PAUSE ==")
    print("   OCMD [9]=R/W [8]=GO [7]=EX [6:0]=RS ; R/W=1 -> read")
    regs = [("OnCE JTAG_ID", 0x02), ("OSR", 0x62), ("DBSR", 0x14),
            ("DBCR0", 0x10), ("CPUSCR", 0x00)]
    for name, rs in regs:
        d.reset_tap()
        d.ir(5, 0x11)             # JTAGC: hand over to OnCE
        ack = d.ir(10, 0x200 | rs)  # OnCE: 10-bit IR = OCMD, read
        val = d.dr(32, 0)         # data pass
        print("   %-13s RS=0x%02X  ack=0x%03X  data=0x%08X" % (name, rs, ack, val))

    d.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
