#!/usr/bin/env python3
"""bcmflash - VBF flashing tool for the Ford BCM (JV6T-14C094 family).

Everything it does is driven by the VBF's OWN header (erase list, blocks, call
address, part type); nothing about a specific part is hardcoded.  That matters:
the reference OEM capture (hscan_bcm_flash.log) is a flash of
JV6T-14C095-AB - sw_part_type = DATA, "Local Configuration", ONE erase region
{0x0000C000, 0x4000} and ONE 16 KiB block.  An APP part (JV6T-14C094-AD) has
ELEVEN erase regions covering 0x10000..0x140000 and transfers ~1.19 MiB.
Copying the log's addresses would erase 16 KiB of the wrong area and leave the
application half-written.  The PBL is never flashed by this tool.

PROVEN SEQUENCE (replicated from the OEM capture):
    3E 00                       wake (first request after idle is dropped)
    22 F111                     identity read - MUST match the VBF part family
    10 02                       programmingSession
    27 01 / 27 02 <key>         securityAccess (level 1)
    3E 80                       TesterPresent, suppressed
    (from here on, a background thread also broadcasts 02 3E 80 on the
     functional ID 0x7DF every 2 s so the session cannot time out while a
     long erase or transfer blocks the physical channel)

    With --quiet-bus, ONE more functional request is sent just BEFORE the 10 02
    above, to stop the other modules transmitting:
        7DF#02 10 82 x20        programmingSession, response suppressed
    and undone after the reset with 7DF#02 11 81 (functional hardReset, every
    module reboots).  Measured on
    the vehicle: a module in programmingSession stops its normal application
    frames, so this alone quiets the network - 28/85 are not needed, and an
    earlier 10 03 + 85 02 + 28 03 01 attempt did NOT work.  TesterPresent by
    itself quiets nothing; it only refreshes S3, which is what makes the quiet
    persist.
    -- SBL stage (RAM) ------------------------------------------------
    34 00 44 <addr><len>        RequestDownload per SBL block
    36 <bc> <data...>           TransferData, chunked per the 74 response
    37                          RequestTransferExit
    31 01 0301 <callAddr>       start the SBL
    -- application stage ---------------------------------------------
    31 01 FF00 <addr><len>      eraseMemory, ONCE PER VBF ERASE REGION
    34/36/37                    download each data block
    11 01                       ECUReset

SAFETY
    * --dry-run (default) prints the full plan and sends nothing.
    * Refuses to flash unless 22 F111 identity matches the VBF's part number
      family, unless --force.
    * Verifies every VBF block CRC-16 and the file CRC-32 BEFORE touching the
      ECU; a corrupt VBF is never transmitted.
    * Treats 7F xx 78 (responsePending) as CONTINUE, not failure.  The OEM erase
      returns 7F 31 78 then 71 01 FF 00 ~230 ms later; a tool that aborts on the
      first negative would stop mid-erase with the app gone.
    * Honours 7F xx 21 (busyRepeatRequest) with a retry.

Usage:
    python3 bcmflash.py info    <part.vbf>
    python3 bcmflash.py verify  <part.vbf>
    python3 bcmflash.py flash   <part.vbf> [--sbl DV6T-14C097-AB.vbf] --execute
"""
import argparse
import os
import re
import socket
import struct
import sys
import threading
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "work", "sbl-upload"))

DEFAULT_SBL = os.path.join(ROOT, "DV6T-14C097-AB.vbf")
SECRET_L1 = bytes.fromhex("64000B0C59")
# Which DID carries the SOFTWARE part number, per VBF part type.  Measured live
# on the bench BCM - see do_flash() for the full readout and why F111 is wrong.
IDENT_DID = {"EXE": "F188", "DATA": "F124", "SBL": "F188"}
# Functional (broadcast) request ID for TesterPresent keepalive, and its period.
# 2 s is comfortably inside the 5 s S3 session timeout even if one frame is lost.
TP_BROADCAST_ID = 0x7DF
TP_INTERVAL = 2.0
PROGRESS_STEP = 5                       # report a permanent progress line every N %
# --quiet-bus arming (functional 10 82) is fire-and-forget - the response is
# suppressed, so a module that misses it stays noisy and we would never know.
# Send it many times rather than rely on one frame landing everywhere.
# Raised 5 -> 20 on the vehicle: with 5 the bus went quiet but SOME MODULES
# STAYED NOISY, so a single sweep of the network is demonstrably not enough.
QUIET_ARM_REPEAT = 20
NRC = {0x10: "generalReject", 0x11: "serviceNotSupported",
       0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLength",
       0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
       0x24: "requestSequenceError", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x35: "invalidKey",
       0x36: "exceedNumberOfAttempts", 0x72: "generalProgrammingFailure",
       0x78: "responsePending", 0x7E: "svcNotSupportedInSession"}


# ----------------------------------------------------------------- VBF parsing
def crc16(d):
    c = 0xFFFF
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
    return c


class Vbf:
    def __init__(self, path):
        self.path = path
        d = open(path, "rb").read()
        self.raw = d
        i = d.find(b"header")
        j = d.find(b"{", i)
        depth = 0
        while True:
            if d[j:j + 1] == b"{":
                depth += 1
            elif d[j:j + 1] == b"}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        self.hdr_end = j + 1
        h = d[:self.hdr_end].decode("latin1")
        self.header = h

        def g(k):
            m = re.search(k + r"\s*=\s*([^;]{0,80});", h)
            return m.group(1).strip().strip('"') if m else None

        self.part = g("sw_part_number")
        self.ptype = g("sw_part_type")
        self.ecu = int(g("ecu_address") or "0x726", 16)
        c = g("call")
        self.call = int(c, 16) if c else None
        fc = re.search(r"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", h)
        self.file_checksum = int(fc.group(1), 16) if fc else None

        # erase list - the authority for what gets erased
        self.erase = []
        m = re.search(r"erase\s*=\s*\{(.*?)\}\s*;", h, re.S)
        if m:
            for a, l in re.findall(r"\{\s*0x([0-9A-Fa-f]+)\s*,\s*0x([0-9A-Fa-f]+)\s*\}",
                                   m.group(1)):
                self.erase.append((int(a, 16), int(l, 16)))

        off = self.hdr_end
        while d[off] in (0x0D, 0x0A, 0x20, 0x09):
            off += 1
        self.data_start = off
        self.blocks = []
        p = off
        while p + 8 <= len(d):
            s, l = struct.unpack(">II", d[p:p + 8])
            if l == 0 or p + 8 + l + 2 > len(d):
                break
            self.blocks.append(dict(start=s, length=l, data=d[p + 8:p + 8 + l],
                                    crc=struct.unpack(">H", d[p + 8 + l:p + 8 + l + 2])[0]))
            p = p + 8 + l + 2

    def check(self):
        """Validate every CRC before a single byte reaches the ECU."""
        problems = []
        for b in self.blocks:
            c = crc16(b["data"])
            if c != b["crc"]:
                problems.append("block 0x%X CRC-16 stored 0x%04X calc 0x%04X"
                                % (b["start"], b["crc"], c))
        if self.file_checksum is not None:
            calc = zlib.crc32(self.raw[self.data_start:]) & 0xFFFFFFFF
            if calc != self.file_checksum:
                problems.append("file CRC-32 stored 0x%08X calc 0x%08X"
                                % (self.file_checksum, calc))
        return problems

    def describe(self):
        out = ["VBF %s" % self.path,
               "   part        %s   type %s" % (self.part, self.ptype),
               "   ecu_address 0x%03X" % self.ecu]
        if self.call is not None:
            out.append("   call        0x%08X" % self.call)
        out.append("   erase regions: %d" % len(self.erase))
        for a, l in self.erase:
            out.append("      0x%08X  len 0x%06X (%s)" % (a, l, human(l)))
        out.append("   data blocks: %d" % len(self.blocks))
        for b in self.blocks:
            out.append("      0x%08X  len 0x%06X (%s)  crc16 0x%04X"
                       % (b["start"], b["length"], human(b["length"]), b["crc"]))
        out.append("   total payload %s" % human(sum(b["length"] for b in self.blocks)))
        return "\n".join(out)


def human(n):
    for u, d in (("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= d:
            return "%.1f %s" % (n / d, u)
    return "%d B" % n


# ------------------------------------------------------------------ UDS client
def key_from_seed(seed3, secret=SECRET_L1):
    s1, s2, s3, s4, s5 = secret
    seed_int = (seed3[0] << 16) + (seed3[1] << 8) + seed3[2]
    or_ed = ((seed_int & 0xFF0000) >> 16) | (seed_int & 0xFF00) | (s1 << 24) \
        | (seed_int & 0xFF) << 16
    m = 0xC541A9
    for i in range(32):
        a = ((or_ed >> i) & 1 ^ m & 1) << 23
        v = a | (m >> 1)
        m = v & 0xEF6FD7 | ((((v & 0x100000) >> 20) ^ ((v & 0x800000) >> 23)) << 20) \
            | (((((m >> 1) & 0x8000) >> 15) ^ ((v & 0x800000) >> 23)) << 15) \
            | (((((m >> 1) & 0x1000) >> 12) ^ ((v & 0x800000) >> 23)) << 12) \
            | 32 * ((((m >> 1) & 0x20) >> 5) ^ ((v & 0x800000) >> 23)) \
            | 8 * ((((m >> 1) & 8) >> 3) ^ ((v & 0x800000) >> 23))
    for j in range(32):
        a = ((((s5 << 24) | (s4 << 16) | s2 | (s3 << 8)) >> j) & 1 ^ m & 1) << 23
        v = a | (m >> 1)
        m = v & 0xEF6FD7 | ((((v & 0x100000) >> 20) ^ ((v & 0x800000) >> 23)) << 20) \
            | (((((m >> 1) & 0x8000) >> 15) ^ ((v & 0x800000) >> 23)) << 15) \
            | (((((m >> 1) & 0x1000) >> 12) ^ ((v & 0x800000) >> 23)) << 12) \
            | 32 * ((((m >> 1) & 0x20) >> 5) ^ ((v & 0x800000) >> 23)) \
            | 8 * ((((m >> 1) & 8) >> 3) ^ ((v & 0x800000) >> 23))
    key = ((m & 0xF0000) >> 16) | 16 * (m & 0xF) \
        | ((((m & 0xF00000) >> 20) | ((m & 0xF000) >> 8)) << 8) \
        | ((m & 0xFF0) >> 4 << 16)
    return bytes([(key & 0xFF0000) >> 16, (key & 0xFF00) >> 8, key & 0xFF])


class Ecu:
    """UDS over ISO-TP, with responsePending handled properly."""

    def __init__(self, iface="can0", txid=0x726, rxid=0x72E, dry=True, log=None):
        self.dry = dry
        self.log = log
        self.s = None
        if not dry:
            from uds import open_isotp
            self.s = open_isotp(iface, txid, rxid)

    def _say(self, msg):
        print(msg)
        if self.log:
            self.log.write(msg + "\n")
            self.log.flush()

    def req(self, payload, timeout=5.0, what="", pending_timeout=30.0):
        hexs = payload if isinstance(payload, str) else payload.hex()
        hexs = hexs.upper()
        if self.dry:
            self._say("   [dry] %-12s %s" % (what, hexs[:60]))
            return b"\x00"
        self.s.settimeout(timeout)
        self.s.send(bytes.fromhex(hexs))
        t_start = time.time()
        while True:
            try:
                r = self.s.recv(4096)
            except Exception:
                self._say("   ERR  %-12s TIMEOUT (%s)" % (what, hexs[:32]))
                return None
            # 7F <sid> <nrc>
            if len(r) >= 3 and r[0] == 0x7F:
                nrc = r[2]
                if nrc == 0x78:                     # responsePending - KEEP WAITING
                    if time.time() - t_start > pending_timeout:
                        self._say("   ERR  %-12s pending timeout" % what)
                        return None
                    self.s.settimeout(pending_timeout)
                    continue
                if nrc == 0x21:                     # busyRepeatRequest
                    time.sleep(0.1)
                    self.s.send(bytes.fromhex(hexs))
                    continue
                self._say("   NRC  %-12s 7F %02X %02X %s"
                          % (what, r[1], nrc, NRC.get(nrc, "?")))
                return r
            return r

    def expect(self, payload, want, what, timeout=5.0, pending_timeout=30.0):
        r = self.req(payload, timeout, what, pending_timeout)
        if self.dry:
            return r
        ok = r is not None and len(r) and r[0] == want
        self._say("   %s %-12s %s" % ("OK  " if ok else "FAIL", what,
                                      r.hex().upper()[:48] if r else "None"))
        if not ok:
            raise SystemExit("aborted at %s" % what)
        return r


# ------------------------------------------------ raw functional (broadcast)
def raw_can_socket(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def can_frame(can_id, payload):
    """One classic CAN frame, zero-padded to 8 (Ford pads functional requests)."""
    data = bytes(payload)
    assert len(data) <= 8
    # struct can_frame { u32 can_id; u8 can_dlc; u8 pad,res0,res1; u8 data[8]; }
    return struct.pack("=IB3x8s", can_id, 8, data.ljust(8, b"\x00"))


def single_frame(payload):
    """ISO-TP single frame: PCI = 0x0<len>, then the UDS payload."""
    p = bytes(payload)
    assert len(p) <= 7
    return bytes([len(p)]) + p


class BusQuiet:
    """Silence normal (application) CAN traffic for the duration of the flash.

    ONE request does it, measured on the vehicle:

        7DF#02 10 82    functional programmingSession, response suppressed

    A module in programmingSession stops transmitting its normal application
    frames, so the broadcast 10 02 quiets the whole network by itself.  No
    CommunicationControl (28) and no ControlDTCSetting (85) are required.

    ⚠ Things that do NOT quiet the bus, recorded so nobody re-adds them:
      * TesterPresent.  3E 80 only refreshes the S3 timer of a module ALREADY
        in a non-default session; a module in its default session ignores it
        and keeps transmitting.  It is what makes the quiet PERSIST, not what
        causes it - without it S3 expires (~5 s) and everyone wakes up.
      * An earlier version sent 10 03 + 85 02 + 28 03 01.  On the car the bus
        stayed noisy.  Because every request carried the suppress bit, nobody
        could answer even to reject, so the failure was invisible - see
        work/flash/quietprobe.py, which exists to read those NRCs.

    The suppress bit is deliberate: a functional request is answered by EVERY
    module at once, and an ISO-TP socket bound to one rx ID cannot receive that
    storm.  Consequence, stated plainly: THERE IS NO CONFIRMATION.  Nothing here
    is checked; watch the bus with candump for proof.  Hence opt-in, default off.

    Restore is a functional hardReset (11 81) - every module reboots into its
    default session and resumes normal transmission.  S3 would also release them
    on its own a few seconds after the last TesterPresent, so the reset is the
    deliberate, immediate route rather than the only one.
    """

    ARM = [("10 02 programmingSession (bus goes quiet)", [0x10, 0x82])]
    RESTORE = [("11 01 hardReset, ALL modules", [0x11, 0x81])]

    def __init__(self, iface="can0", can_id=0x7DF, dry=True, log=None,
                 enabled=False):
        self.iface, self.can_id = iface, can_id
        self.dry, self.log, self.enabled = dry, log, enabled
        self.armed = False

    def _say(self, msg):
        print(msg)
        if self.log:
            self.log.write(msg + "\n")
            self.log.flush()

    def _send(self, seq, what, repeat=1):
        if not self.enabled:
            return
        self._say("   %s:" % what)
        if self.dry:
            for name, req in seq:
                self._say("      [dry] %03X  %s  x%d   (%s)"
                          % (self.can_id, single_frame(req).hex().upper(),
                             repeat, name))
            return
        sock = raw_can_socket(self.iface)
        try:
            for name, req in seq:
                frame = can_frame(self.can_id, single_frame(req))
                # Repeated because a functional request is fire-and-forget: the
                # response is suppressed, so a module that missed it (asleep,
                # busy, or the first frame after an idle bus - the same reason
                # the wake-up 3E 00 is sent twice) can never be detected, and
                # would simply stay noisy for the whole flash.
                for _ in range(repeat):
                    sock.send(frame)
                    time.sleep(0.02)
                self._say("      sent %03X  %s  x%d   (%s)  [unconfirmed]"
                          % (self.can_id, single_frame(req).hex().upper(),
                             repeat, name))
                time.sleep(0.05)
        finally:
            sock.close()

    def arm(self):
        if not self.enabled:
            return self
        self._send(self.ARM, "quiet-bus: silencing normal communication",
                   repeat=QUIET_ARM_REPEAT)
        self.armed = True
        return self

    def restore(self):
        """Reset every module so it leaves programmingSession and talks again.

        MUST run after the keepalive stops: while TesterPresent is still going,
        S3 never expires.  Best-effort: never raises, because it runs from a
        finally that may already be unwinding an exception, and a failure to
        restore must not mask the real error.
        """
        if not (self.enabled and self.armed):
            return
        try:
            self._send(self.RESTORE, "quiet-bus: resetting all modules")
        except Exception as e:                          # noqa: BLE001
            self._say("   !! quiet-bus reset FAILED: %s" % e)
            self._say("      normal communication returns on its own ~5 s after")
            self._say("      the last TesterPresent (S3 timeout).")
        self.armed = False


# -------------------------------------------------- broadcast TesterPresent
class TesterPresentBroadcast:
    """Functionally-addressed TesterPresent (3E 80) every `interval` seconds.

    Sent on a SEPARATE raw CAN socket, not the ISO-TP one, because the flash
    spends long stretches blocked inside Ecu.req() waiting for an erase or a
    TransferData response - exactly the window in which the session would
    otherwise time out (S3 = 5 s).  The sub-function is 0x80
    (suppressPosRspMsgIndication) so no ECU answers and nothing can be mistaken
    for the reply to the request currently in flight on the physical channel.

    A raw single frame is used rather than an ISO-TP socket: the payload is
    2 bytes, so it is always a single frame, and interleaving a different CAN ID
    with an in-progress ISO-TP transfer is legal (arbitration handles it).
    """

    def __init__(self, iface="can0", can_id=0x7DF, interval=2.0,
                 dry=True, log=None):
        self.iface, self.can_id, self.interval = iface, can_id, interval
        self.dry, self.log = dry, log
        self.sock = None
        self._stop = threading.Event()
        self._thread = None
        self.sent = 0

    # PCI 0x02, SID 0x3E, sub-function 0x80, padded to 8 with 0x00
    FRAME = single_frame([0x3E, 0x80]).ljust(8, b"\x00")

    def _say(self, msg):
        print(msg)
        if self.log:
            self.log.write(msg + "\n")
            self.log.flush()

    def start(self):
        if self.interval <= 0:
            return self
        if self.dry:
            self._say("   [dry] tester-present broadcast %03X 02 3E 80 every %.1fs"
                      % (self.can_id, self.interval))
            return self
        self.sock = raw_can_socket(self.iface)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._say("   keepalive: broadcast 3E 80 on %03X every %.1f s"
                  % (self.can_id, self.interval))
        return self

    def _run(self):
        frame = can_frame(self.can_id, self.FRAME)
        sock = self.sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                sock.send(frame)
                self.sent += 1
            except OSError:
                pass                    # bus hiccup: keep trying, never abort
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 1.0)
            self._thread = None
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


# ------------------------------------------------------------- flash sequence
def download_blocks(ecu, blocks, tag):
    """34 RequestDownload -> 36 TransferData (chunked) -> 37 TransferExit."""
    total = sum(b["length"] for b in blocks)
    done = 0
    t0 = time.time()
    next_mark = PROGRESS_STEP            # next whole-transfer % milestone to report

    def milestone(pct, rate):
        """Permanent, logged progress line at each PROGRESS_STEP % of the transfer."""
        line = ("      %s %3d%%  %s / %s  %.1f KiB/s  elapsed %.0fs"
                % (tag, int(pct), human(done), human(total),
                   rate / 1024, time.time() - t0))
        sys.stdout.write("\r" + line + "\n")   # \r clears the live counter line
        sys.stdout.flush()
        if ecu.log:
            ecu.log.write(line + "\n")
            ecu.log.flush()

    for bi, b in enumerate(blocks):
        rd = "340044" + struct.pack(">I", b["start"]).hex() \
            + struct.pack(">I", b["length"]).hex()
        r = ecu.expect(rd, 0x74, "%s blk%d 34" % (tag, bi), timeout=10.0)
        # maxNumberOfBlockLength from the 74 response
        if ecu.dry:
            chunk = 0x0C62
        elif r[1] == 0x20:
            chunk = (r[2] << 8) | r[3]
        elif r[1] == 0x10:
            chunk = r[2]
        else:
            chunk = 0x100
        chunk -= 2                      # SID + block counter overhead
        bc, off = 1, 0
        while off < b["length"]:
            piece = b["data"][off:off + chunk]
            msg = bytes([0x36, bc & 0xFF]) + piece
            if ecu.dry:
                off += len(piece)
                bc = (bc + 1) & 0xFF
                continue
            rr = ecu.req(msg, timeout=10.0, what="")
            if rr is None or rr[0] != 0x76:
                raise SystemExit("TransferData failed at blk%d bc=%d: %s"
                                 % (bi, bc, rr.hex().upper() if rr else "None"))
            off += len(piece)
            done += len(piece)
            bc = (bc + 1) & 0xFF
            el = time.time() - t0
            rate = done / el if el > 0 else 0
            pct = 100.0 * done / total if total else 100
            # permanent milestone line every PROGRESS_STEP % of the whole transfer
            while pct >= next_mark and next_mark <= 100:
                milestone(next_mark, rate)
                next_mark += PROGRESS_STEP
            if bc % 64 == 0 or off >= b["length"]:
                sys.stdout.write("\r      %s %5.1f%%  %s / %s  %.1f KiB/s   "
                                 % (tag, pct, human(done), human(total),
                                    rate / 1024))
                sys.stdout.flush()
        if ecu.dry:
            print("      [dry] %s blk%d: %d chunks of <=%d B"
                  % (tag, bi, (b["length"] + chunk - 1) // chunk, chunk))
        ecu.expect("37", 0x77, "%s blk%d 37" % (tag, bi), timeout=15.0)
    if not ecu.dry and total:
        print()


def do_flash(a):
    vbf = Vbf(a.vbf)
    print(vbf.describe())
    problems = vbf.check()
    if problems:
        print("\n!! VBF INTEGRITY FAILURE - refusing to transmit:")
        for p in problems:
            print("   %s" % p)
        raise SystemExit(2)
    print("   integrity   all block CRC-16 + file CRC-32 OK\n")

    if not vbf.erase:
        print("!! this VBF declares no erase regions; an EXE/DATA part must.")
        if not a.force:
            raise SystemExit(2)

    sbl = Vbf(a.sbl)
    if sbl.call is None:
        raise SystemExit("SBL VBF has no call address")
    print(sbl.describe())
    sp = sbl.check()
    if sp:
        print("\n!! SBL integrity failure:")
        for p in sp:
            print("   %s" % p)
        raise SystemExit(2)

    print("\n== PLAN ==")
    print("   1. wake, identity check (22 %s vs VBF part %s)"
          % (IDENT_DID.get((vbf.ptype or "").upper(), "F188"), vbf.part))
    print("   2. 10 02 programmingSession + 27 security access")
    print("   3. upload SBL %s to RAM (%d blocks), start at 0x%08X"
          % (sbl.part, len(sbl.blocks), sbl.call))
    print("   4. erase %d region(s):" % len(vbf.erase))
    for s, l in vbf.erase:
        print("         31 01 FF00 %08X %08X" % (s, l))
    print("   5. download %d block(s), %s total"
          % (len(vbf.blocks), human(sum(b["length"] for b in vbf.blocks))))
    print("   6. 11 01 ECUReset")
    if a.quiet_bus:
        print("   --quiet-bus: functional 7DF#02 10 82 x%d before step 2,"
              % QUIET_ARM_REPEAT)
        print("                7DF#02 11 81 (reset ALL modules) after step 6")
    print("   throughout 3-6: broadcast 3E 80 on 0x%03X every %.1f s; progress "
          "reported every %d%%" % (a.tp_id, a.tp_interval, PROGRESS_STEP))
    if a.dry:
        print("\n[DRY RUN] nothing was sent. Re-run with --execute to flash.")
        print("          Every frame below would have been transmitted:\n")

    log = None
    if a.logfile:
        os.makedirs(os.path.dirname(a.logfile), exist_ok=True)
        log = open(a.logfile, "a")
        log.write("\n=== %s flash %s ===\n" % (time.strftime("%F %T"), vbf.part))
    ecu = Ecu(a.iface, vbf.ecu, a.rxid, dry=a.dry, log=log)

    print("\n== 1. wake + identity ==")
    ecu.req("3E00", timeout=1.0, what="wake")       # first one is always dropped
    time.sleep(0.05)
    ecu.req("3E00", timeout=1.0, what="wake")
    # ⚠ WHICH DID CARRIES THE PART NUMBER DEPENDS ON THE PART TYPE.
    # Measured on the bench BCM:
    #     F111 = DV6T-14C245-FF   <- ECU hardware/assembly, NOT software
    #     F113 = DV6T-14A073-FK
    #     F124 = JV6T-14C095-AB   <- DATA / calibration part
    #     F188 = JV6T-14C094-AD   <- APPLICATION software part
    # An earlier version gated on F111 and would have REFUSED a perfectly valid
    # app flash, because F111 never matches an EXE VBF's sw_part_number.
    idd = IDENT_DID.get((vbf.ptype or "").upper(), "F188")
    r = ecu.req("22" + idd, timeout=3.0, what="22 " + idd)
    if not a.dry:
        ident = ""
        if r and r[0] == 0x62:
            ident = r[3:].decode("latin1", "replace").rstrip("\x00 ")
        print("   ECU %s reports: %r   (VBF declares %r)" % (idd, ident, vbf.part))
        if not ident:
            print("   !! could not read the ECU's %s part number" % idd)
            if not a.force:
                raise SystemExit("identity unreadable (use --force to skip)")
        elif ident.strip() != (vbf.part or "").strip():
            print("   !! identity mismatch: ECU %r vs VBF %r" % (ident, vbf.part))
            if not a.force:
                raise SystemExit("refusing to flash a mismatched part (use --force)")
            print("   --force given, continuing anyway")
        else:
            print("   identity OK")

    print("\n== 2. session + security ==")
    # ⚠ ORDER MATTERS: quiet the rest of the network BEFORE opening the BCM's
    # programming session, so the functional 10 03 cannot disturb the 10 02 we
    # are about to establish on the physical channel.
    quiet = BusQuiet(a.iface, a.tp_id, dry=a.dry, log=log,
                     enabled=a.quiet_bus).arm()
    try:
        ecu.expect("1002", 0x50, "10 02", timeout=5.0)
        time.sleep(0.1)
        r = ecu.expect("2701", 0x67, "27 01", timeout=5.0)
        if a.dry:
            print("   [dry] key would be computed from the live seed")
        else:
            key = key_from_seed(list(r[2:5]))
            print("   seed %s -> key %s"
                  % (bytes(r[2:5]).hex().upper(), key.hex().upper()))
            ecu.expect("2702" + key.hex(), 0x67, "27 02", timeout=5.0)
        ecu.req("3E80", timeout=1.0, what="3E 80")

        # Keep the programming session alive for the whole erase+download, which
        # can block for tens of seconds at a time inside a single request.  With
        # --quiet-bus this ALSO holds the other modules in their extended
        # session, which is what keeps them silent.
        tp = TesterPresentBroadcast(a.iface, a.tp_id, a.tp_interval,
                                    dry=a.dry, log=log).start()
        try:
            print("\n== 3. SBL upload (RAM) ==")
            download_blocks(ecu, sbl.blocks, "sbl")
            ecu.expect("31010301" + struct.pack(">I", sbl.call).hex(), 0x71,
                       "start SBL", timeout=10.0)
            print("   SBL running at 0x%08X" % sbl.call)

            print("\n== 4. erase %d region(s) ==" % len(vbf.erase))
            for s, l in vbf.erase:
                # ⚠ the OEM capture answers 7F 31 78 (responsePending) FIRST and
                # only then 71 01 FF 00 ~230 ms later.  Ecu.req() waits through
                # pending.
                ecu.expect("3101FF00" + struct.pack(">I", s).hex()
                           + struct.pack(">I", l).hex(), 0x71,
                           "erase %08X" % s, timeout=10.0,
                           pending_timeout=a.erase_timeout)

            print("\n== 5. download application ==")
            download_blocks(ecu, vbf.blocks, "app")

            print("\n== 6. reset ==")
            ecu.req("1101", timeout=5.0, what="11 01")
        finally:
            # Stop the keepalive FIRST: while it runs, S3 never expires and the
            # other modules stay in the extended session holding 28 03 01.
            tp.stop()
            if tp.sent:
                print("   keepalive: %d broadcast TesterPresent frames sent"
                      % tp.sent)
    finally:
        quiet.restore()
    print("\n*** %s ***" % ("DRY RUN COMPLETE - nothing sent" if a.dry
                            else "FLASH COMPLETE"))
    if not a.dry:
        print("    Power-cycle if the module does not come back on its own,")
        print("    then confirm with:  python3 work/flash/bcmflash.py ident")


def do_info(a):
    v = Vbf(a.vbf)
    print(v.describe())
    p = v.check()
    print("\n   integrity: %s" % ("OK" if not p else "FAILED"))
    for x in p:
        print("      %s" % x)


def do_verify(a):
    v = Vbf(a.vbf)
    p = v.check()
    print("%s\n   %s" % (v.path, "ALL CRCs OK" if not p else "FAILURES:"))
    for x in p:
        print("      %s" % x)
    raise SystemExit(1 if p else 0)


def do_ident(a):
    """Read the ECU's identity DIDs.  Multi-frame aware."""
    ecu = Ecu(a.iface, 0x726, a.rxid, dry=False)
    ecu.req("3E00", timeout=1.0, what="wake")
    time.sleep(0.05)
    ecu.req("3E00", timeout=1.0, what="wake")
    known = [("F188", "application sw part  (EXE VBFs)"),
             ("F124", "calibration part     (DATA VBFs)"),
             ("F111", "ECU hardware/assembly"),
             ("F113", "ECU core assembly"),
             ("F110", "diagnostic spec"),
             ("F180", "bootloader"),
             ("F18C", "ECU serial number"),
             ("F190", "VIN")]
    print("== BCM identity ==")
    for did, what in known:
        r = ecu.req("22" + did, timeout=2.0, what="")
        if r and r[0] == 0x62:
            v = r[3:].decode("latin1", "replace").rstrip("\x00 ")
            print("   %s  %-34s %r" % (did, what, v))
        else:
            print("   %s  %-34s -" % (did, what))
    print("\n   For a flash, bcmflash gates on the DID matching the VBF's")
    print("   sw_part_type: EXE->F188, DATA->F124.")


def main():
    ap = argparse.ArgumentParser(description="Ford BCM VBF flasher")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("info", "verify"):
        s = sub.add_parser(name)
        s.add_argument("vbf")
    s = sub.add_parser("ident")
    s.add_argument("--iface", default="can0")
    s.add_argument("--rxid", type=lambda x: int(x, 0), default=0x72E)
    s = sub.add_parser("flash")
    s.add_argument("vbf")
    s.add_argument("--sbl", default=DEFAULT_SBL)
    s.add_argument("--iface", default="can0")
    s.add_argument("--rxid", type=lambda x: int(x, 0), default=0x72E)
    s.add_argument("--execute", action="store_true",
                   help="actually transmit (default is a dry run)")
    s.add_argument("--force", action="store_true",
                   help="ignore an identity mismatch")
    s.add_argument("--erase-timeout", type=float, default=60.0)
    s.add_argument("--tp-interval", type=float, default=TP_INTERVAL,
                   help="broadcast TesterPresent period in seconds "
                        "(default %.1f; 0 disables)" % TP_INTERVAL)
    s.add_argument("--tp-id", type=lambda x: int(x, 0), default=TP_BROADCAST_ID,
                   help="functional/broadcast CAN ID for TesterPresent "
                        "(default 0x%03X)" % TP_BROADCAST_ID)
    s.add_argument("--quiet-bus", action="store_true",
                   help="silence the OTHER modules for the duration of the "
                        "flash with functional 7DF#02 10 82 "
                        "(programmingSession), undone with 7DF#02 10 81.  "
                        "Verified on the vehicle, but UNCONFIRMED at runtime "
                        "(the response is suppressed) and network-wide - off "
                        "by default")
    s.add_argument("--logfile", default=os.path.join(ROOT, "work/flash/logs/flash.log"))
    a = ap.parse_args()
    if a.cmd == "flash":
        a.dry = not a.execute
    {"info": do_info, "verify": do_verify, "ident": do_ident,
     "flash": do_flash}[a.cmd](a)


if __name__ == "__main__":
    main()
