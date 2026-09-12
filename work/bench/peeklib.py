#!/usr/bin/env python3
"""Fast reusable client for the UDS `peek` service (docs/peek_tool.md).

Why this exists: `peek_read.py`'s `uds()` sends a 3E 80 and sleeps 40 ms +
drains 80 ms before EVERY request, which caps it near 8 Hz.  That is fine for
`accept` but useless for correlating a cell against a ~100 ms event.  Here the
keepalive runs on its own thread and each peek is a single request/response
round trip on one persistent AF_CAN socket.

Instrument rules baked in (docs/peek_tool.md §4.2):
  * bounded drain -- never loop until a socket timeout on a live bus;
  * every response is matched against the DID echo, so a stale multi-frame
    reply cannot be read as the answer to the current question;
  * out-of-range reads return the EE marker and are surfaced, not hidden.

Use `Peeker` as a context manager:

    with Peeker() as p:
        p.assert_live()                 # known-truth + self-referential
        v = p.read32(0x40008E74)
"""
import os
import socket
import struct
import threading
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
BACKUP = os.path.join(ROOT, "backups", "owner-backup-20260911T090300Z",
                      "cflash.bin")
TESTER = 0x726
ECU = 0x72E
MAGIC = 0xDEAD
EE = b"\xEE\xEE\xEE\xEE"

NRC = {0x11: "serviceNotSupported", 0x13: "incorrectMessageLength",
       0x22: "conditionsNotCorrect", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x78: "responsePending"}


class PeekError(RuntimeError):
    pass


class Peeker:
    def __init__(self, iface="can0", keepalive=1.5):
        self.iface = iface
        self.keepalive = keepalive
        self.sock = None
        self._stop = threading.Event()
        self._thr = None
        self._lock = threading.Lock()
        self.n_reads = 0

    # ---------------------------------------------------------------- setup
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *a):
        self.close()

    def open(self):
        s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        s.bind((self.iface,))
        s.settimeout(0.02)
        self.sock = s
        self.wake()
        self._thr = threading.Thread(target=self._ka_loop, daemon=True)
        self._thr.start()

    def close(self):
        self._stop.set()
        if self._thr:
            self._thr.join(timeout=1.0)
        if self.sock:
            self.sock.close()
            self.sock = None

    def _ka_loop(self):
        while not self._stop.wait(self.keepalive):
            with self._lock:
                try:
                    self._send(TESTER, [0x02, 0x3E, 0x80])
                except OSError:
                    return

    # ------------------------------------------------------------- raw wire
    def _send(self, cid, data):
        d = bytes(data) + b"\x00" * (8 - len(data))
        self.sock.send(struct.pack("=IB3x8s", cid, 8, d))

    def _drain(self, max_s=0.05):
        """BOUNDED drain.  A live bus never goes quiet, so a drain that loops
        until timeout never returns (docs/peek_tool.md §4.2)."""
        t0 = time.time()
        while time.time() - t0 < max_s:
            try:
                self.sock.recv(16)
            except socket.timeout:
                return

    def wake(self, secs=5.0):
        t0 = time.time()
        while time.time() - t0 < secs:
            with self._lock:
                self._send(TESTER, [0x02, 0x3E, 0x80])
            time.sleep(0.2)
        with self._lock:
            self._drain(0.2)

    # ----------------------------------------------------------------- peek
    def read(self, addr, timeout=0.6):
        """Return 4 bytes at `addr`, or raise PeekError.

        The reply is only accepted if it is 62 DE AD ...., so a stale frame
        from a previous unanswered request cannot be mistaken for this one.
        """
        body = [0x22, (MAGIC >> 8) & 0xFF, MAGIC & 0xFF,
                (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF, addr & 0xFF]
        with self._lock:
            self._send(TESTER, [len(body)] + body)
            t0 = time.time()
            while time.time() - t0 < timeout:
                try:
                    f = self.sock.recv(16)
                except socket.timeout:
                    continue
                cid, dlc, data = struct.unpack("=IB3x8s", f)
                if (cid & 0x7FF) != ECU:
                    continue
                d = data[:dlc]
                if d[0] >> 4 != 0:          # only single frames are ours
                    continue
                n = d[0] & 0x0F
                r = d[1:1 + n]
                if not r:
                    continue
                if r[0] == 0x7F:
                    nrc = r[2] if len(r) > 2 else 0
                    raise PeekError("NRC 0x%02X %s"
                                    % (nrc, NRC.get(nrc, "?")))
                if r[0] != 0x62 or len(r) < 7:
                    continue
                if ((r[1] << 8) | r[2]) != MAGIC:
                    continue                # someone else's DID -- not ours
                self.n_reads += 1
                return r[3:7]
        raise PeekError("timeout at 0x%08X" % addr)

    def read32(self, addr):
        return int.from_bytes(self.read(addr), "big")

    def readb(self, addr):
        return self.read(addr)[0]

    # ------------------------------------------------------------- controls
    def assert_live(self, verbose=True):
        """Two controls, both mandatory before believing any reading.

        1. KNOWN TRUTH, external to this tool: flash bytes must equal the
           owner backup (AGENTS.md rule 31).
        2. SELF-REFERENTIAL: peek the UDS request buffer, whose contents are
           the very request doing the peeking.  A frozen snapshot, a cached
           read or an address-ignoring decode cannot produce this (rule 36 /
           docs/peek_tool.md §4.1).
        """
        truth = open(BACKUP, "rb").read()[0xDE278:0xDE278 + 4]
        got = self.read(0x000DE278)
        if got != truth:
            raise PeekError("KNOWN-TRUTH control FAILED: %s != %s"
                            % (got.hex(), truth.hex()))
        oor = self.read(0xFFFFFFFF)
        if oor != EE:
            raise PeekError("OUT-OF-RANGE control FAILED: %s" % oor.hex())
        a = 0x4000A9E5
        echo = self.read(a)
        if int.from_bytes(echo, "big") != a:
            raise PeekError("SELF-REFERENTIAL control FAILED: %s at 0x%08X"
                            % (echo.hex(), a))
        if verbose:
            print("controls: known-truth OK | out-of-range OK | "
                  "self-referential OK (0x%08X -> %s)" % (a, echo.hex().upper()))
        return True

    def rate(self, addr=0x40008E74, n=60):
        t0 = time.time()
        for _ in range(n):
            self.read(addr)
        dt = time.time() - t0
        return n / dt


if __name__ == "__main__":
    with Peeker() as p:
        p.assert_live()
        print("peek rate: %.1f Hz" % p.rate())
