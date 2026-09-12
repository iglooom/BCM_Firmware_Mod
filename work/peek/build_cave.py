#!/usr/bin/env python3
"""Assemble the UDS peek cave + hook, round-tripped through Ghidra's VLE assembler.

WIRE FORMAT (bench-measured, not assumed -- work/bench/peek_carrier_raw.py):
    22 DE AD <A3> <A2> <A1> <A0>   ->   62 DE AD <4 bytes at 0xA3A2A1A0>

Round 1 REFUTED "22 <DID> <addr32>" as a trailing-byte extension: 5/5 NRC 0x31.
The NRC was requestOutOfRange, NOT incorrectMessageLength, because
FUN_0010B65E LOOPS over the request reading DID pairs.  Round 2 proved
multi-DID 0x22 IS served (22 0631 401B 4099 -> 62 ..., total=10), so the address
rides AS TWO SYNTHETIC DIDs and the stock parser is happy.

HOOK (from 280_peek_build_prereq.py):
    0x0010B764  (4B) e_cmpli cr0,r26,0xee00      <- displaced, replayed in cave
    0x0010B768  (2B) se_bne cr0,0x0010b7c4       <- return target
  at this point: r26 = the assembled DID, r27 = request length,
                 r28 = byte index of that DID (loop starts at 1, += 2 per DID)

The cave mimics the stock 0xEE00 case at 0x10B76A..0x10B7C0 exactly: append the
DID echo then the data bytes via FUN_00109916, then branch to the
"handled, continue" path at 0x10B992 -- with r28 advanced by 4 extra so the two
address-carrying DIDs are consumed.

SAFETY: read-only.  The address is range-checked to CFlash (<0x00180000) or
SRAM (0x40000000..0x40017FFF); anything else emits four 0xEE marker bytes
instead of dereferencing, so a bad address is a recognisable READING, never a
bus fault.

Scratch: 0x40011010..0x40011013 (proven-unused band per docs/scratch_ram.md;
clear of acc-fix 0x40011000 and rke-lock 0x40011001).
"""
import os
import json
import sys
import traceback
import pyghidra
import jpype

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.base.project import GhidraProject                       # noqa: E402
from ghidra.app.plugin.assembler import Assemblers                  # noqa: E402
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock  # noqa: E402
from ghidra.program.model.address import AddressSet                 # noqa: E402
from ghidra.app.cmd.disassemble import DisassembleCommand           # noqa: E402
from ghidra.program.model.lang import RegisterValue                 # noqa: E402
from java.math import BigInteger                                    # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
HERE = os.path.join(ROOT, "work", "peek")
os.makedirs(HERE, exist_ok=True)

# --- addresses -------------------------------------------------------
HOOK = 0x0010B764          # e_cmpli cr0,r26,0xee00
HOOK_LEN = 4
RET = 0x0010B768           # se_bne cr0,0x0010b7c4
CONT = 0x0010B992          # the stock "DID handled, continue" path
CAVE = 0x00118000          # inside the 0x1170F3 padding run, clear of acc-fix
MAGIC = 0xDEAD             # absent from the 492-entry identifier array (P1)
SCRATCH = 0x40011010       # 4 bytes
REQ = 0x4000538C
RESP = 0x400053A4
F_GETB = 0x001098DE        # (msg, i) -> byte
F_PUTB = 0x00109916        # (msg, b) -> ok

project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                    "BCM_C1MCA", False)
program = None
try:
    program = project.openProgram("/", "flash_merged.bin", False)
    af = program.getAddressFactory().getDefaultAddressSpace()

    def A(x):
        return af.getAddress(x)

    asm = Assemblers.getAssembler(program.getLanguage())
    JB = jpype.JArray(jpype.JByte)
    CTX = AssemblyPatternBlock.fromBytes(0, JB([0x20, 0, 0, 0]))

    def asm1(a, line):
        return bytes(int(x) & 0xFF for x in asm.assembleLine(A(a), line, CTX))

    def jb(bs):
        return JB([b if b < 128 else b - 256 for b in bs])

    # ---- sanity: the assembler reproduces the OEM hook instruction ----
    mem = program.getMemory()
    cur = bytearray(HOOK_LEN)
    for i in range(HOOK_LEN):
        cur[i] = mem.getByte(A(HOOK + i)) & 0xFF
    want = asm1(HOOK, "e_cmpli cr0,r26,0xee00")
    print("hook OEM bytes  : %s" % cur.hex().upper())
    print("assembler says  : %s" % want.hex().upper())
    assert bytes(cur) == want, "ASSEMBLER/OEM MISMATCH at the hook -- stop"
    print("  -> assembler round-trips the OEM instruction  OK\n")

    def setmsg(reg, addr):
        """Build a message-object pointer into rN."""
        return ["e_lis %s,0x%04X" % (reg, (addr >> 16) & 0xFFFF),
                "e_add16i %s,%s,0x%04X" % (reg, reg, addr & 0xFFFF)]

    P = []
    # r26=DID, r27=req length, r28=byte index of this DID
    # NOTE: the mnemonic is e_cmpl16i. WITH the trailing dot -- proven by
    # work/peek/asm_probe.py, which reproduced the OEM bytes at 0x10B7CC
    # (e_cmpl16i. r26,0xf3ff = 73DAABFF) byte-for-byte.  e_cmpli takes a
    # SCALED IMM8 and cannot encode 0xDEAD; "e_cmpl16i" without the dot is a
    # syntax error.  Both were tried and rejected by the assembler.
    P += ["e_cmpl16i. r26,0x%04X" % MAGIC, ("BNE", "NOTMAGIC")]
    # need bytes [r28+2 .. r28+5] -> require r28+6 <= r27
    P += ["e_addi r7,r28,0x6", "cmplw r7,r27", ("BGT", "NOTMAGIC")]

    # We are about to make e_bl calls, which clobber LR.  The enclosing
    # function FUN_0010B65E saved its own LR in its prologue and the stock
    # 0xEE00 case makes the same calls, so LR is free here -- but we must not
    # corrupt the caller's frame, so use our own stack frame for safety and
    # keep every value we need in the scratch cell rather than in volatiles.
    P += ["e_stwu r1,-0x10(r1)", "se_mflr r0", "e_stw r0,0xC(r1)"]

    # ---- pull the 4 address bytes out of the request into scratch ----
    for k in range(4):
        P += ["e_addi r4,r28,0x%X" % (2 + k), "se_extzh r4"]
        P += setmsg("r3", REQ)
        P += ["e_bl 0x%X" % F_GETB]
        P += setmsg("r4", SCRATCH)
        P += ["e_stb r3,0x%X(r4)" % k]

    # ---- echo the MAGIC DID, exactly as the stock 0xEE00 case does ----
    for b in ((MAGIC >> 8) & 0xFF, MAGIC & 0xFF):
        P += setmsg("r3", RESP) + ["e_li r4,0x%02X" % b,
                                   "e_bl 0x%X" % F_PUTB]

    # ---- range check the assembled address --------------------------
    P += setmsg("r4", SCRATCH) + ["e_lwz r9,0x0(r4)"]
    P += ["e_lis r7,0x0018", "cmplw r9,r7", ("BLT", "OKADDR")]   # CFlash
    P += ["e_lis r7,0x4000", "cmplw r9,r7", ("BLT", "BADADDR")]  # below SRAM
    P += ["e_lis r7,0x4001", "e_or2i r7,0x8000",
          "cmplw r9,r7", ("BGE", "BADADDR")]                     # >= 0x40018000

    # ---- OK: read 4 bytes and append them ---------------------------
    P += [("LBL", "OKADDR")]
    for k in range(4):
        P += setmsg("r4", SCRATCH) + ["e_lwz r9,0x0(r4)",
                                      "e_lbz r4,0x%X(r9)" % k]
        P += setmsg("r3", RESP) + ["e_bl 0x%X" % F_PUTB]
    P += [("B", "FINISH")]

    # ---- BAD: emit a recognisable marker, never dereference ---------
    P += [("LBL", "BADADDR")]
    for _ in range(4):
        P += setmsg("r3", RESP) + ["e_li r4,0xEE", "e_bl 0x%X" % F_PUTB]

    # ---- consume the two extra DIDs and rejoin the stock path -------
    # unwind our frame first (restore LR and SP) -- the stock path at CONT
    # expects the function's own frame, not ours.
    P += [("LBL", "FINISH"), "e_lwz r0,0xC(r1)", "se_mtlr r0",
          "e_add16i r1,r1,0x10", "se_addi r28,0x4", ("BA", CONT)]

    # ---- not our DID: replay the displaced compare and return -------
    P += [("LBL", "NOTMAGIC"), "e_cmpli cr0,r26,0xee00", ("BA", RET)]

    # ---------- two-pass assembly with label resolution ---------------
    def size(it, a):
        if isinstance(it, tuple):
            k = it[0]
            if k == "LBL":
                return 0
            if k == "BA":
                return len(asm1(a, "e_b 0x%X" % it[1]))
            if k == "B":
                return len(asm1(a, "e_b 0x%X" % (a + 0x40)))
            return len(asm1(a, "e_b%s cr0,0x%X" % (k.lower()[1:], a + 0x40)))
        return len(asm1(a, it))

    addrs, a, labels = [], CAVE, {}
    for it in P:
        if isinstance(it, tuple) and it[0] == "LBL":
            labels[it[1]] = a
        addrs.append(a)
        a += size(it, a)
    end = a

    out = bytearray()
    for it, a in zip(P, addrs):
        if isinstance(it, tuple):
            k = it[0]
            if k == "LBL":
                continue
            if k == "BA":
                line = "e_b 0x%X" % it[1]
            elif k == "B":
                line = "e_b 0x%X" % labels[it[1]]
            else:
                line = "e_b%s cr0,0x%X" % (k.lower()[1:], labels[it[1]])
        else:
            line = it
        out += asm1(a, line)
    cave = bytes(out)
    hook = asm1(HOOK, "e_b 0x%X" % CAVE)
    assert len(hook) == HOOK_LEN, "hook branch is %d bytes, need %d" % (
        len(hook), HOOK_LEN)
    print("cave: 0x%X .. 0x%X  (%d bytes)" % (CAVE, end, len(cave)))
    print("hook: 0x%X <- %s\n" % (HOOK, hook.hex().upper()))

    # ---------- round-trip: write, disassemble, print ----------------
    listing = program.getListing()
    ctxreg = program.getLanguage().getContextBaseRegister()
    pc = program.getProgramContext()
    val = RegisterValue(ctxreg, BigInteger("20000000", 16),
                        BigInteger("FFFFFFFF", 16))
    tid = program.startTransaction("peek-roundtrip")
    try:
        listing.clearCodeUnits(A(CAVE), A(CAVE + len(cave) - 1), False)
        pc.setRegisterValue(A(CAVE), A(CAVE + len(cave)), val)
        mem.setBytes(A(CAVE), jb(cave))
        listing.clearCodeUnits(A(HOOK), A(HOOK + len(hook) - 1), False)
        mem.setBytes(A(HOOK), jb(hook))
        for lo, hi in ((CAVE, CAVE + len(cave)), (HOOK, HOOK + len(hook))):
            listing.clearCodeUnits(A(lo), A(hi - 1), False)
            DisassembleCommand(A(lo), AddressSet(A(lo), A(hi - 1)),
                               True).applyTo(program)
        print("=== CAVE re-disassembled from the written bytes ===")
        n = 0
        for ins in listing.getInstructions(
                AddressSet(A(CAVE), A(CAVE + len(cave) - 1)), True):
            b = " ".join("%02X" % (x & 0xFF) for x in ins.getBytes())
            print("  %s %-12s %s" % (ins.getAddress(), b, ins))
            n += 1
        print("  (%d instructions)" % n)
        print("=== HOOK: %s ===" % listing.getInstructionAt(A(HOOK)))
    finally:
        program.endTransaction(tid, False)      # rollback: analysis only

    json.dump({"cave_addr": CAVE, "cave": list(cave),
               "hook_addr": HOOK, "hook": list(hook),
               "magic": MAGIC, "scratch": SCRATCH,
               "ret": RET, "cont": CONT,
               "oem_hook_bytes": list(cur)},
              open(os.path.join(HERE, "peek_blobs.json"), "w"), indent=1)
    print("\nsaved %s/peek_blobs.json" % HERE)
except Exception:
    traceback.print_exc()
finally:
    try:
        if program is not None:
            project.close()
    except Exception:
        pass
    sys.stdout.flush()
    sys.stderr.flush()
