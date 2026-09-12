#!/usr/bin/env python3
"""Assemble the remote-start TRIGGER cave, round-tripped through Ghidra's VLE
assembler (AGENTS.md rule 3: assemble -> write -> re-disassemble -> compare).

STRUCTURE (docs/rs_trigger_design.md Sec.4)
    peek's cave at 0x118000 is left BYTE-IDENTICAL.  Its NOTMAGIC tail
    currently reads:
            e_cmpli cr0,r26,0xee00      <- replayed displaced instruction
            e_b 0x0010B768              <- back to stock
    We retarget ONLY that final branch to this cave, so the chain is
            hook -> peek cave -> rs cave -> stock
    One hook, one displaced instruction, one rejoin (same shape as acc-fix +
    rke-lock sharing caves).

DEPTHS (separate MAGIC DIDs, verified FREE on hardware by 302_stock_did_probe)
    0xDE13  depth 1  APP_lock_request_input = 1 ; DAT_40008D75 = 1
    0xDE16  depth 2  APP_rke_command_code = 0x1808 ; valid flag = 1
    0xDE2C  depth 3  APP_power_mode = 4 ; dirty flags 0xFF x3

Each replies  62 <MAGIC> 00  (one status byte) using the SAME response
accessor peek uses, then rejoins the stock "DID handled, continue" path.

SAFETY
  * every store targets ONE named absolute cell -- no computed/indexed store,
    so a wrong address cannot scribble a range;
  * no store happens before the MAGIC compare matches;
  * anything that is not one of our three MAGICs replays the displaced
    e_cmpli and returns to stock, byte-for-byte as peek does.
"""
import os
import sys
import json
import traceback

import pyghidra
import jpype

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.base.project import GhidraProject                          # noqa: E402
from ghidra.app.plugin.assembler import Assemblers                     # noqa: E402
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock  # noqa: E402
from ghidra.program.model.address import AddressSet                    # noqa: E402
from ghidra.app.cmd.disassemble import DisassembleCommand              # noqa: E402
from ghidra.program.model.lang import RegisterValue                    # noqa: E402
from java.math import BigInteger                                       # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
HERE = os.path.join(ROOT, "work", "rs-trigger")
os.makedirs(HERE, exist_ok=True)

# --- geometry ---------------------------------------------------------
HOOK = 0x0010B764          # e_cmpli cr0,r26,0xee00  (peek already hooks it)
RET = 0x0010B768           # stock: se_bne cr0,0x0010b7c4
CONT = 0x0010B992          # stock "DID handled, continue"
PEEK_CAVE = 0x00118000
CAVE = 0x00119000          # ours -- inside the 0x1170F3 FF run, sum8-covered
RESP = 0x400053A4          # response message object
F_PUTB = 0x00109916        # append-byte accessor
# 4 bytes of proven-unused scratch, clear of acc-fix 0x40011000,
# rke-lock 0x40011001 and peek 0x40011010..13 (docs/scratch_ram.md)
SCRATCH = 0x40011020

# --- targets (all re-asserted below against the design doc) -----------
T_LOCK_REQ = 0x40008D2C    # APP_lock_request_input
T_ARM = 0x40008D75         # DAT_40008D75 -- the (c)-confidence arming flag
T_RKE_CODE = 0x40002DA2    # APP_rke_command_code (halfword)
# ⚠ THE ANNOUNCE VALUE IS 0xFF, NOT 1.
# 0x40003F53 is a Volcano DIRTY-FLAG BYTE, not a boolean.  The real receive
# path (APP_rke_code_commit) does:
#     0x058568  se_bmaski r0,0x8     ; r0 = 0xFF  -- ALL eight flag bits
#     0x05856A  e_stb r0,0x51(r30)   ; 0x40003F53 = 0xFF
#     0x05856E  e_sth r3,0x82(r31)   ; 0x40002DA2 = code
# Consumers call VOL_test_and_clear_dirty(&flag, n) which tests mask 0x80>>n:
#     0x0AEEDA  n=2 -> mask 0x20   <- THE REMOTE-START CONSUMER
#     0x099308  n=1 -> mask 0x40   <- RKE one-hot demux (not RS)
# Depth 2 wrote 1 = bit index 7, which NO consumer reads: 0x01 & 0x20 == 0.
# That is exactly why the injected code persisted for minutes on the vehicle
# and nothing ever fired (vehicle_session_1.md Sec.9.2).
T_RKE_VALID = 0x40003F53   # Volcano dirty-flag byte -- write 0xFF
RKE_ANNOUNCE = 0xFF
T_POWER_MODE = 0x40001D85  # APP_power_mode
T_DIRTY = (0x40003EB6, 0x40003EB7, 0x40003EB8)

# --- depth 4 (vehicle_session_1.md Sec.7.5/7.6) ----------------------
# FUN_000AD97C sets bit 27 of the gate word ITSELF when
#     ((*0x4000967C >> 0x1A) & 3) == 1   AND   *(u8*)0x400095E1 == 1
# so we set those two preconditions and let the firmware's own legitimate
# path raise bit 27 and tear it down on its own schedule, instead of
# fighting the 44 writers of 0x40009680.
T_SUBSTATE = 0x4000967C    # +0x90, sub-state word; bits[26:27] must be 1
T_FLAG = 0x400095E1        # param_1+5, PROVEN by 333_param1_fallthrough.py
SUB_KEEP = 0xF3FFFFFF      # mask the firmware itself uses
SUB_SET = 0x04000000       # sub-state = 1

RKE_ENUM8 = 0x1808         # the exact halfword the bench measured

DEPTHS = [
    ("DEPTH1", 0xDE13),
    ("DEPTH2", 0xDE16),
    ("DEPTH3", 0xDE2C),
    ("DEPTH4", 0xDE38),
    ("DEPTH5", 0xDE4A),
]


def main():
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", False)
    program = None
    try:
        program = project.openProgram("/", "flash_merged.bin", False)
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        listing = program.getListing()

        def A(x):
            return af.getAddress(x)

        asm = Assemblers.getAssembler(program.getLanguage())
        JB = jpype.JArray(jpype.JByte)
        CTX = AssemblyPatternBlock.fromBytes(0, JB([0x20, 0, 0, 0]))

        def asm1(a, line):
            return bytes(int(x) & 0xFF for x in asm.assembleLine(A(a), line, CTX))

        def jb(bs):
            return JB([b if b < 128 else b - 256 for b in bs])

        # ---- GATE: assembler must reproduce the OEM hook instruction ----
        cur = bytes(mem.getByte(A(HOOK + i)) & 0xFF for i in range(4))
        want = asm1(HOOK, "e_cmpli cr0,r26,0xee00")
        print("hook OEM bytes : %s" % cur.hex().upper())
        print("assembler says : %s" % want.hex().upper())
        assert cur == want, "ASSEMBLER/OEM MISMATCH at hook -- stop (rule 37)"
        print("  -> assembler round-trips the OEM instruction  OK\n")

        # ---- GATE: the cave region must be virgin 0xFF padding ----------
        blank = [i for i in range(0x400)
                 if (mem.getByte(A(CAVE + i)) & 0xFF) != 0xFF]
        assert not blank, "cave 0x%X not blank at +0x%X" % (CAVE, blank[0])
        print("cave 0x%06X: 0x400 bytes verified 0xFF (free)\n" % CAVE)

        def imm32(reg, val):
            """Build a 32-bit constant into reg."""
            return ["e_lis %s,0x%04X" % (reg, (val >> 16) & 0xFFFF),
                    "e_or2i %s,0x%04X" % (reg, val & 0xFFFF)]

        def setaddr(reg, addr):
            """Build an absolute address into reg.

            ⚠ `e_add16i` takes a **SIGNED** imm16 (-0x8000..0x7FFF).  For any
            address whose low half is >= 0x8000 (here APP_lock_request_input
            0x40008D2C and DAT_40008D75) a plain `e_add16i reg,reg,0x8D2C` is
            REJECTED by the assembler:
                "Value ...8D:2C is not valid for [ins(0,15), signed ...]"
            The fix is the standard lis/addi sign-compensation: bump the high
            half by 1 and add the negative low half.  peek's cave never hit
            this because all four of its addresses have low halves < 0x8000.
            (AGENTS.md rule 37 -- the assembler's rejection is the evidence.)
            """
            lo = addr & 0xFFFF
            if lo >= 0x8000:
                hi = ((addr >> 16) + 1) & 0xFFFF
                slo = lo - 0x10000
                return ["e_lis %s,0x%04X" % (reg, hi),
                        "e_add16i %s,%s,-0x%X" % (reg, reg, -slo)]
            return ["e_lis %s,0x%04X" % (reg, (addr >> 16) & 0xFFFF),
                    "e_add16i %s,%s,0x%04X" % (reg, reg, lo)]

        def store_imm8(addr, val, areg="r4", vreg="r3"):
            """*(u8*)addr = val  -- one named cell, no indexing."""
            return (setaddr(areg, addr)
                    + ["e_li %s,0x%02X" % (vreg, val),
                       "e_stb %s,0x0(%s)" % (vreg, areg)])

        # ---- GATE: prove setaddr()'s arithmetic by DISASSEMBLING it ------
        # Rule 34/37: do not trust the sign-compensation reasoning; assemble
        # it, read the operands back, and reconstruct the address.
        print("=== setaddr() self-check (esp. the signed-imm16 cases) ===")
        probe = 0x11A000            # scratch area, rolled back below
        ok_all = True
        tid0 = program.startTransaction("setaddr-selfcheck")
        try:
            for nm, tgt in (("lock_req", T_LOCK_REQ), ("arm", T_ARM),
                            ("rke_code", T_RKE_CODE), ("power_mode", T_POWER_MODE),
                            ("dirty0", T_DIRTY[0]), ("resp", RESP)):
                lines = setaddr("r4", tgt)
                blob = b""
                aa = probe
                for ln in lines:
                    bs = asm1(aa, ln)
                    blob += bs
                    aa += len(bs)
                listing.clearCodeUnits(A(probe), A(probe + len(blob) - 1), False)
                pc0 = program.getProgramContext()
                v0 = RegisterValue(program.getLanguage().getContextBaseRegister(),
                                   BigInteger("20000000", 16),
                                   BigInteger("FFFFFFFF", 16))
                pc0.setRegisterValue(A(probe), A(probe + len(blob)), v0)
                mem.setBytes(A(probe), jb(blob))
                listing.clearCodeUnits(A(probe), A(probe + len(blob) - 1), False)
                DisassembleCommand(
                    A(probe), AddressSet(A(probe), A(probe + len(blob) - 1)),
                    True).applyTo(program)
                ins = [listing.getInstructionAt(A(probe))]
                ins.append(ins[0].getNext())
                hi = int(ins[0].getScalar(1).getValue()) & 0xFFFF
                lo = int(ins[1].getScalar(2).getValue())
                got = ((hi << 16) + lo) & 0xFFFFFFFF
                good = got == tgt
                ok_all &= good
                print("   %-11s want 0x%08X  lis 0x%04X + addi %-8s = 0x%08X  %s"
                      % (nm, tgt, hi, hex(lo), got, "OK" if good else "*** WRONG ***"))
        finally:
            program.endTransaction(tid0, False)
        assert ok_all, "setaddr() arithmetic is wrong -- stop"
        print("   -> all address constructions verified by disassembly\n")

        def store_imm16(addr, val, areg="r4", vreg="r3"):
            return (setaddr(areg, addr)
                    + imm32(vreg, val)
                    + ["e_sth %s,0x0(%s)" % (vreg, areg)])

        P = []

        # r26 = assembled DID, r27 = request length, r28 = byte index
        for name, magic in DEPTHS:
            P += ["e_cmpl16i. r26,0x%04X" % magic, ("BEQ", name)]
        P += [("B", "NOTOURS")]

        # ---------- depth bodies ----------
        # Each makes e_bl calls (LR clobber) -> own frame, save LR.
        # No store happens before a MAGIC compare has matched.

        # ---------- DEPTH 1 ----------
        P += [("LBL", "DEPTH1"), "e_stwu r1,-0x10(r1)", "se_mflr r0",
              "e_stw r0,0xC(r1)"]
        P += store_imm8(T_LOCK_REQ, 1)
        P += store_imm8(T_ARM, 1)
        P += imm32("r5", 0xDE13)
        P += [("B", "REPLY")]

        # ---------- DEPTH 2 ----------
        P += [("LBL", "DEPTH2"), "e_stwu r1,-0x10(r1)", "se_mflr r0",
              "e_stw r0,0xC(r1)"]
        P += store_imm16(T_RKE_CODE, RKE_ENUM8)
        P += store_imm8(T_RKE_VALID, 1)
        P += imm32("r5", 0xDE16)
        P += [("B", "REPLY")]

        # ---------- DEPTH 3 ----------
        P += [("LBL", "DEPTH3"), "e_stwu r1,-0x10(r1)", "se_mflr r0",
              "e_stw r0,0xC(r1)"]
        P += store_imm8(T_POWER_MODE, 4)
        for d in T_DIRTY:
            P += store_imm8(d, 0xFF)
        P += imm32("r5", 0xDE2C)
        P += [("B", "REPLY")]

        # ---------- DEPTH 4 ----------
        # Read-modify-write the sub-state field to 1 using the firmware's own
        # mask, then raise the flag.  FUN_000AD97C does the rest.
        P += [("LBL", "DEPTH4"), "e_stwu r1,-0x10(r1)", "se_mflr r0",
              "e_stw r0,0xC(r1)"]
        P += setaddr("r4", T_SUBSTATE)
        P += ["e_lwz r3,0x0(r4)"]
        P += imm32("r5", SUB_KEEP) + ["se_and r3,r5"]
        P += imm32("r5", SUB_SET) + ["se_or r3,r5"]
        P += ["e_stw r3,0x0(r4)"]
        P += store_imm8(T_FLAG, 1)
        P += imm32("r5", 0xDE38)
        P += [("B", "REPLY")]

        # ---------- DEPTH 5 ----------
        # Depth 2 done RIGHT: write the code AND announce its arrival with the
        # same value the real receive path uses (0xFF), in the same ORDER
        # (flag first, then code -- 0x05856A precedes 0x05856E).  Ordering is
        # cheap insurance: a consumer that samples between the two stores then
        # sees "announced but stale code" rather than "new code, no announce".
        P += [("LBL", "DEPTH5"), "e_stwu r1,-0x10(r1)", "se_mflr r0",
              "e_stw r0,0xC(r1)"]
        P += store_imm8(T_RKE_VALID, RKE_ANNOUNCE)
        P += store_imm16(T_RKE_CODE, RKE_ENUM8)
        P += imm32("r5", 0xDE4A)
        P += [("B", "REPLY")]

        # ---------- reply: 62 <MAGIC-hi> <MAGIC-lo> 00 ----------
        # ⚠ The MAGIC is held in SCRATCH RAM, not a register.  The first build
        # carried it in r5 across the e_bl calls to the append accessor; r5 is
        # a VOLATILE register (PPC EABI r3-r12) so the callee clobbered it and
        # the echo came back `62 DE 29` instead of `62 DE 13`.  read_did() then
        # rejected the reply and a WORKING trigger reported "no response"
        # (vehicle_session_1.md Sec.4.2).  peek never hit this because it keeps
        # its value in a scratch cell -- do the same.
        P += [("LBL", "REPLY")]
        P += setaddr("r4", SCRATCH) + ["e_stw r5,0x0(r4)"]
        P += setaddr("r4", SCRATCH) + ["e_lwz r5,0x0(r4)",
                                       "e_srwi r4,r5,0x8", "se_extzb r4"]
        P += setaddr("r3", RESP) + ["e_bl 0x%X" % F_PUTB]
        P += setaddr("r4", SCRATCH) + ["e_lwz r5,0x0(r4)",
                                       "e_andi. r4,r5,0xFF"]
        P += setaddr("r3", RESP) + ["e_bl 0x%X" % F_PUTB]
        P += ["e_li r4,0x00"]
        P += setaddr("r3", RESP) + ["e_bl 0x%X" % F_PUTB]
        # unwind our frame, then rejoin stock "handled, continue"
        P += ["e_lwz r0,0xC(r1)", "se_mtlr r0", "e_add16i r1,r1,0x10",
              ("BA", CONT)]

        # ---------- not ours: replay displaced insn, back to stock -------
        P += [("LBL", "NOTOURS"), "e_cmpli cr0,r26,0xee00", ("BA", RET)]

        # ---------- two-pass assembly ------------------------------------
        def size(it, a):
            if isinstance(it, tuple):
                k = it[0]
                if k == "LBL":
                    return 0
                if k == "BA":
                    return len(asm1(a, "e_b 0x%X" % it[1]))
                if k == "B":
                    return len(asm1(a, "e_b 0x%X" % (a + 0x200)))
                return len(asm1(a, "e_b%s cr0,0x%X"
                                % (k.lower()[1:], a + 0x200)))
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
        print("rs cave: 0x%X .. 0x%X  (%d bytes)" % (CAVE, end, len(cave)))

        # ---- retarget peek's NOTMAGIC tail branch to us -----------------
        # find the peek cave's final `e_b RET` and repoint it at CAVE
        pb = json.load(open(os.path.join(ROOT, "work", "peek",
                                         "peek_blobs.json")))
        peek_bytes = bytes(pb["cave"])
        tail = asm1(PEEK_CAVE + len(peek_bytes) - 4, "e_b 0x%X" % RET)
        idx = peek_bytes.rfind(tail)
        assert idx >= 0, "could not locate peek's tail branch to 0x%X" % RET
        tail_addr = PEEK_CAVE + idx
        newtail = asm1(tail_addr, "e_b 0x%X" % CAVE)
        assert len(newtail) == len(tail), "tail branch size changed"
        print("peek tail branch @0x%06X: %s -> %s  (now chains to rs cave)"
              % (tail_addr, tail.hex().upper(), newtail.hex().upper()))

        # ---------- round-trip -------------------------------------------
        ctxreg = program.getLanguage().getContextBaseRegister()
        pc = program.getProgramContext()
        val = RegisterValue(ctxreg, BigInteger("20000000", 16),
                            BigInteger("FFFFFFFF", 16))
        tid = program.startTransaction("rs-roundtrip")
        try:
            listing.clearCodeUnits(A(CAVE), A(CAVE + len(cave) - 1), False)
            pc.setRegisterValue(A(CAVE), A(CAVE + len(cave)), val)
            mem.setBytes(A(CAVE), jb(cave))
            listing.clearCodeUnits(A(CAVE), A(CAVE + len(cave) - 1), False)
            DisassembleCommand(A(CAVE),
                               AddressSet(A(CAVE), A(CAVE + len(cave) - 1)),
                               True).applyTo(program)
            print("\n=== RS CAVE re-disassembled from written bytes ===")
            n = 0
            for ins in listing.getInstructions(
                    AddressSet(A(CAVE), A(CAVE + len(cave) - 1)), True):
                b = " ".join("%02X" % (x & 0xFF) for x in ins.getBytes())
                print("  %s %-12s %s" % (ins.getAddress(), b, ins))
                n += 1
            print("  (%d instructions)" % n)
        finally:
            program.endTransaction(tid, False)     # rollback: analysis only

        json.dump({"cave_addr": CAVE, "cave": list(cave),
                   "peek_tail_addr": tail_addr,
                   "peek_tail_old": list(tail), "peek_tail_new": list(newtail),
                   "depths": {n: m for n, m in DEPTHS},
                   "targets": {"lock_req": T_LOCK_REQ, "arm": T_ARM,
                               "rke_code": T_RKE_CODE,
                               "rke_valid": T_RKE_VALID,
                               "power_mode": T_POWER_MODE,
                               "substate": T_SUBSTATE, "flag": T_FLAG,
                               "scratch": SCRATCH,
                               "dirty": list(T_DIRTY)},
                   "hook_addr": HOOK, "ret": RET, "cont": CONT},
                  open(os.path.join(HERE, "rs_blobs.json"), "w"), indent=1)
        print("\nsaved %s/rs_blobs.json" % HERE)
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


main()
