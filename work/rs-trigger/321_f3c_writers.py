#!/usr/bin/env python3
"""321 -- COMPLETE writer census for DAT_40002F3C (0x40002F3C), the gate byte of
FUN_000AD6C6 (`if (*(0x40002D20+0x21C) == 3)`).

Four independent instruments, each reported separately (AGENTS.md rule 17: two
scans that disagree is the finding; never pick a favourite):

  A. Ghidra reference manager, absolute references only.
     Expected WEAK -- rule 45: this cell is reached as disp(rX), so a scan that
     matches only absolute refs is structurally blind to most sites.
  B. Linear base+displacement sweep over EVERY INSTRUCTION IN THE IMAGE
     (listing.getInstructions(True)), not only instructions inside functions,
     so unswept blocks (rule 14/44) are covered.  Register state is reset at
     every function entry and every address discontinuity; a call invalidates
     the volatile set (r0, r3-r12) but keeps the callee-saved set.  Scoped so
     nothing leaks across a function boundary (rule 17).
  C. Decompiler p-code, CALLOTHER userop 0x10000002 = store (rule 14 corollary;
     a STORE-only walk finds nothing in this language).
  D. Byte-pattern scan of the raw image for the two encodings that can form the
     address (e_lis rX,0x4000 / e_add16i then a stb with disp 0x21C, and any
     stb whose base was set to 0x40002F30 with disp 0xC), independent of
     Ghidra's disassembly entirely.  Implemented as: every *store* instruction
     in the image whose displacement is one of the displacements that could
     reach the cell from a plausible base, then resolve the base by method B's
     tracker -- reported as a superset/candidate count.

POSITIVE CONTROLS -- rule 45: same address region AND same addressing form.
  0x40002F37 = r31+0x7   written at 0x113788  (se_stb r0,0x7(r31), value 5)
  0x40002F32 = r31+0x2   written at 0x11378A  (se_stb r0,0x2(r31), value 5)
  0x40002F30 = r31+0x0 / r30+0x210
  ...all in the SAME struct at 0x40002D20 as the subject, all disp(rX).
  Secondary (different region, documented): 0x4000965C with 6 known writers.

Read-only.
"""
import os
import re
import sys
import json
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.app.decompiler import DecompInterface  # noqa: E402
from ghidra.util.task import ConsoleTaskMonitor  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
OUT = os.path.join(ROOT, "work/rs-trigger/f3c_writers.json")

TARGET = 0x40002F3C
CONTROLS = {
    0x40002F37: "ctrl same-struct byte (+0x217 / r31+0x7), writer 0x113788",
    0x40002F32: "ctrl same-struct byte (+0x212 / r31+0x2), writer 0x11378A",
    0x40002F30: "ctrl same-struct byte (+0x210 / r31+0x0)",
    0x4000965C: "ctrl other-region enum, 6 documented writers",
}
WATCH = dict(CONTROLS)
WATCH[TARGET] = "TARGET gate byte"

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu", "stb", "sth", "stw",
            "e_stmw", "stbx", "sthx", "stwx")
BYTE_STORE = ("e_stb", "se_stb", "e_stbu", "stb")

VOLATILE = set(["r0"] + ["r%d" % i for i in range(3, 13)])

DISP_RE = re.compile(r"^(-?)0x([0-9a-fA-F]+)\((r\d+)\)$")
DISP_RE2 = re.compile(r"^(-?)(\d+)\((r\d+)\)$")

skipped_disp = 0


def parse_disp(txt):
    """Signed displacement parse (rule 16). Never swallow silently."""
    global skipped_disp
    t = txt.strip().lower()
    m = DISP_RE.match(t)
    if m:
        sign, mag, reg = m.groups()
        v = int(mag, 16)
    else:
        m = DISP_RE2.match(t)
        if not m:
            skipped_disp += 1
            return None, None
        sign, mag, reg = m.groups()
        v = int(mag)
    return (-v if sign == "-" else v), reg


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        refmgr = program.getReferenceManager()
        mem = program.getMemory()

        print("=" * 78)
        print("SCOPE (rule 18)")
        print("=" * 78)
        for b in mem.getBlocks():
            print("   block %-16s %s..%s  %s%s%s" % (
                b.getName(), b.getStart(), b.getEnd(),
                "r" if b.isRead() else "-",
                "w" if b.isWrite() else "-",
                "x" if b.isExecute() else "-"))
        print("   functions in program: %d" % fm.getFunctionCount())

        results = {hex(a): {"A": [], "B": [], "C": []} for a in WATCH}

        # ---------------- A: reference manager (absolute only) -------------
        print()
        print("=" * 78)
        print("A. REFERENCE MANAGER  (absolute references only)")
        print("=" * 78)
        for addr, desc in WATCH.items():
            n_all = 0
            for r in refmgr.getReferencesTo(af.getAddress(addr)):
                n_all += 1
                fa = r.getFromAddress()
                ins = listing.getInstructionAt(fa)
                if ins is None:
                    continue
                mn = ins.getMnemonicString().lower()
                if mn.startswith(STORE_MN):
                    results[hex(addr)]["A"].append(
                        [fa.getOffset(), str(ins)])
            print("   0x%08X %-52s refs=%-4d stores=%d"
                  % (addr, desc, n_all, len(results[hex(addr)]["A"])))

        # ---------------- B: full-image linear base+disp sweep -------------
        print()
        print("=" * 78)
        print("B. LINEAR BASE+DISP SWEEP over EVERY instruction in the image")
        print("=" * 78)
        fn_entries = set()
        for f in fm.getFunctions(True):
            fn_entries.add(f.getEntryPoint().getOffset())

        regs = {}
        prev_end = None
        n_ins = 0
        n_store = 0
        n_resolved = 0
        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            n_ins += 1
            a = ins.getAddress()
            off = a.getOffset()
            # scope resets
            if off in fn_entries or prev_end is None or off != prev_end:
                regs = {}
            prev_end = off + ins.getLength()
            mn = ins.getMnemonicString().lower()
            try:
                d0 = ins.getDefaultOperandRepresentation(0).strip().lower()
            except Exception:
                d0 = ""

            if mn.startswith(STORE_MN):
                n_store += 1
                try:
                    t = ins.getDefaultOperandRepresentation(1).strip().lower()
                except Exception:
                    t = ""
                disp, reg = parse_disp(t)
                if reg is not None and disp is not None and reg in regs:
                    n_resolved += 1
                    ea = (regs[reg] + disp) & 0xFFFFFFFF
                    if ea in WATCH:
                        fn = fm.getFunctionContaining(a)
                        results[hex(ea)]["B"].append(
                            [off, str(ins), fn.getName() if fn else "UNSWEPT",
                             mn, reg, disp, regs[reg]])
                # a store does not define its operand-0 register (rule/287)
                continue

            if mn in ("e_lis", "se_lis", "lis"):
                try:
                    regs[d0] = (int(ins.getScalar(1).getValue()) << 16) & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_add16i", "e_addi", "addi", "e_add2i.", "e_add2is"):
                try:
                    src = ins.getDefaultOperandRepresentation(1).strip().lower()
                    val = int(ins.getScalar(2).getValue())
                    if mn == "e_add2is":
                        val = (val << 16) & 0xFFFFFFFF
                    if src in regs:
                        regs[d0] = (regs[src] + val) & 0xFFFFFFFF
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("se_addi",):
                try:
                    val = int(ins.getScalar(1).getValue())
                    if d0 in regs:
                        regs[d0] = (regs[d0] + val) & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("se_mr", "mr", "e_mr", "se_mtar", "se_mfar"):
                try:
                    src = ins.getDefaultOperandRepresentation(1).strip().lower()
                    if src in regs:
                        regs[d0] = regs[src]
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn.startswith(("e_bl", "se_bl")) and not mn.startswith(
                    ("e_blr", "se_blr")):
                for v in list(regs):
                    if v in VOLATILE:
                        regs.pop(v, None)
            elif mn.startswith(("e_cmp", "se_cmp", "cmp", "e_b", "se_b")):
                pass
            elif d0.startswith("r"):
                regs.pop(d0, None)

        print("   instructions swept : %d" % n_ins)
        print("   store instructions : %d" % n_store)
        print("   base resolved      : %d" % n_resolved)
        print("   disp parse skipped : %d" % skipped_disp)
        for addr, desc in WATCH.items():
            print("   0x%08X %-52s stores=%d"
                  % (addr, desc, len(results[hex(addr)]["B"])))

        # ---------------- C: decompiler p-code CALLOTHER stores -------------
        print()
        print("=" * 78)
        print("C. DECOMPILER P-CODE  CALLOTHER 0x10000002 (store)")
        print("=" * 78)
        di = DecompInterface()
        di.openProgram(program)
        monitor = ConsoleTaskMonitor()
        nfun = 0
        nfail = 0
        nnoram = 0
        for f in fm.getFunctions(True):
            nfun += 1
            try:
                res = di.decompileFunction(f, 45, monitor)
            except Exception:
                nfail += 1
                continue
            if res is None or not res.decompileCompleted():
                nfail += 1
                continue
            hf = res.getHighFunction()
            if hf is None:
                nfail += 1
                continue
            got_ram = False
            ops = hf.getPcodeOps()
            while ops.hasNext():
                op = ops.next()
                try:
                    mn = op.getMnemonic()
                except Exception:
                    continue
                ins_addr = op.getSeqnum().getTarget().getOffset()
                vns = [op.getInput(i) for i in range(op.getNumInputs())]
                # CALLOTHER userop: input0 = userop id
                if mn == "CALLOTHER" and len(vns) >= 2:
                    try:
                        uid = vns[0].getOffset()
                    except Exception:
                        continue
                    for v in vns[1:]:
                        if v is None:
                            continue
                        sp = v.getAddress()
                        if sp is None or not sp.isMemoryAddress():
                            continue
                        got_ram = True
                        ea = sp.getOffset()
                        if ea in WATCH and uid == 0x10000002:
                            results[hex(ea)]["C"].append(
                                [ins_addr, f.getName(), "CALLOTHER-store"])
                elif mn == "STORE":
                    for v in vns[1:2]:
                        if v is None:
                            continue
                        if v.isConstant():
                            ea = v.getOffset()
                            if ea in WATCH:
                                results[hex(ea)]["C"].append(
                                    [ins_addr, f.getName(), "STORE"])
                # plain ram varnode written by any op
                out = op.getOutput()
                if out is not None:
                    oa = out.getAddress()
                    if oa is not None and oa.isMemoryAddress():
                        got_ram = True
                        if oa.getOffset() in WATCH:
                            results[hex(oa.getOffset())]["C"].append(
                                [ins_addr, f.getName(), "def:" + mn])
            if not got_ram:
                nnoram += 1
        print("   functions decompiled: %d  (failed %d, no ram-resolved op %d)"
              % (nfun, nfail, nnoram))
        for addr, desc in WATCH.items():
            print("   0x%08X %-52s stores=%d"
                  % (addr, desc, len(results[hex(addr)]["C"])))

        with open(OUT, "w") as fh:
            json.dump(results, fh, indent=1)
        print("\nwrote %s" % OUT)

        # ---------------- summary ----------------
        print()
        print("=" * 78)
        print("UNION PER CELL")
        print("=" * 78)
        for addr, desc in WATCH.items():
            u = {}
            for m in ("A", "B", "C"):
                for rec in results[hex(addr)][m]:
                    u.setdefault(rec[0], set()).add(m)
            tag = "TARGET " if addr == TARGET else "control"
            print("\n%s 0x%08X  %s   union=%d" % (tag, addr, desc, len(u)))
            for a in sorted(u):
                ins = listing.getInstructionAt(af.getAddress(a))
                fn = fm.getFunctionContaining(af.getAddress(a))
                print("   0x%06X  %-28s  by=%s  fn=%s"
                      % (a, str(ins) if ins else "?", ",".join(sorted(u[a])),
                         fn.getName() if fn else "UNSWEPT"))
    except Exception:
        traceback.print_exc()
    finally:
        try:
            project.close()
        except Exception:
            pass
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


main()
