#!/usr/bin/env python3
"""Who writes DAT_40002F3C, the OUTER gate of FUN_000AD6C6?

vehicle_session_1.md Sec.5.2: the only producer of the remote-start debounce
counter is guarded by `if (DAT_40002F3C == 3)`.  That cell is NOT in the
0x400095EC struct -- it is a separate global, and nothing in this project has
looked at it.  If it is a simple mode variable with few writers it is a far
better trigger target than the gate word (35+ writers, three independent
readers).

Two questions:
   Q1  who writes it, and with what values?  (is 3 reachable?)
   Q2  what else READS it?  (a cell read by one function is a private flag;
       read by many is a shared mode)

METHOD -- reference manager + per-function base+disp sweep, the pair that
agreed in 311.  Rule 45: the CONTROLS are cells in the same address
neighbourhood accessed the same way, so a null here is informative.

Read-only.
"""
import os
import sys
import re
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

TARGET = 0x40002F3C
CONTROLS = {
    0x4000965C: "base+0x70 debounce counter (6 writers known, 311)",
    0x40002DA2: "APP_rke_command_code (known live)",
}

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu")
LOAD_MN = ("e_lbz", "e_lhz", "e_lwz", "se_lbz", "se_lhz", "se_lwz",
           "e_lha", "e_lbzu", "e_lwzu")
NON_DEFINING = STORE_MN + ("e_cmp", "se_cmp", "cmp", "e_cmpl", "e_cmpli",
                           "e_cmpl16i", "e_cmph", "e_b", "se_b", "e_bc")


def parse_disp(txt):
    m = re.match(r"(-?)0x([0-9a-fA-F]+)\((r\d+)\)", txt)
    if m:
        s, mag, reg = m.groups()
        v = int(mag, 16)
        return (-v if s == "-" else v), reg
    m = re.match(r"(-?)(\d+)\((r\d+)\)", txt)
    if m:
        s, mag, reg = m.groups()
        v = int(mag)
        return (-v if s == "-" else v), reg
    return None, None


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        cells = {TARGET: "DAT_40002F3C  (TARGET)"}
        cells.update(CONTROLS)
        stores = defaultdict(list)
        loads = defaultdict(list)

        nfun = 0
        for fn in fm.getFunctions(True):
            nfun += 1
            regs = {}
            body = fn.getBody()
            ins = listing.getInstructionAt(body.getMinAddress())
            lim = body.getMaxAddress().getOffset()
            while ins is not None and ins.getAddress().getOffset() <= lim:
                mn = ins.getMnemonicString().lower()
                try:
                    d0 = ins.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    d0 = ""
                if mn in ("e_lis", "se_lis", "lis"):
                    try:
                        regs[d0] = (int(ins.getScalar(1).getValue()) << 16) & 0xFFFFFFFF
                    except Exception:
                        regs.pop(d0, None)
                elif mn in ("e_add16i", "e_addi", "addi"):
                    try:
                        src = ins.getDefaultOperandRepresentation(1).strip().lower()
                        val = int(ins.getScalar(2).getValue())
                        regs[d0] = ((regs[src] + val) & 0xFFFFFFFF) if src in regs else None
                        if regs[d0] is None:
                            regs.pop(d0)
                    except Exception:
                        regs.pop(d0, None)
                elif mn.startswith(STORE_MN) or mn.startswith(LOAD_MN):
                    idx = 1
                    try:
                        t = ins.getDefaultOperandRepresentation(idx).strip().lower()
                    except Exception:
                        t = ""
                    disp, reg = parse_disp(t)
                    if reg in regs and disp is not None:
                        ea = (regs[reg] + disp) & 0xFFFFFFFF
                        if ea in cells:
                            rec = (ins.getAddress().getOffset(), str(ins),
                                   fn.getName())
                            if mn.startswith(STORE_MN):
                                stores[ea].append(rec)
                            else:
                                loads[ea].append(rec)
                    if d0 in regs and mn.startswith(LOAD_MN):
                        regs.pop(d0, None)
                elif d0 in regs and not mn.startswith(NON_DEFINING):
                    regs.pop(d0, None)
                ins = ins.getNext()

        print("swept %d functions\n" % nfun)
        print("=" * 74)
        print("Q1/Q2  writers and readers")
        print("=" * 74)
        for a, desc in cells.items():
            tag = "TARGET " if a == TARGET else "control"
            print("\n%s 0x%08X  %s" % (tag, a, desc))
            print("   %d store(s), %d load(s)" % (len(stores[a]), len(loads[a])))
            for off, txt, fnm in stores[a][:12]:
                print("     W 0x%06X  %-30s %s" % (off, txt, fnm))
            for off, txt, fnm in loads[a][:12]:
                print("     R 0x%06X  %-30s %s" % (off, txt, fnm))

        ok = any(stores[a] or loads[a] for a in CONTROLS)
        print()
        print("CONTROL: %s" % ("PASS -- nulls above are informative" if ok
                               else "FAIL -- every null is UNINFORMATIVE"))

        # ---- what value is stored at each writer of the target? ----
        if stores[TARGET]:
            print()
            print("=" * 74)
            print("VALUES stored to DAT_40002F3C  (is 3 reachable?)")
            print("=" * 74)
            for off, txt, fnm in stores[TARGET]:
                ins = listing.getInstructionAt(af.getAddress(off))
                try:
                    src = ins.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    continue
                cur = ins.getPrevious()
                n = 0
                found = None
                while cur is not None and n < 30:
                    n += 1
                    m2 = cur.getMnemonicString().lower()
                    try:
                        dd = cur.getDefaultOperandRepresentation(0).strip().lower()
                    except Exception:
                        dd = ""
                    if dd == src and not m2.startswith(NON_DEFINING):
                        found = cur
                        break
                    cur = cur.getPrevious()
                lit = ""
                if found is not None and found.getMnemonicString().lower() in (
                        "se_li", "e_li", "li"):
                    try:
                        v = int(found.getScalar(1).getValue())
                        lit = "  literal %d%s" % (
                            v, "   <<< THE GATE VALUE" if v == 3 else "")
                    except Exception:
                        pass
                print("   0x%06X %-28s <- %s%s"
                      % (off, txt, str(found) if found else "unresolved", lit))
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
