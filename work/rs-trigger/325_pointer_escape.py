#!/usr/bin/env python3
"""325 -- METHOD E: POINTER-ESCAPE CENSUS.

323/324 found the writer that all four address-resolving methods missed:

    FUN_0011367e:  FUN_00113ea8(1, &stack0x08, &DAT_40002f3c);
    FUN_00113ea8:  *param_3 = bVar1 & 3;      <-- writes 0..3, INCLUDING 3

The cell's ADDRESS is handed to a callee.  The store then happens through a
POINTER PARAMETER, so it has no ram varnode, no absolute reference, and no
resolvable base register -- it is invisible to the reference manager, to a
base+disp sweep, to p-code CALLOTHER, and to a raw-binary base tracker alike.
Their unanimous "2 writers" is a SHARED BLIND SPOT, not a confirmation
(AGENTS.md rule 17: methods agreeing does not make them right; a method that
finds what others cannot must explain their blindness -- this one does).

This script closes the census by enumerating the OTHER direction: every site in
the image where the VALUE 0x40002F3C is materialised into a register without
being dereferenced (i.e. the address escapes as a pointer), so no further
pointer writer can be hiding.

  E1. all references Ghidra records to the cell, classified
  E2. full-image scan for the constant 0x40002F3C being formed in a register
      and NOT immediately used as a load/store base
  E3. exact address + operand of the `*param_3 = bVar1 & 3` store
  E4. the source table (&DAT_4000B0BB)[idx*0xE] -- what values does byte&3 take

Read-only.
"""
import os
import sys
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

CELLS = {0x40002F3C: "TARGET", 0x40002F32: "sibling ch0", 0x40002F37: "sibling ch2"}
STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu")
LOAD_MN = ("e_lbz", "e_lhz", "e_lwz", "se_lbz", "se_lhz", "se_lwz",
           "e_lha", "e_lbzu", "e_lhzu", "e_lwzu")


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        refmgr = program.getReferenceManager()

        # ---------------- E1 ----------------
        print("=" * 78)
        print("E1. ALL references to each cell, CLASSIFIED")
        print("=" * 78)
        for cell, tag in CELLS.items():
            print("\n---- 0x%08X (%s) ----" % (cell, tag))
            byk = defaultdict(list)
            for r in refmgr.getReferencesTo(af.getAddress(cell)):
                fa = r.getFromAddress()
                ins = listing.getInstructionAt(fa)
                mn = ins.getMnemonicString().lower() if ins else "(data)"
                if mn.startswith(STORE_MN):
                    k = "WRITE"
                elif mn.startswith(LOAD_MN):
                    k = "read"
                elif ins is None:
                    k = "data-word (pointer in a table?)"
                else:
                    k = "ADDRESS-TAKEN / other: " + mn
                fn = fm.getFunctionContaining(fa)
                byk[k].append("0x%06X %-26s fn=%s"
                              % (fa.getOffset(), str(ins) if ins else "-",
                                 fn.getName() if fn else "UNSWEPT"))
            for k in sorted(byk):
                print("   [%s]  n=%d" % (k, len(byk[k])))
                for s in byk[k]:
                    print("       " + s)

        # ---------------- E2 ----------------
        print()
        print("=" * 78)
        print("E2. FULL-IMAGE: where is the ADDRESS 0x40002F3C materialised")
        print("    into a register?  (pointer escape -> possible hidden writer)")
        print("=" * 78)
        regs = {}
        prev_end = None
        fn_entries = set(f.getEntryPoint().getOffset()
                         for f in fm.getFunctions(True))
        esc = []
        it = listing.getInstructions(True)
        nins = 0
        while it.hasNext():
            ins = it.next()
            nins += 1
            off = ins.getAddress().getOffset()
            if off in fn_entries or prev_end is None or off != prev_end:
                regs = {}
            prev_end = off + ins.getLength()
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
                    if src in regs:
                        regs[d0] = (regs[src] + val) & 0xFFFFFFFF
                        if regs[d0] in CELLS:
                            fn = fm.getFunctionContaining(ins.getAddress())
                            esc.append((off, str(ins), d0, regs[d0],
                                        fn.getName() if fn else "UNSWEPT"))
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_li", "se_li", "li"):
                try:
                    v = int(ins.getScalar(1).getValue()) & 0xFFFFFFFF
                    regs[d0] = v
                    if v in CELLS:
                        fn = fm.getFunctionContaining(ins.getAddress())
                        esc.append((off, str(ins), d0, v,
                                    fn.getName() if fn else "UNSWEPT"))
                except Exception:
                    regs.pop(d0, None)
            elif mn.startswith(STORE_MN) or mn.startswith(LOAD_MN):
                pass
            elif d0.startswith("r"):
                regs.pop(d0, None)
        print("   swept %d instructions" % nins)
        print("   address-materialisation sites: %d" % len(esc))
        for e in esc:
            print("     0x%06X  %-30s %s = 0x%08X   fn=%s"
                  % (e[0], e[1], e[2], e[3], e[4]))

        # ---------------- E3 ----------------
        print()
        print("=" * 78)
        print("E3. The hidden writer: `*param_3 = bVar1 & 3` in FUN_00113ea8")
        print("=" * 78)
        f = fm.getFunctionAt(af.getAddress(0x113EA8))
        ins = listing.getInstructionAt(f.getEntryPoint())
        lim = f.getBody().getMaxAddress().getOffset()
        while ins is not None and ins.getAddress().getOffset() <= lim:
            mn = ins.getMnemonicString().lower()
            print("   0x%06X  %s" % (ins.getAddress().getOffset(), ins))
            ins = ins.getNext()

        # ---------------- E4 ----------------
        print()
        print("=" * 78)
        print("E4. SOURCE TABLE (&DAT_4000B0BB)[idx*0xE] -- what can byte&3 be?")
        print("=" * 78)
        print("   0x4000B0BB is SRAM (block SRAM 40000000..40017fff), i.e. a")
        print("   RUNTIME structure, not flash constants -- so byte&3 is not")
        print("   statically bounded below 3 by any table image.")
        print("   Also check: the index table PTR_DAT_0011322E in FLASH")
        base = 0x11322E
        b = bytearray()
        for i in range(32):
            b.append(program.getMemory().getByte(af.getAddress(base + i)) & 0xFF)
        print("   0x%06X: %s" % (base, b.hex(" ")))
        for nm in ("DAT_0011323c", "DAT_0011323d"):
            pass
        for aa in (0x11323C, 0x11323D):
            print("   0x%06X = 0x%02X"
                  % (aa, program.getMemory().getByte(af.getAddress(aa)) & 0xFF))
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
