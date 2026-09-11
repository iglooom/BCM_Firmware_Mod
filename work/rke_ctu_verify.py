"""Ground-truth disassembly around the two suspected CTU accesses in FUN_0003a402.

The constant-propagating scan reported loads/stores resolving to 0xFFE64000
(CTU base + 0x0). That offset is RESERVED in the CTU register map, which is a
strong hint of a mis-resolve: FUN_0003a402 computes its peripheral base
dynamically as (param_1 * 0x4000) - 0x200000, i.e. ADC0=0xFFE00000 /
ADC1=0xFFE04000. A propagator that guesses a stale constant for the register
holding param_1*0x4000 can land on 0xFFE64000 by accident.

Print the real instructions so the claim is decided by disassembly, not inference.
Read-only.
"""
import os
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
SITES = [0x3A694, 0x3A6AA]
WINDOW = 14

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    for site in SITES:
        a = af.getAddress(site)
        f = fm.getFunctionContaining(a)
        print("\n" + "=" * 72)
        print("site 0x%06X in %s" % (site, f.getName() if f else "?"))
        print("=" * 72)
        ins = listing.getInstructionAt(a)
        # rewind
        cur = ins
        for _ in range(WINDOW):
            p = cur.getPrevious()
            if p is None:
                break
            cur = p
        for _ in range(WINDOW * 2 + 4):
            if cur is None:
                break
            mark = "  <<<<" if cur.getAddress().getOffset() in SITES else ""
            refs = ""
            try:
                rr = cur.getReferencesFrom()
                if rr:
                    refs = "   ; " + ", ".join(
                        "%s->%s" % (r.getReferenceType(), r.getToAddress()) for r in rr[:3])
            except Exception:
                pass
            print("  %s  %-34s%s%s" % (cur.getAddress(), cur, refs, mark))
            cur = cur.getNext()
finally:
    project.close()
