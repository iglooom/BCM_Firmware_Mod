"""Boot/startup analysis + does the application CALL INTO the un-flashed low region?

Key question: 0x00000000-0x0000BFFF (48 KB) is covered by no VBF, so a
bootloader/bootblock may live there containing code we have never seen - possibly
including low-level pin init.

Decisive test: enumerate every branch/call target and every code pointer in the
application that lands below 0xC000. If the app never transfers control there and
holds no pointers there, then whatever lives in low flash runs only before the
app (or not at all) and cannot be servicing pins at runtime for the app.

Also: decode the startup path from the RCHW entry and look for an RTOS.

Read-only.
"""
import os
import struct
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()
LOW_END = 0x0000C000
APP_LO = 0x0000C000

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    # ---- 1. control transfers into low flash ---------------------------
    print("=" * 78)
    print("[1] branches / calls from the application into 0x0..0xBFFF")
    print("=" * 78)
    hits = []
    total_flow = 0
    for f in fm.getFunctions(True):
        for ins in listing.getInstructions(f.getBody(), True):
            flows = []
            try:
                flows = list(ins.getFlows())
            except Exception:
                pass
            for t in flows:
                total_flow += 1
                off = t.getOffset()
                if off < LOW_END:
                    hits.append((str(ins.getAddress()), f.getName(),
                                 ins.getMnemonicString(), off))
    print("  total flow targets examined: %d" % total_flow)
    print("  targets below 0xC000       : %d" % len(hits))
    for site, fn, mn, off in hits[:40]:
        print("     @%s [%s] %s -> 0x%08X" % (site, fn, mn, off))
    if not hits:
        print("     (NONE - the application never transfers control into low flash)")

    # ---- 2. indirect call sites ----------------------------------------
    print("\n" + "=" * 78)
    print("[2] indirect calls (se_bctrl / bctrl) - could reach anywhere")
    print("=" * 78)
    ind = 0
    for f in fm.getFunctions(True):
        for ins in listing.getInstructions(f.getBody(), True):
            if ins.getMnemonicString() in ("se_bctrl", "bctrl", "bctr", "se_bctr"):
                ind += 1
    print("  indirect call/jump instructions: %d" % ind)
    print("  (these resolve via function pointers - see [3])")

    # ---- 3. code pointers into low flash --------------------------------
    print("\n" + "=" * 78)
    print("[3] 32-bit words in the image that point into 0x0..0xBFFF")
    print("=" * 78)
    ptrs = {}
    for i in range(0, len(raw) - 3, 2):
        v = struct.unpack_from(">I", raw, i)[0]
        if 0x100 <= v < LOW_END and (v & 1) == 0:
            ptrs.setdefault(v, []).append(i)
    plausible = {v: o for v, o in ptrs.items() if len(o) <= 4}
    print("  distinct candidate values: %d" % len(plausible))
    print("  NOTE: most are data/constants, not pointers. Showing values that")
    print("  appear in the app region and are 4-byte aligned targets:")
    shown = 0
    for v in sorted(plausible):
        offs = [o for o in plausible[v] if o >= APP_LO and o % 4 == 0]
        if not offs:
            continue
        shown += 1
        if shown <= 25:
            print("     0x%08X  referenced at %s"
                  % (v, ",".join(hex(o) for o in offs[:3])))
    print("  (%d such values total)" % shown)

    # ---- 4. startup path ------------------------------------------------
    print("\n" + "=" * 78)
    print("[4] startup path from RCHW entry 0x0010F4A0")
    print("=" * 78)
    entry = af.getAddress(0x0010F4A0)
    f = fm.getFunctionContaining(entry)
    print("  entry function: %s" % (f.getName() if f else "(not a function)"))
    cur = listing.getInstructionAt(entry)
    for _ in range(40):
        if cur is None:
            break
        print("     %s  %s" % (cur.getAddress(), cur))
        cur = cur.getNext()
finally:
    project.close()
