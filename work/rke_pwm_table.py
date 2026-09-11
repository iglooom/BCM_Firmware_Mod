"""Enumerate the PWM (eMIOS) output channels this firmware actually configures.

FUN_0003f836 is a generic PWM driver: it takes a logical channel id, reads a
per-channel record (`iVar3*0x24 + DAT_40004220`), and dispatches to one of the
eMIOS "master bus" groups - eMIOS_0 ch{0,8,16,24} / eMIOS_1 ch{0,8,16,24} - i.e.
the unified-channel banks. The *hardware* channel actually driven comes from that
record's channel field, so the config table is what identifies real output pins.

Find the PWM config table: locate writers of DAT_40004220 (the table pointer),
recover the flash address it is loaded from, then dump the 0x24-byte records.

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
PTR = 0x40004220

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    rm = program.getReferenceManager()

    print("=" * 78)
    print("writers / readers of the PWM config-table pointer 0x%08X" % PTR)
    print("=" * 78)
    refs = list(rm.getReferencesTo(af.getAddress(PTR)))
    for r in refs:
        site = r.getFromAddress()
        f = fm.getFunctionContaining(site)
        print("  @%s [%s] %s" % (site, f.getName() if f else "?", r.getReferenceType()))
        if str(r.getReferenceType()) != "WRITE":
            continue
        ins = listing.getInstructionAt(site)
        cur, win = ins, []
        for _ in range(14):
            p = cur.getPrevious()
            if p is None:
                break
            win.append(p)
            cur = p
        for w in reversed(win):
            print("      %s  %s" % (w.getAddress(), w))
finally:
    project.close()

# candidate table addresses: any flash pointer that looks like a config array
print("\n" + "=" * 78)
print("scan: plausible PWM config tables (0x24-stride records in flash)")
print("=" * 78)


def u32(o):
    return struct.unpack_from(">I", raw, o)[0]


# The init passes a config struct; search 0x16000-0x18000 (driver config region)
# for a pointer followed by a small count, the pattern used by the ADC/EIRQ cfgs.
for base in range(0x16000, 0x18000, 4):
    p = u32(base)
    if not (0x16000 <= p < 0x1C000):
        continue
    cnt = raw[base + 4]
    if not (1 <= cnt <= 32):
        continue
    # validate: records of 0x24 bytes whose first byte is a plausible channel id
    ok = all(raw[p + i * 0x24] < 64 for i in range(min(cnt, 6)))
    if ok and p + cnt * 0x24 < len(raw):
        chans = [raw[p + i * 0x24] for i in range(cnt)]
        if len(set(chans)) == len(chans):
            print("  hdr@0x%05X -> table 0x%05X count=%d  first-bytes=%s"
                  % (base, p, cnt, chans))
