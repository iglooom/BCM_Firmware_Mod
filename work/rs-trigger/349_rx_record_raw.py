#!/usr/bin/env python3
"""349 - raw bytes of the MS-CAN 0x100 RX record and of descriptor 0x142FD4,
so the arrival-flag OR mask and the get16 source/mask are read from the image
rather than inferred.

RX record layout (docs/owner_flash_layers.md Sec.16/17, stride 0x1C):
  +0x00 dst image ptr   +0x08 flag byte ptr   +0x0C src ptr (raw-copy variant)
  +0x16 flag OR mask    +0x19 mailbox index   +0x1A copymask

Signal descriptor layout (32 bytes):
  +0x00 ptr to source byte in the frame image   +0x0C mask   +0x0D shift

CONTROL: the record parsed here must reproduce rx_frame_map.json's already-
published values for this frame -- image_base 0x40000918, flag 0x400004FE,
mb 53, copymask 0xFF.  A mismatch means the offsets are wrong and NOTHING in
this script may be used.

READ-ONLY.
"""
import os, sys, json, struct, traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

REC = 0x152088 + 4 * 0x1C     # array 0x152088, idx 4 (MS 0x100, mb 53)
DESC = 0x142FD4

project = None
try:
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    af = prog.getAddressFactory().getDefaultAddressSpace()
    mem = prog.getMemory()

    def rd(a, n):
        # jpype: mem.getBytes needs a JAVA byte[]; a python bytearray is NOT
        # written through (it silently returns zeros -- the first run of this
        # script produced an all-zero record and a FAILING control, which is
        # exactly why the control exists).
        import jpype
        JByte = jpype.JArray(jpype.JByte)
        buf = JByte(n)
        mem.getBytes(af.getAddress(a), buf)
        return bytes(bytearray([(int(x) & 0xFF) for x in buf]))

    r = rd(REC, 0x1C)
    print("RX record @ 0x%06X:" % REC, r.hex())
    dst = struct.unpack(">I", r[0:4])[0]
    src = struct.unpack(">I", r[4:8])[0]
    flg = struct.unpack(">I", r[8:12])[0]
    p3 = struct.unpack(">I", r[12:16])[0]
    print("  +0x00 dst image ptr   = 0x%08X" % dst)
    print("  +0x04 src ptr         = 0x%08X" % src)
    print("  +0x08 flag byte ptr   = 0x%08X" % flg)
    print("  +0x0C ptr3            = 0x%08X" % p3)
    print("  +0x15 idmatch         = 0x%02X" % r[0x15])
    print("  +0x16 FLAG OR MASK    = 0x%02X" % r[0x16])
    print("  +0x17 mask2           = 0x%02X" % r[0x17])
    print("  +0x19 mailbox         = %d" % r[0x19])
    print("  +0x1A COPYMASK        = 0x%02X" % r[0x1A])

    ok = (dst == 0x40000918 and flg == 0x400004FE and r[0x19] == 53
          and r[0x1A] == 0xFF)
    print("CONTROL (matches rx_frame_map.json):", "PASS" if ok else "FAIL")

    d = rd(DESC, 0x20)
    print()
    print("descriptor @ 0x%06X:" % DESC, d.hex())
    print("  +0x00 src byte ptr = 0x%08X" % struct.unpack(">I", d[0:4])[0])
    print("  +0x0C mask         = 0x%02X" % d[0x0C])
    print("  +0x0D shift        = %d" % d[0x0D])
    dctl = (struct.unpack(">I", d[0:4])[0] == 0x4000091E and d[0x0C] == 0x1F)
    print("CONTROL (matches rx_signal_dict.json 0x4000091E mask 0x1F):",
          "PASS" if dctl else "FAIL")

except Exception:
    traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
finally:
    try:
        if project is not None:
            project.close()
    except Exception:
        traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)
