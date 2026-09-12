#!/usr/bin/env python3
"""345 - RX path for MS-CAN 0x100 RKE -> FUN_000ADADA.

Stage 1: decompile the known nodes of the path and dump raw listings so the
stores can be enumerated by hand + by p-code in stage 2.

Nodes:
  0x0FC63E  VOL_rx_copy_to_image   (RX copier)
  0x048C40  VOL_frame_arrived
  0x048C6C  APP_rx_unpack_main
  0x0FBB38  VOL_sig_get16
  0x0584A4  APP_rke_code_validate
  0x058538  APP_rke_code_commit    <-- the writer of 0x40002DA2 / 0x40003F53
  0x0992B2  APP_rke_command_demux
  0x0ADADA  FUN_000ADADA           (consumer)

READ-ONLY.
"""
import os, sys, json, traceback

REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")
os.makedirs(OUT, exist_ok=True)

NODES = [0x0FC63E, 0x048C40, 0x048C6C, 0x0FBB38,
         0x0584A4, 0x058538, 0x0992B2, 0x0ADADA]

project = None
try:
    os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    af = prog.getAddressFactory().getDefaultAddressSpace()
    fm = prog.getFunctionManager()
    listing = prog.getListing()

    di = DecompInterface()
    di.openProgram(prog)
    mon = ConsoleTaskMonitor()

    res = {}
    for a in NODES:
        ad = af.getAddress(a)
        f = fm.getFunctionContaining(ad)
        rec = {"addr": hex(a), "func": None, "entry": None, "body": None, "c": None}
        if f is not None:
            rec["func"] = f.getName()
            rec["entry"] = str(f.getEntryPoint())
            rec["body"] = [str(f.getBody().getMinAddress()), str(f.getBody().getMaxAddress())]
            r = di.decompileFunction(f, 120, mon)
            if r.decompileCompleted():
                rec["c"] = r.getDecompiledFunction().getC()
            else:
                rec["c"] = "DECOMP FAIL: " + str(r.getErrorMessage())
        res[hex(a)] = rec
        print("=" * 72)
        print(hex(a), rec["func"], rec["entry"], rec["body"])
        print("=" * 72)
        if rec["c"]:
            print(rec["c"])

    with open(os.path.join(OUT, "345_nodes.json"), "w") as fh:
        json.dump(res, fh, indent=1)
    print("WROTE", os.path.join(OUT, "345_nodes.json"))

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
