import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.scalar import Scalar
import collections

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing()
    fm=program.getFunctionManager()
    # Build: for each instruction, collect 32-bit constants formed by lis+ori pairs is hard.
    # Simpler: scan for e_lis/se_lis with 0x4000 (signal RAM high) and 0xFFFC (flexcan) and 0x0014 / 0x0015 (F10A tables) and 0x000F (handlers)
    # Report functions that reference signal-RAM area 0x4000 with low parts near 0x0044(frame img) or 0x0006(signal)
    want_hi={0x4000:"RAM",0xFFFC:"FLEXCAN"}
    funchits=collections.defaultdict(lambda: collections.Counter())
    for ins in listing.getInstructions(True):
        mn=ins.getMnemonicString()
        if mn not in ("e_lis","se_lis","e_add16i","e_or2i","e_ori"): continue
        for oi in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(oi):
                if isinstance(obj,Scalar):
                    v=obj.getUnsignedValue()&0xFFFF
                    if mn in ("e_lis","se_lis") and v in want_hi:
                        f=fm.getFunctionContaining(ins.getAddress())
                        if f: funchits[str(f.getEntryPoint())][want_hi[v]]+=1
    # print functions with both FLEXCAN and RAM refs (candidate RX/TX drivers)
    print("=== functions referencing FlexCAN base (0xFFFC) ===")
    rows=[]
    for ep,c in funchits.items():
        if c["FLEXCAN"]>0:
            f=fm.getFunctionAt(program.getAddressFactory().getAddress(ep))
            rows.append((c["FLEXCAN"],c["RAM"],ep,f.getName() if f else "?"))
    for flex,ram,ep,nm in sorted(rows,reverse=True):
        print(f"  {ep} {nm:28s} flexcan={flex} ram={ram}")
finally:
    project.close()
