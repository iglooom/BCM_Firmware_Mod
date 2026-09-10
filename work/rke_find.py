import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing()
    fm=program.getFunctionManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    refmgr=program.getReferenceManager()

    # 0x100 MS frame image = 0x40000918..0x4000091F ; status flag 0x400004FE
    IMG_BASE=0x40000918
    targets = list(range(0x40000918,0x40000920)) + [0x400004FE]

    for t in targets:
        addr=A(t)
        refs=list(refmgr.getReferencesTo(addr))
        if not refs: continue
        lbl = ("d%d"%(t-IMG_BASE)) if IMG_BASE<=t<=IMG_BASE+7 else ("statusFlag" if t==0x400004FE else "?")
        print(f"\n=== Ghidra refs to 0x{t:08X} [{lbl}]: {len(refs)} ===")
        for r in refs[:30]:
            fr=r.getFromAddress()
            f=fm.getFunctionContaining(fr)
            # skip refs that live in the F10A data tables (0x140000-0x160000)
            fro=fr.getOffset()
            zone = "DATA(F10A)" if 0x140000<=fro<0x160000 else ("CODE" if 0x10000<=fro<0x140000 else "OTHER")
            print(f"  from {fr} ({r.getReferenceType()}) [{zone}] in {f.getName() if f else '?'}@{f.getEntryPoint() if f else '-'}")
finally:
    project.close()
