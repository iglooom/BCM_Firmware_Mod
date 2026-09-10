import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    fm=program.getFunctionManager()
    refmgr=program.getReferenceManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    lo,hi=0x400008F0,0x40000960
    hitcells={}
    for t in range(lo,hi):
        refs=[r for r in refmgr.getReferencesTo(A(t))]
        code=[r for r in refs if 0x10000<=r.getFromAddress().getOffset()<0x140000]
        if code:
            hitcells[t]=code
    if not hitcells:
        print("NO code refs anywhere in 0x400008F0..0x40000960 (all table-driven).")
    for t,code in sorted(hitcells.items()):
        print(f"\ncell 0x{t:08X}: {len(code)} CODE refs")
        for r in code[:12]:
            fr=r.getFromAddress(); f=fm.getFunctionContaining(fr)
            print(f"   <- 0x{fr.getOffset():06X} {r.getReferenceType()} in {f.getName()+'@'+f.getEntryPoint().toString() if f else '?'}")
finally:
    project.close()
