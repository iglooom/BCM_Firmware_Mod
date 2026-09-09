import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    fm=program.getFunctionManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    refmgr=program.getReferenceManager()
    # find refs to master net table entries & routing/frame tables
    targets=[int(x,16) for x in sys.argv[1:]]
    for t in targets:
        refs=list(refmgr.getReferencesTo(A(t)))
        print(f"\n=== refs to 0x{t:X}: {len(refs)} ===")
        for r in refs[:25]:
            fr=r.getFromAddress(); f=fm.getFunctionContaining(fr)
            print(f"  {fr} {r.getReferenceType()} in {f.getName() if f else '?'}@{f.getEntryPoint() if f else '?'}")
finally:
    project.close()
