import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.program.model.scalar import Scalar

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing()
    fm=program.getFunctionManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    refmgr=program.getReferenceManager()

    # Which target addresses to find references to
    targets=[int(x,16) for x in sys.argv[1:]] if len(sys.argv)>1 else [
        0x1464E0,0x146900,0x146C50,   # controller descriptors
        0x146530,0x146950,0x146CA0,   # MB lists
        0x146698,0x146638,0x146608,   # HS 0x0C0/0x060/0x020 filter
        0x146950,0x146974,            # MS 0x020/0x060 filter
    ]
    for t in targets:
        addr=A(t)
        refs=list(refmgr.getReferencesTo(addr))
        print(f"\n=== refs to 0x{t:06X}: {len(refs)} ===")
        for r in refs[:20]:
            fr=r.getFromAddress()
            f=fm.getFunctionContaining(fr)
            print(f"  from {fr} ({r.getReferenceType()}) in {f.getName() if f else '?'}@{f.getEntryPoint() if f else '?'}")
finally:
    project.close()
