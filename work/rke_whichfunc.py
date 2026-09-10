import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    fm=program.getFunctionManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    for a in (0x018CB3,0x04EC25,0x07D32B):
        f=fm.getFunctionContaining(A(a))
        cu=program.getListing().getCodeUnitContaining(A(a))
        print(f"0x{a:06X}: func={f.getName()+'@'+f.getEntryPoint().toString() if f else 'NONE(not in a function)'}  cu={cu}")
finally:
    project.close()
