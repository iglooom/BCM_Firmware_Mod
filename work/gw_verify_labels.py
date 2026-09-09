import os
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra; pyghidra.start()
from ghidra.base.project import GhidraProject
project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    st=program.getSymbolTable(); fm=program.getFunctionManager()
    space=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return space.getAddress(x)
    print("=== named functions (non-FUN_) ===")
    cnt=0
    for f in fm.getFunctions(True):
        n=f.getName()
        if not n.startswith("FUN_"):
            print("  0x%s  %s"%(f.getEntryPoint(), n)); cnt+=1
    print("total named funcs:",cnt)
    print("\n=== sample labels at key addrs ===")
    for x in (0x178B0,0x1464E0,0x146608,0x146698,0x146950,0x40000751,0x40000614,0x18000):
        syms=st.getSymbols(A(x))
        names=[s.getName() for s in syms]
        print("  0x%06X: %s"%(x,names))
    # count user labels
    from ghidra.program.model.symbol import SourceType
    ud=[s for s in st.getAllSymbols(False) if s.getSource()==SourceType.USER_DEFINED]
    print("\ntotal USER_DEFINED symbols:",len(ud))
finally:
    project.close()
