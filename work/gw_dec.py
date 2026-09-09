import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
monitor=ConsoleTaskMonitor()
try:
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    fm=program.getFunctionManager()
    di=DecompInterface(); di.openProgram(program)
    for s in sys.argv[1:]:
        ent=int(s,16)
        f=fm.getFunctionAt(A(ent)) or fm.getFunctionContaining(A(ent))
        if not f:
            print("no func at",hex(ent)); continue
        res=di.decompileFunction(f,90,monitor)
        print(f"\n==================== {f.getName()} @ {f.getEntryPoint()} ====================")
        if res and res.decompileCompleted():
            print(res.getDecompiledFunction().getC())
        else:
            print("FAILED:",res.getErrorMessage() if res else "none")
finally:
    project.close()
