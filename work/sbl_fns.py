import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
monitor=ConsoleTaskMonitor()
gp=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl","SBL",False)
prog=gp.openProgram("/","sbl_merged.bin",False)
try:
    fm=prog.getFunctionManager()
    fns=sorted(fm.getFunctions(True), key=lambda f:f.getEntryPoint().getOffset())
    print("=== %d functions ===" % fm.getFunctionCount())
    for f in fns:
        body=f.getBody()
        print(f"{f.getEntryPoint()}  size={body.getNumAddresses():5d}  {f.getName()}  called_by={len(f.getCallingFunctions(monitor))}")
finally:
    gp.close()
