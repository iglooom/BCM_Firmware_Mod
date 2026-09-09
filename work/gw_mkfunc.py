import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
monitor=ConsoleTaskMonitor()
try:
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    fm=program.getFunctionManager()
    from ghidra.app.cmd.function import CreateFunctionCmd
    for s in sys.argv[1:]:
        ent=int(s,16)
        a=A(ent)
        f=fm.getFunctionContaining(a)
        if f:
            print(f"0x{ent:X}: inside {f.getName()} @ {f.getEntryPoint()}")
        else:
            # try to create a function here
            cmd=CreateFunctionCmd(a)
            ok=cmd.applyTo(program,monitor)
            print(f"0x{ent:X}: no func; create={ok} -> {cmd.getFunction()}")
finally:
    project.close()
