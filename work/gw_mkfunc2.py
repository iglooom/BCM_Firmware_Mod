import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",True)
program = project.openProgram("/","flash_merged.bin",False)
monitor=ConsoleTaskMonitor()
tx=program.startTransaction("mkfuncs")
try:
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    fm=program.getFunctionManager()
    listing=program.getListing()
    targets=[int(x,16) for x in sys.argv[1:]] if len(sys.argv)>1 else [
        0x144B10,0x144B90,0x144DD0,0x145250,0x145760,0x145D00,0x146060,0x146330,0x144DC0]
    for ent in targets:
        a=A(ent)
        if listing.getInstructionAt(a) is None:
            dc=DisassembleCommand(a,None,True); dc.applyTo(program,monitor)
        f=fm.getFunctionContaining(a)
        if not f:
            cmd=CreateFunctionCmd(a); cmd.applyTo(program,monitor)
            f=cmd.getFunction()
        print(f"0x{ent:X}: {f.getName() if f else 'FAILED'}")
    program.endTransaction(tx,True)
    project.save(program)
    print("saved")
finally:
    try: project.close()
    except: pass
