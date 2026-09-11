import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
monitor=ConsoleTaskMonitor()
gp=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl","SBL",False)
prog=gp.openProgram("/","sbl_merged.bin",False)
try:
    af=prog.getAddressFactory().getDefaultAddressSpace()
    def A(a): return af.getAddress(a)
    tx=prog.startTransaction("d2")
    # VLE already =1 across 0x40002000..0x4000e3b8. Just disassemble from vtable targets.
    for t in (0x40006b68,0x40006b80,0x40006ba8,0x40006bc0,0x40004cbc):
        DisassembleCommand(A(t),None,True).applyTo(prog,monitor)
    # also linear-sweep the un-analyzed gap 0x400052d4..0x4000c000 by trying each 2-byte boundary that isn't yet code
    prog.endTransaction(tx,True); gp.save(prog)
    fm=prog.getFunctionManager()
    print("functions now:", fm.getFunctionCount())
    lst=prog.getListing()
    for t in (0x40006b68,0x40006b80,0x40006ba8,0x40006bc0,0x40004cbc):
        print(f"\n===== @ {hex(t)} =====")
        ins=lst.getInstructions(A(t),True); c=ins.next(); n=0
        while c and n<45:
            s=str(c)
            print(f"{c.getAddress()}  {s}")
            if s.startswith("se_blr") or s.startswith("se_rfi"): break
            c=ins.next(); n+=1
finally:
    gp.close()
