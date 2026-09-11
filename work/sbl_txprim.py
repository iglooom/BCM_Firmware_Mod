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
    tx=prog.startTransaction("d3")
    for t in (0x40004cf2,):
        DisassembleCommand(A(t),None,True).applyTo(prog,monitor)
    prog.endTransaction(tx,True); gp.save(prog)
    lst=prog.getListing()
    def dump(a,e,tag):
        print(f"\n===== {tag} {hex(a)}..{hex(e)} =====")
        ins=lst.getInstructions(A(a),True); c=ins.next()
        while c and c.getAddress().getOffset()<e:
            ad=c.getAddress().getOffset(); rs=c.getReferencesFrom(); rr=""
            for r in rs:
                if r.getReferenceType().isData() or r.getReferenceType().isCall() or r.getReferenceType().isJump():
                    rr+=f"  ->{r.getToAddress()}"
            print(f"{hex(ad)}  {c}{rr}")
            c=ins.next()
    dump(0x40004cf2,0x40004d48,"FUN_40004cf2 seed-handler")
    dump(0x40002f8c,0x400030ae,"FUN_40002f8c TX-primitive")
    dump(0x40002dce,0x40002e2c,"FUN_40002dce")
    dump(0x40002d42,0x40002dce,"FUN_40002d42")
    dump(0x40002f2e,0x40002f8c,"FUN_40002f2e")
finally:
    gp.close()
