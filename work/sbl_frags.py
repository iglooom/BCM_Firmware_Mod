import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.lang import RegisterValue
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
import java.math.BigInteger as BigInteger
monitor=ConsoleTaskMonitor()
gp=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl","SBL",False)
prog=gp.openProgram("/","sbl_merged.bin",False)
try:
    af=prog.getAddressFactory().getDefaultAddressSpace()
    def A(a): return af.getAddress(a)
    tx=prog.startTransaction("disasm frags")
    pc=prog.getProgramContext(); vle=pc.getRegister("vle")
    for a,e in ((0x4000e480,0x4000e556),(0x4000e600,0x4000e6ee)):
        pc.setRegisterValue(A(a),A(e),RegisterValue(vle,BigInteger.valueOf(1)))
        DisassembleCommand(A(a),None,True).applyTo(prog,monitor)
    prog.endTransaction(tx,True)
    gp.save(prog)
    lst=prog.getListing()
    for a,e in ((0x4000e480,0x4000e556),(0x4000e600,0x4000e6ee)):
        print(f"\n===== frag {hex(a)}..{hex(e)} =====")
        ins=lst.getInstructions(A(a),True)
        cur=ins.next()
        while cur and cur.getAddress().getOffset()<e:
            print(f"{cur.getAddress()}  {cur}")
            cur=ins.next()
finally:
    gp.close()
