import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import RegisterValue, LanguageID
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.util import DefaultLanguageService
import java.math.BigInteger as BigInteger
import java.io.File as File

PROJ="/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl"
BIN="/home/gl/Projects/ford/BCM/Research/work/sbl_merged.bin"
BASE=0x40002000
CALL=0x40002000
monitor=ConsoleTaskMonitor()

gp=GhidraProject.createProject(PROJ,"SBL",False)
ls=DefaultLanguageService.getLanguageService()
lang=ls.getLanguage(LanguageID("PowerPC:BE:64:VLE-32addr"))
cspec=lang.getDefaultCompilerSpec()
prog=gp.importProgram(File(BIN), lang, cspec)

tx=prog.startTransaction("setup")
af=prog.getAddressFactory(); space=af.getDefaultAddressSpace()
def A(a): return space.getAddress(a)
# set image base
prog.setImageBase(A(BASE), True)
mem=prog.getMemory()
for b in mem.getBlocks():
    print("block",b.getName(),hex(b.getStart().getOffset()),hex(b.getEnd().getOffset()))
# add peripheral space for FlexCAN/flash controller if referenced
try:
    mem.createUninitializedBlock("PERIPH", A(0xC3F00000), 0x100000, False)
except Exception as e: print("periph:",e)
try:
    mem.createUninitializedBlock("PERIPH2", A(0xFFF00000), 0x100000, False)
except Exception as e: print("periph2:",e)

# VLE=1 across the code block0 range 0x40002000..0x4000E3B8
pc=prog.getProgramContext(); vle=pc.getRegister("vle")
pc.setRegisterValue(A(0x40002000), A(0x4000E3B8),
                    RegisterValue(vle, BigInteger.valueOf(1)))
st=prog.getSymbolTable(); st.addExternalEntryPoint(A(CALL))
cmd=DisassembleCommand(A(CALL), None, True); cmd.applyTo(prog, monitor)
print("instr after entry disasm:", prog.getListing().getNumInstructions())
prog.endTransaction(tx,True)
gp.saveAs(prog, "/", "sbl_merged.bin", True); gp.close()
print("DONE")
