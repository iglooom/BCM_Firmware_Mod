import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.symbol import SourceType
import java.math.BigInteger as BigInteger

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
monitor = ConsoleTaskMonitor()
try:
    tx = program.startTransaction("setup+disasm")
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    def addr(a): return space.getAddress(a)
    mem = program.getMemory()

    # add SRAM block (MPC5607B: 0x40000000, 96KB) uninitialized, and peripheral space
    from ghidra.program.model.mem import MemoryBlock
    try:
        mem.createUninitializedBlock("SRAM", addr(0x40000000), 0x18000, False)
        print("SRAM block created")
    except Exception as e:
        print("SRAM:", e)
    try:
        mem.createUninitializedBlock("PERIPH", addr(0xC3F00000), 0x100000, False)
        print("PERIPH block created")
    except Exception as e:
        print("PERIPH:", e)

    # set VLE=1 over the whole flash code region
    pc = program.getProgramContext()
    vle = pc.getRegister("vle")
    codeset = AddressSet(addr(0x00010000), addr(0x0013FFFF))
    pc.setRegisterValue(codeset.getMinAddress(), codeset.getMaxAddress(),
                        RegisterValue(vle, BigInteger.valueOf(1)))
    print("VLE context set on 0x10000..0x13FFFF")

    # entry point from RCHW
    entry = addr(0x0010F4A0)
    st = program.getSymbolTable()
    st.addExternalEntryPoint(entry)
    program.getFunctionManager()  # ensure
    # disassemble from entry (VLE)
    cmd = DisassembleCommand(entry, None, True)
    ok = cmd.applyTo(program, monitor)
    print("disasm from entry ok:", ok, " instr now:", program.getListing().getNumInstructions())
    program.endTransaction(tx, True)
    project.save(program)
    print("saved.")
finally:
    project.close()
