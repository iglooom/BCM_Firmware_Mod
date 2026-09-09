import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    mem=program.getMemory()
    print("=== MEMORY BLOCKS ===")
    for b in mem.getBlocks():
        print("  %-16s %s..%s  r=%s w=%s x=%s init=%s size=0x%X"%(
            b.getName(),b.getStart(),b.getEnd(),b.isRead(),b.isWrite(),b.isExecute(),b.isInitialized(),b.getSize()))
    print("num instructions:", program.getListing().getNumInstructions())
    print("num defined data:", program.getListing().getNumDefinedData())
    # context register for VLE
    pc=program.getProgramContext()
    for rn in ["vle","VLE"]:
        r=pc.getRegister(rn)
        print("reg",rn,"->",r)
    print("registers:", [str(r.getName()) for r in pc.getRegisters()][:40])
finally:
    project.close()
