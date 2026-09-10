import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    fm=program.getFunctionManager()
    listing=program.getListing()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    # Scan ALL instructions in code region for any that reference (as a resolved operand address or
    # scalar) an address in the 0x100 MS image page 0x40000918..0x4000091F, OR the whole frame page
    # 0x40000900..0x40000940 (RFA frames cluster), regardless of Ghidra's reference DB.
    lo,hi=0x40000900,0x40000940
    insts=listing.getInstructions(A(0x10000),True)
    n=0; found=0
    while insts.hasNext():
        ins=insts.next()
        ea=ins.getAddress().getOffset()
        if ea>=0x140000: break
        n+=1
        # check resolved refs from this instruction
        for r in ins.getReferencesFrom():
            t=r.getToAddress().getOffset()
            if lo<=t<hi:
                f=fm.getFunctionContaining(ins.getAddress())
                print(f"@0x{ea:06X} {ins}  -> 0x{t:08X}  in {f.getName() if f else '?'}")
                found+=1
    print(f"\nscanned {n} instructions; {found} touch 0x40000900-page")
finally:
    project.close()
