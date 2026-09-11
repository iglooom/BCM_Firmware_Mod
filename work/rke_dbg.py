import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    # inspect the known site 0x0003592e region: e_lis r7,c3f9; e_addi r7,r7,0x4000; se_lwz r6,0x18(r7)
    for a in (0x3592e,0x35932,0x35936):
        ins=listing.getInstructionAt(A(a))
        print("@%s  %s   numOps=%d"%(ins.getAddress(),ins,ins.getNumOperands()))
        for oi in range(ins.getNumOperands()):
            objs=list(ins.getOpObjects(oi))
            print("    op%d objtypes=%s vals=%s"%(oi,[o.__class__.__name__ for o in objs],
                  [ (o.getName() if o.__class__.__name__=='Register' else (o.getValue() if hasattr(o,'getValue') else str(o))) for o in objs]))
        r0=ins.getRegister(0); s1=ins.getScalar(1)
        print("    getRegister(0)=%s getScalar(1)=%s"%(r0, s1))
finally:
    project.close()
