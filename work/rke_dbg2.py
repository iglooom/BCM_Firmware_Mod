import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing(); fm=program.getFunctionManager()
    f=fm.getFunctionContaining(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3592e))
    val={}
    LD={"e_lbz","e_lhz","e_lwz","lbz","lhz","lwz","se_lwz","se_lbz","se_lhz"}
    ST={"e_stb","e_sth","e_stw","stb","sth","stw","se_stw","se_stb","se_sth"}
    LS=LD|ST
    for ins in listing.getInstructions(f.getBody(),True):
        mn=ins.getMnemonicString()
        if mn in ("e_lis","lis"):
            rd=ins.getRegister(0); sc=ins.getScalar(1)
            if rd and sc is not None: val[rd.getName()]=(sc.getUnsignedValue()&0xFFFF)<<16
        elif mn in ("e_addi","e_add16i","addi","se_addi"):
            regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
            sc=None
            for k in range(ins.getNumOperands()):
                if ins.getScalar(k) is not None: sc=ins.getScalar(k)
            if regs and sc is not None:
                rd=regs[0].getName(); rs=(regs[1].getName() if len(regs)>1 else rd)
                if rs in val: val[rd]=(val[rs]+sc.getSignedValue())&0xFFFFFFFF
                else: val.pop(rd,None)
        elif mn in LS:
            base=None; disp=0
            for oi in range(ins.getNumOperands()):
                objs=list(ins.getOpObjects(oi))
                rs=[o for o in objs if o.__class__.__name__=="Register"]
                sc=[o for o in objs if o.__class__.__name__=="Scalar"]
                if rs and sc: base=rs[0].getName(); disp=sc[0].getSignedValue()
                elif rs and base is None and oi>0: base=rs[0].getName(); disp=0
            resolved = (val[base]+disp)&0xFFFFFFFF if base in val else None
            print("  %s %-22s base=%s disp=0x%X -> EA=%s"%(ins.getAddress(),str(ins),base,disp&0xFFFFFFFF, ("0x%08X"%resolved) if resolved else "?"))
            if mn in LD:
                rd=ins.getRegister(0)
                if rd: val.pop(rd.getName(),None)
finally:
    project.close()
