import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing(); fm=program.getFunctionManager()
    insns=list(listing.getInstructions(True))
    idx={ins.getAddress().getOffset():i for i,ins in enumerate(insns)}
    def fname(a):
        f=fm.getFunctionContaining(a); return f.getName() if f else "?"
    # find e_lis rX,0xC3F9  (and se variants); then look ahead a few insns for the reg being used with a displacement / e_add16i / e_or2i
    print("=== e_lis rX,0xC3F9 sites, with following context ===")
    for i,ins in enumerate(insns):
        mn=ins.getMnemonicString()
        if mn not in ("e_lis","lis","se_lis"): continue
        sc=ins.getScalar(1)
        if sc is None or (sc.getUnsignedValue()&0xFFFF)!=0xC3F9: continue
        rd=ins.getRegister(0)
        rname=rd.getName() if rd else "?"
        # gather next up to 8 insns mentioning rname
        ctx=[]
        for j in range(i, min(i+9,len(insns))):
            t=insns[j]
            s=str(t)
            if j==i or (rname and rname in s) or t.getMnemonicString() in ("e_add16i","e_or2i","e_lbz","e_stb","e_lhz","e_sth","e_lwz","e_stw"):
                ctx.append("      %s  %s"%(t.getAddress(), s))
            if len(ctx)>=7: break
        print("  @%s  [%s]  rd=%s"%(ins.getAddress(), fname(ins.getAddress()), rname))
        for c in ctx: print(c)
        print()
finally:
    project.close()
