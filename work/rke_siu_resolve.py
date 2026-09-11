import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing(); fm=program.getFunctionManager()
    insns=list(listing.getInstructions(True))
    def fname(a):
        f=fm.getFunctionContaining(a); return f.getName() if f else "?"

    # our pad registers of interest (SIUL base 0xC3F90000)
    SIU=0xC3F90000
    def pad(port,pin):
        base={'A':0,'B':16,'C':32,'D':48,'E':64,'F':80,'G':96,'H':112,'I':128}[port]
        return base+pin
    PI15=pad('I',15); PF12=pad('F',12)  # 143, 92
    interest={}
    for nm,pd in (("PI15",PI15),("PF12",PF12)):
        interest[SIU+0x800+pd]="GPDI_%s(in)"%nm
        interest[SIU+0x600+pd]="GPDO_%s(out)"%nm
        interest[SIU+0x40+2*pd]="PCR_%s"%nm
    # parallel regs (16-bit per port): PGPDO@0x0C00+2n, PGPDI@0x0C40+2n ; port I idx8, F idx5
    interest[SIU+0x0C00+2*8]="PGPDO_portI"; interest[SIU+0x0C40+2*8]="PGPDI_portI"
    interest[SIU+0x0C00+2*5]="PGPDO_portF"; interest[SIU+0x0C40+2*5]="PGPDI_portF"
    # MPGPDO masked out @0x0C80+4n
    interest[SIU+0x0C80+4*8]="MPGPDO_portI"; interest[SIU+0x0C80+4*5]="MPGPDO_portF"

    def reg_of(op_objs):
        rs=[o for o in op_objs if o.__class__.__name__=="Register"]
        sc=[o for o in op_objs if o.__class__.__name__=="Scalar"]
        return (rs[0] if rs else None, sc[0] if sc else None)

    LS={"e_lbz","e_stb","e_lhz","e_sth","e_lwz","e_stw","lbz","stb","lhz","sth","lwz","stw",
        "e_lbzu","e_stbu","se_lwz","se_stw","se_lbz","se_stb","se_lhz","se_sth"}
    hits=[]           # (addr, func, access, EA, regname)
    allSIUpage=[]     # every EA in 0xC3F90000..0xC3F90FFF
    val={}            # regname -> int const (linear approx, reset on branch target boundaries is skipped for simplicity)
    for ins in insns:
        mn=ins.getMnemonicString()
        try:
            if mn in ("e_lis","lis"):
                rd=ins.getRegister(0); sc=ins.getScalar(1)
                if rd is not None and sc is not None: val[rd.getName()]=(sc.getUnsignedValue()&0xFFFF)<<16
                continue
            if mn in ("e_li","li","se_li"):
                rd=ins.getRegister(0); sc=ins.getScalar(1)
                if rd is not None and sc is not None: val[rd.getName()]=sc.getSignedValue()&0xFFFFFFFF
                continue
            if mn in ("e_add16i","e_addi","se_addi","addi"):
                # rd = rs + imm  (e_add16i rd,rs,imm ; se_addi rd,imm)
                regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                scs=None
                for k in range(ins.getNumOperands()):
                    if ins.getScalar(k) is not None: scs=ins.getScalar(k)
                if regs and scs is not None:
                    rd=regs[0].getName()
                    rs=regs[1].getName() if len(regs)>1 else rd
                    if rs in val: val[rd]=(val[rs]+scs.getSignedValue())&0xFFFFFFFF
                    else: val.pop(rd,None)
                continue
            if mn in ("e_or2i","ori","e_add2i.","oris"):
                regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                sc=None
                for k in range(ins.getNumOperands()):
                    if ins.getScalar(k) is not None: sc=ins.getScalar(k)
                if regs and sc is not None:
                    rd=regs[0].getName()
                    if rd in val: val[rd]=(val[rd]|(sc.getUnsignedValue()))&0xFFFFFFFF
                continue
            if mn in LS:
                # find base reg + disp in the memory operand (last operand)
                nop=ins.getNumOperands()
                base=None; disp=0
                for oi in range(nop):
                    objs=list(ins.getOpObjects(oi))
                    r,s=reg_of(objs)
                    if r is not None and (s is not None or oi==nop-1):
                        # heuristic: memory operand has a register; prefer one with scalar
                        if s is not None:
                            base=r; disp=s.getSignedValue(); 
                        elif base is None:
                            base=r; disp=0
                if base is not None and base.getName() in val:
                    ea=(val[base.getName()]+disp)&0xFFFFFFFF
                    acc="ST" if ("st" in mn) else "LD"
                    if 0xC3F90000<=ea<=0xC3F90FFF:
                        allSIUpage.append((ins.getAddress(),fname(ins.getAddress()),acc,ea,mn))
                    if ea in interest:
                        hits.append((ins.getAddress(),fname(ins.getAddress()),acc,ea,interest[ea],mn))
                # a load/store may clobber rd for loads
        except Exception as e:
            pass
    print("=== DIRECT hits on our pad registers ===")
    if hits:
        for a,f,acc,ea,tag,mn in hits:
            print("  @%s [%s] %s %s 0x%08X (%s)"%(a,f,acc,mn,ea,tag))
    else:
        print("  (none)")
    print("\n=== ALL resolved EAs in SIUL page 0xC3F90xxx (grouped by offset) ===")
    from collections import defaultdict
    byoff=defaultdict(list)
    for a,f,acc,ea,mn in allSIUpage:
        byoff[ea-0xC3F90000].append((str(a),f,acc,mn))
    for off in sorted(byoff):
        lst=byoff[off]
        print("  +0x%04X (0x%08X): %d  e.g. %s"%(off,0xC3F90000+off,len(lst),lst[0]))
finally:
    project.close()
