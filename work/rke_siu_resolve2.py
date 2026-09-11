import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from collections import defaultdict
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing(); fm=program.getFunctionManager()
    SIU=0xC3F90000
    def pad(port,pin):
        base={'A':0,'B':16,'C':32,'D':48,'E':64,'F':80,'G':96,'H':112,'I':128}[port]; return base+pin
    PI15=pad('I',15); PF12=pad('F',12)
    interest={}
    for nm,pd in (("PI15",PI15),("PF12",PF12)):
        interest[SIU+0x800+pd]="GPDI_%s_IN"%nm
        interest[SIU+0x600+pd]="GPDO_%s_OUT"%nm
        interest[SIU+0x40+2*pd]="PCR_%s"%nm
    interest[SIU+0x0C40+2*8]="PGPDI_portI"; interest[SIU+0x0C40+2*5]="PGPDI_portF"
    interest[SIU+0x0C00+2*8]="PGPDO_portI"; interest[SIU+0x0C00+2*5]="PGPDO_portF"

    LD={"e_lbz","e_lhz","e_lwz","lbz","lhz","lwz","se_lwz","se_lbz","se_lhz"}
    ST={"e_stb","e_sth","e_stw","stb","sth","stw","se_stw","se_stb","se_sth"}
    LSX={"e_lbzx","lbzx","e_lhzx","lhzx","e_lwzx","lwzx","e_stbx","stbx","e_sthx","sthx","e_stwx","stwx"}
    LS=LD|ST

    perioff=defaultdict(list)   # EA -> [(addr,func,acc)]
    padhits=[]
    idxbase=[]                  # indexed loads whose base is in a pad table range

    funcs=list(fm.getFunctions(True))
    for f in funcs:
        val={}
        body=f.getBody()
        it=listing.getInstructions(body,True)
        for ins in it:
            mn=ins.getMnemonicString()
            try:
                if mn in ("e_lis","lis"):
                    rd=ins.getRegister(0); sc=ins.getScalar(1)
                    if rd and sc is not None: val[rd.getName()]=(sc.getUnsignedValue()&0xFFFF)<<16
                    continue
                if mn in ("e_li","li","se_li"):
                    rd=ins.getRegister(0); sc=ins.getScalar(1)
                    if rd and sc is not None: val[rd.getName()]=sc.getSignedValue()&0xFFFFFFFF
                    continue
                if mn in ("e_add16i","e_addi","addi","se_addi","e_add2i","e_add2i."):
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                    sc=None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None: sc=ins.getScalar(k)
                    if regs and sc is not None:
                        rd=regs[0].getName(); rs=(regs[1].getName() if len(regs)>1 else rd)
                        if rs in val: val[rd]=(val[rs]+sc.getSignedValue())&0xFFFFFFFF
                        else: val.pop(rd,None)
                    continue
                if mn in ("e_or2i","oris","ori"):
                    rd=ins.getRegister(0); sc=None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None: sc=ins.getScalar(k)
                    if rd and sc is not None and rd.getName() in val:
                        val[rd.getName()]=(val[rd.getName()]|sc.getUnsignedValue())&0xFFFFFFFF
                    continue
                if mn in LSX:
                    # indexed: rD, rA, rB  -> EA=rA+rB ; check if rA (or rB) resolved into a pad-table base
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                    for r in regs:
                        b=val.get(r.getName())
                        if b is not None and (0xC3F90000<=b<=0xC3F90FFF):
                            idxbase.append((str(ins.getAddress()),f.getName(),mn,r.getName(),b))
                    continue
                if mn in LS:
                    nop=ins.getNumOperands(); base=None; disp=0
                    for oi in range(nop):
                        objs=list(ins.getOpObjects(oi))
                        rs=[o for o in objs if o.__class__.__name__=="Register"]
                        sc=[o for o in objs if o.__class__.__name__=="Scalar"]
                        if rs:
                            if sc: base=rs[0]; disp=sc[0].getSignedValue()
                            elif base is None: base=rs[0]; disp=0
                    if base is not None and base.getName() in val:
                        ea=(val[base.getName()]+disp)&0xFFFFFFFF
                        acc="ST" if mn in ST else "LD"
                        if 0xC3F80000<=ea<=0xC3FFFFFF or 0xFFF40000<=ea<=0xFFF4FFFF:
                            perioff[ea].append((str(ins.getAddress()),f.getName(),acc,mn))
                        if ea in interest:
                            padhits.append((str(ins.getAddress()),f.getName(),acc,mn,ea,interest[ea]))
                    # load clobbers rd
                    if mn in LD:
                        rd=ins.getRegister(0)
                        if rd: val.pop(rd.getName(),None)
            except Exception:
                pass

    print("=== DIRECT pad-register hits (PI15/PF12 GPDI/GPDO/PCR, PGPDI/PGPDO port I/F) ===")
    if padhits:
        for a,fn,acc,mn,ea,tag in padhits: print("  @%s [%s] %s %s 0x%08X %s"%(a,fn,acc,mn,ea,tag))
    else: print("  (none)")
    print("\n=== indexed loads with base resolved into SIUL pad page ===")
    if idxbase:
        for a,fn,mn,rn,b in idxbase: print("  @%s [%s] %s base %s=0x%08X"%(a,fn,mn,rn,b))
    else: print("  (none)")
    print("\n=== resolved EAs in 0xC3F8xxxx..0xC3FFxxxx / 0xFFF4xxxx (by addr) ===")
    for ea in sorted(perioff):
        lst=perioff[ea]
        print("  0x%08X x%d  e.g. %s [%s] %s"%(ea,len(lst),lst[0][0],lst[0][1],lst[0][3]))
finally:
    project.close()
