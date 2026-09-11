import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from collections import defaultdict
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing(); fm=program.getFunctionManager(); mem=program.getMemory()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    def fname(a):
        f=fm.getFunctionContaining(a); return f.getName() if f else "?"
    def rd32(addr):
        try:
            b=bytearray(4); mem.getBytes(A(addr),b); return int.from_bytes(bytes(b),"big")
        except: return None
    LD={"e_lbz","e_lhz","e_lwz","lbz","lhz","lwz","se_lwz","se_lbz","se_lhz"}
    ST={"e_stb","e_sth","e_stw","stb","sth","stw","se_stw","se_stb","se_sth"}
    LSX={"e_lbzx","lbzx","e_lhzx","lhzx","e_lwzx","lwzx","e_stbx","stbx","e_sthx","sthx","e_stwx","stwx",
         "se_lwzx","se_stwx"}
    LS=LD|ST
    def R(o): return o.__class__.__name__.endswith(".Register")
    def S(o): return o.__class__.__name__.endswith(".Scalar")
    def opparse(ins):
        base=None; disp=0
        for oi in range(ins.getNumOperands()):
            objs=list(ins.getOpObjects(oi))
            rs=[o for o in objs if R(o)]; sc=[o for o in objs if S(o)]
            if rs and sc: base=rs[0].getName(); disp=sc[0].getSignedValue()
            elif rs and oi>0 and base is None: base=rs[0].getName(); disp=0
        return base,disp

    siul=defaultdict(list)     # offset -> [(addr,func,acc,mn)]
    idxbase=[]                 # indexed accesses with a base register that resolved into SIUL
    for f in fm.getFunctions(True):
        val={}
        for ins in listing.getInstructions(f.getBody(),True):
            mn=ins.getMnemonicString()
            try:
                if mn in ("e_lis","lis"):
                    rd=ins.getRegister(0); sc=ins.getScalar(1)
                    if rd and sc is not None: val[rd.getName()]=(sc.getUnsignedValue()&0xFFFF)<<16
                elif mn in ("e_li","li","se_li"):
                    rd=ins.getRegister(0); sc=ins.getScalar(1)
                    if rd and sc is not None: val[rd.getName()]=sc.getSignedValue()&0xFFFFFFFF
                elif mn in ("e_add16i","e_addi","addi","se_addi"):
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                    sc=None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None: sc=ins.getScalar(k)
                    if regs and sc is not None:
                        rd=regs[0].getName(); rs=(regs[1].getName() if len(regs)>1 else rd)
                        if rs in val: val[rd]=(val[rs]+sc.getSignedValue())&0xFFFFFFFF
                        else: val.pop(rd,None)
                elif mn in ("e_or2i","oris","ori"):
                    rd=ins.getRegister(0); sc=None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None: sc=ins.getScalar(k)
                    if rd and sc is not None and rd.getName() in val:
                        val[rd.getName()]=(val[rd.getName()]|sc.getUnsignedValue())&0xFFFFFFFF
                elif mn in LSX:
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                    for r in regs:
                        b=val.get(r.getName())
                        if b is not None and 0xC3F90000<=b<=0xC3F90FFF:
                            idxbase.append((str(ins.getAddress()),fname(ins.getAddress()),mn,r.getName(),b))
                elif mn in LS:
                    base,disp=opparse(ins)
                    if base in val:
                        ea=(val[base]+disp)&0xFFFFFFFF
                        if 0xC3F90000<=ea<=0xC3F90FFF:
                            siul[ea-0xC3F90000].append((str(ins.getAddress()),fname(ins.getAddress()),("ST" if mn in ST else "LD"),mn))
                        if mn in LD:
                            rd=ins.getRegister(0); w=rd32(ea)
                            if rd is not None:
                                if w is not None and ((w>>24)in(0xC3,0xFF)): val[rd.getName()]=w
                                else: val.pop(rd.getName(),None)
            except Exception: pass

    def decode(off):
        if 0x40<=off<0x240 and off%2==0: return "PCR[%d]"%((off-0x40)//2)
        if 0x500<=off<0x502: return "GPDO?"
        if 0x600<=off<0x700: return "GPDO[pad %d]"%(off-0x600)
        if 0x800<=off<0x900: return "GPDI[pad %d]"%(off-0x800)
        if 0xC00<=off<0xC40: return "PGPDO[port %d]"%((off-0xC00)//2)
        if 0xC40<=off<0xC80: return "PGPDI[port %d]"%((off-0xC40)//2)
        if 0xC80<=off<0xD00: return "MPGPDO[port %d]"%((off-0xC80)//4)
        named={0x0:"MIDR1",0x4:"MIDR2",0x14:"ISR(EIRQ)",0x18:"IRER",0x28:"IREER",0x2C:"IFEER",0x30:"IFER",0x38:"IFMC?"}
        return named.get(off,"?")
    print("=== SIUL offsets accessed (absolute) ===")
    for off in sorted(siul):
        l=siul[off]
        print("  +0x%04X %-16s x%d  e.g. %s [%s] %s"%(off,decode(off),len(l),l[0][0],l[0][1],l[0][3]))
    print("\n=== indexed loads/stores with base in SIUL page (pad tables!) ===")
    if idxbase:
        for a,fn,mn,rn,b in idxbase: print("  @%s [%s] %s base %s=0x%08X (+0x%X %s)"%(a,fn,mn,rn,b,b-0xC3F90000,decode(b-0xC3F90000)))
    else: print("  (none)")
finally:
    project.close()
