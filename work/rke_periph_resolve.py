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
    LS=LD|ST

    peri=defaultdict(list)
    def note(ea,ins,acc,mn):
        if (0xC3F80000<=ea<=0xC3FFFFFF) or (0xFFE00000<=ea<=0xFFFFFFFF):
            peri[ea].append((str(ins.getAddress()),fname(ins.getAddress()),acc,mn))

    def opparse_ls(ins):
        base=None; disp=0
        for oi in range(ins.getNumOperands()):
            objs=list(ins.getOpObjects(oi))
            rs=[o for o in objs if o.__class__.__name__.endswith(".Register")]
            sc=[o for o in objs if o.__class__.__name__.endswith(".Scalar")]
            if rs and sc:
                base=rs[0].getName(); disp=sc[0].getSignedValue()
            elif rs and oi>0 and base is None:
                base=rs[0].getName(); disp=0
        return base,disp

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
                elif mn in LS:
                    base,disp=opparse_ls(ins)
                    if base in val:
                        ea=(val[base]+disp)&0xFFFFFFFF
                        note(ea,ins,("ST" if mn in ST else "LD"),mn)
                        if mn in LD:
                            rd=ins.getRegister(0)
                            w=rd32(ea)
                            if rd is not None:
                                if w is not None and ((w>>24)in(0xC3,0xFF)): val[rd.getName()]=w
                                else: val.pop(rd.getName(),None)
            except Exception:
                pass

    SIU=0xC3F90000
    def padof(port,pin):
        b={'A':0,'B':16,'C':32,'D':48,'E':64,'F':80,'G':96,'H':112,'I':128}[port]; return b+pin
    tgt={}
    for nm,pd in (("PI15",padof('I',15)),("PF12",padof('F',12))):
        tgt[SIU+0x800+pd]="GPDI_%s_IN"%nm; tgt[SIU+0x600+pd]="GPDO_%s_OUT"%nm; tgt[SIU+0x40+2*pd]="PCR_%s"%nm
    tgt[SIU+0xC40+2*8]="PGPDI_portI"; tgt[SIU+0xC40+2*5]="PGPDI_portF"
    tgt[SIU+0xC00+2*8]="PGPDO_portI"; tgt[SIU+0xC00+2*5]="PGPDO_portF"

    print("=== resolved peripheral EAs total:",sum(len(v) for v in peri.values()),"distinct:",len(peri))
    print("\n=== DIRECT pad-register hits (PI15/PF12) ===")
    hit=False
    for ea,tag in sorted(tgt.items()):
        if ea in peri:
            hit=True
            for a,fn,acc,mn in peri[ea]: print("  %-14s 0x%08X @%s [%s] %s %s"%(tag,ea,a,fn,acc,mn))
    if not hit: print("  (none)")
    print("\n=== GPIO data-page EAs 0xC3F906xx(out)/08xx(in)/0Cxx(parallel) ===")
    g=[ea for ea in peri if 0xC3F90600<=ea<=0xC3F90FFF]
    for ea in sorted(g):
        off=ea-SIU
        kind = "GPDO" if 0x600<=off<0x800 else "GPDI" if 0x800<=off<0xA00 else "PARALLEL"
        print("  0x%08X (%s +0x%X) x%d e.g.%s[%s]%s"%(ea,kind,off,len(peri[ea]),peri[ea][0][0],peri[ea][0][1],peri[ea][0][3]))
    if not g: print("  (none)")
    print("\n=== peripheral pages touched (top 30) ===")
    pages=defaultdict(int)
    for ea,l in peri.items(): pages[ea&0xFFFFF000]+=len(l)
    for pg,c in sorted(pages.items(),key=lambda kv:-kv[1])[:30]:
        print("  page 0x%08X : %d"%(pg,c))
finally:
    project.close()
