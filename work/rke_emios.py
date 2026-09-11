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
    def A(x):return af.getAddress(x)
    def rd32(a):
        try:
            b=bytearray(4);mem.getBytes(A(a),b);return int.from_bytes(bytes(b),"big")
        except:return None
    def R(o):return o.__class__.__name__.endswith(".Register")
    def S(o):return o.__class__.__name__.endswith(".Scalar")
    LD={"e_lbz","e_lhz","e_lwz","lbz","lhz","lwz","se_lwz","se_lbz","se_lhz"}
    ST={"e_stb","e_sth","e_stw","stb","sth","stw","se_stw","se_stb","se_sth"}
    LS=LD|ST
    E0,E1=0xC3FA0000,0xC3FA4000
    hits=defaultdict(int); chan=defaultdict(set); accesses=defaultdict(list); indexed=[]
    for f in fm.getFunctions(True):
        val={}
        for ins in listing.getInstructions(f.getBody(),True):
            mn=ins.getMnemonicString()
            try:
                if mn in ("e_lis","lis"):
                    rd=ins.getRegister(0);sc=ins.getScalar(1)
                    if rd and sc is not None: val[rd.getName()]=(sc.getUnsignedValue()&0xFFFF)<<16
                elif mn in ("e_add16i","e_addi","addi","se_addi"):
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)];sc=None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None:sc=ins.getScalar(k)
                    if regs and sc is not None:
                        rd=regs[0].getName();rs=(regs[1].getName() if len(regs)>1 else rd)
                        if rs in val:val[rd]=(val[rs]+sc.getSignedValue())&0xFFFFFFFF
                        else:val.pop(rd,None)
                elif mn in {"e_lbzx","lbzx","e_lhzx","lhzx","e_lwzx","lwzx","e_stbx","stbx","e_sthx","sthx","e_stwx","stwx"}:
                    regs=[ins.getRegister(k) for k in range(ins.getNumOperands()) if ins.getRegister(k)]
                    for reg in regs:
                        base=val.get(reg.getName())
                        if base is not None and E0 <= base < E1 + 0x400:
                            indexed.append((str(ins.getAddress()),f.getName(),mn,reg.getName(),base))
                elif mn in LS:
                    base=None;disp=0
                    for oi in range(ins.getNumOperands()):
                        objs=list(ins.getOpObjects(oi));rs=[o for o in objs if R(o)];sc=[o for o in objs if S(o)]
                        if rs and sc:base=rs[0].getName();disp=sc[0].getSignedValue()
                        elif rs and oi>0 and base is None:base=rs[0].getName();disp=0
                    if base in val:
                        ea=(val[base]+disp)&0xFFFFFFFF
                        for nm,b in (("eMIOS0",E0),("eMIOS1",E1)):
                            if b<=ea<b+0x400:
                                hits[nm]+=1
                                off=ea-b
                                accesses[nm].append((str(ins.getAddress()),f.getName(),mn,ea,off))
                                if off>=0x20: chan[nm].add((off-0x20)//0x20)
                        if mn in LD:
                            rd=ins.getRegister(0);w=rd32(ea)
                            if rd is not None:
                                if w is not None and (w>>24)in (0xC3,0xFF):val[rd.getName()]=w
                                else:val.pop(rd.getName(),None)
            except Exception:
                pass
    print("eMIOS access counts:",dict(hits))
    print("eMIOS_0 channels touched:",sorted(chan["eMIOS0"]))
    print("eMIOS_1 channels touched:",sorted(chan["eMIOS1"]),"  <-- PF12 = eMIOS_1 ch25")
    print("eMIOS_1 channel 25 touched:",25 in chan["eMIOS1"])
    print("\n=== eMIOS access sites ===")
    for module in ("eMIOS0","eMIOS1"):
        print(module)
        for site,function,mn,ea,off in accesses[module]:
            channel = ((off-0x20)//0x20) if off >= 0x20 else None
            print("  @%s [%s] %-8s 0x%08X +0x%03X channel=%s" %
                  (site,function,mn,ea,off,channel))
    print("\n=== indexed accesses with a statically known eMIOS base ===")
    for row in indexed:
        print("  @%s [%s] %s base %s=0x%08X" % row)
    if not indexed:
        print("  (none)")
finally:
    project.close()
