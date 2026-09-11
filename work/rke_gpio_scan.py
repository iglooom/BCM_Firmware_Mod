import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    listing=program.getListing()
    insns=list(listing.getInstructions(True))
    print("total insns:",len(insns))
    # Collect e_lis / se_lis style high-half loads: reg <- imm<<16, then track same-reg load/store displacement.
    # Build a histogram of (high<<16) values used as bases and, per base, the set of displacements seen.
    from collections import defaultdict
    base_disp=defaultdict(set)     # basehigh -> set(disp)
    base_count=defaultdict(int)
    # also raw: any instruction whose scalar operands include a 0xC3F9xxxx or 0xFFF4xxxx or 0xFFF9xxxx
    periph_hits=defaultdict(list)
    reg_hi={}  # regname -> high value at 'recent' (very rough, reset per basic-ish window)
    for ins in insns:
        mn=ins.getMnemonicString()
        # track register high loads
        if mn in ("e_lis","se_lis","lis"):
            try:
                rd=ins.getRegister(0)
                imm=ins.getScalar(1)
                if rd is not None and imm is not None:
                    reg_hi[rd.getName()]=(imm.getUnsignedValue()&0xFFFF)<<16
            except: pass
            continue
        # e_or2i / e_add16i / ori / addi that combine with a tracked high reg -> full address
        # load/store forms: e_lbz/e_stb/e_lhz/e_sth/e_lwz/e_stw rD, disp(rA)
        if mn in ("e_lbz","e_stb","e_lhz","e_sth","e_lwz","e_stw","lbz","stb","lhz","sth","lwz","stw",
                  "e_lbzu","e_stbu"):
            try:
                # operand pattern rD, disp(rA)
                ra=None; disp=None
                # scan objects
                n=ins.getNumOperands()
                # last operand is usually disp(reg)
                for oi in range(n):
                    objs=ins.getOpObjects(oi)
                    regs=[o for o in objs if hasattr(o,'getName') and o.__class__.__name__=='Register']
                    scs=[o for o in objs if o.__class__.__name__=='Scalar']
                    if regs and (scs or True):
                        # candidate base reg operand
                        rname=regs[0].getName()
                        d=scs[0].getSignedValue() if scs else 0
                        if rname in reg_hi:
                            full=reg_hi[rname]+d
                            if (full>>24) in (0xC3,0xFF):
                                base_disp[reg_hi[rname]].add(d)
                                base_count[reg_hi[rname]]+=1
                                if 0xC3F90000<=full<=0xC3F90FFF or 0xFFF48000<=full<=0xFFF48FFF or 0xFFF90000<=full<=0xFFF90FFF:
                                    periph_hits[full].append(str(ins.getAddress()))
            except: pass
    print("\n=== base-high values used most as load/store bases (top 25) ===")
    for b,c in sorted(base_count.items(), key=lambda kv:-kv[1])[:25]:
        print("  base 0x%08X  uses=%d  ndisp=%d"%(b,c,len(base_disp[b])))
    print("\n=== hits in candidate SIU/pad windows (C3F90xxx / FFF48xxx / FFF90xxx) ===")
    for full in sorted(periph_hits):
        print("  0x%08X : %s"%(full, periph_hits[full][:6]))
    if not periph_hits: print("  (none via reg-tracking; will need raw scan)")
finally:
    project.close()
