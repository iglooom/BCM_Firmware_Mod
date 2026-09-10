import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
try:
    fm=program.getFunctionManager()
    refmgr=program.getReferenceManager()
    af=program.getAddressFactory().getDefaultAddressSpace()
    def A(x): return af.getAddress(x)
    # Which code references the signal-descriptor table / routing table bases?
    for label,rng in [("sig-desc tbl 0x15A920..0x15B200",range(0x15A920,0x15B200,4)),
                      ("routing tbl 0x140000..0x140400",range(0x140000,0x140400,4))]:
        funcs={}
        for t in rng:
            for r in refmgr.getReferencesTo(A(t)):
                fr=r.getFromAddress().getOffset()
                if 0x10000<=fr<0x140000:
                    f=fm.getFunctionContaining(r.getFromAddress())
                    k=f.getName()+"@"+f.getEntryPoint().toString() if f else "?@%06x"%fr
                    funcs.setdefault(k,0); funcs[k]+=1
        print(f"\n[{label}] code referrers:")
        for k,v in sorted(funcs.items(),key=lambda x:-x[1])[:15]:
            print(f"   {k}  x{v}")
finally:
    project.close()
