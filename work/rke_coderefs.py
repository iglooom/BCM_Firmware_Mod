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
    # scan every code ref target in the MS 0x100 image page + MS-net frameObj/flag block
    ranges = list(range(0x40000918,0x40000920)) + list(range(0x400004FC,0x40000500)) + [0x400004FE]
    hits={}
    for t in ranges:
        for r in refmgr.getReferencesTo(A(t)):
            fr=r.getFromAddress().getOffset()
            if 0x10000<=fr<0x140000:   # CODE only
                f=fm.getFunctionContaining(r.getFromAddress())
                key=(f.getName(),f.getEntryPoint().toString()) if f else ("?",hex(fr))
                hits.setdefault(key,[]).append((t,fr,str(r.getReferenceType())))
    if not hits:
        print("NO code refs to image page or MS frameObj block (all data-table).")
    for k,v in hits.items():
        print(f"\nFUNC {k[0]} @{k[1]}:")
        for t,fr,rt in v: print(f"   0x{t:08X} <- 0x{fr:06X} {rt}")
finally:
    project.close()
