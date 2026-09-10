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
    # Count CODE refs to the WHOLE signal band 0x40000600..0x40000E00 to see if ANY cell is read by code.
    band_lo,band_hi=0x40000600,0x40000E00
    codecells={}
    for t in range(band_lo,band_hi):
        code=[r for r in refmgr.getReferencesTo(A(t)) if 0x10000<=r.getFromAddress().getOffset()<0x140000]
        if code: codecells[t]=len(code)
    print(f"signal-band cells with >=1 CODE ref: {len(codecells)} / {band_hi-band_lo}")
    # show a sample
    for t in sorted(codecells)[:40]:
        print(f"  0x{t:08X}: {codecells[t]} code refs")
finally:
    project.close()
