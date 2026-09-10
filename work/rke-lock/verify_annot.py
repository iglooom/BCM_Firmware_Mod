import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.listing import CodeUnit
ROOT="/home/gl/Projects/ford/BCM/Research"
project=GhidraProject.openProject(ROOT+"/ghidra_proj_accfix_rkelock","BCM_C1MCA",True)
program=project.openProgram("/","flash_merged.bin",True)
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
st=program.getSymbolTable(); listing=program.getListing()
try:
    print("=== LABELS ===")
    for a in (0x117100,0x117400,0x40000707,0x40000705,0x40011000,0x40000918,0x40000919,
              0x4000091F,0xFFFC42C8,0xFFFC4090,0x40011001,0x40011002):
        syms=[s.getName() for s in st.getSymbols(A(a)) if not s.isDynamic()]
        print("  0x%08X: %s"%(a,syms))
    print("\n=== HOOK EOL COMMENTS ===")
    for a in (0xFC2C2,0xFC440):
        print("  0x%X: %s"%(a,listing.getComment(CodeUnit.EOL_COMMENT,A(a))))
    print("\n=== BOOKMARKS (MOD/RKE-LOCK) ===")
    for bm in program.getBookmarkManager().getBookmarksIterator():
        if bm.getCategory() in ("MOD","RKE-LOCK"):
            print("  %s [%s] %s : %s"%(bm.getAddress(),bm.getTypeString(),bm.getCategory(),bm.getComment()))
    print("\n=== CAVE2 walker disasm (first 30 insns) ===")
    n=0
    for ins in listing.getInstructions(A(0x117400),True):
        print("  %s  %s"%(ins.getAddress(),ins))
        n+=1
        if n>=30: break
    print("\n=== plate comment present on cave2? ===")
    pc=listing.getComment(CodeUnit.PLATE_COMMENT,A(0x117400))
    print("  cave2 plate:", "YES (%d chars)"%len(pc) if pc else "MISSING")
    pc1=listing.getComment(CodeUnit.PLATE_COMMENT,A(0x40011002))
    print("  L3 plate:", "YES" if pc1 else "MISSING")
finally:
    project.close()
