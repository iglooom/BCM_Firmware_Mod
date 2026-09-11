import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
monitor=ConsoleTaskMonitor()
gp=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl","SBL",False)
prog=gp.openProgram("/","sbl_merged.bin",False)
try:
    af=prog.getAddressFactory().getDefaultAddressSpace()
    def A(a): return af.getAddress(a)
    lst=prog.getListing(); fm=prog.getFunctionManager()
    refm=prog.getReferenceManager()

    def dump(a,e,tag):
        print(f"\n===== {tag}  {hex(a)}..{hex(e)} =====")
        ins=lst.getInstructions(A(a),True); c=ins.next()
        while c and c.getAddress().getOffset()<e:
            ad=c.getAddress().getOffset()
            # show any reference target
            rs=c.getReferencesFrom()
            refstr=""
            for r in rs:
                if r.getReferenceType().isData() or r.getReferenceType().isCall() or r.getReferenceType().isJump():
                    refstr+=f"  ->{r.getToAddress()}"
            print(f"{hex(ad)}  {c}{refstr}")
            c=ins.next()

    # 1. raw disasm of transfer executor
    dump(0x40003502,0x400037dc,"FUN_40003502 transfer-exec")
    # 2. how DAT_400021b0 is loaded: disasm dispatcher head
    dump(0x40003f66,0x40003fb0,"dispatcher head")
    # 3. xrefs to 0x40004cbc and FUN_40003502
    for t in (0x40004cbc,0x40003502):
        print(f"\n--- xrefs to {hex(t)} ---")
        it=refm.getReferencesTo(A(t))
        for r in it:
            print("   from",r.getFromAddress(),r.getReferenceType())
    # 4. resolve DAT_400021b0 literal: read the word and see what references it
    print("\n--- refs to 0x400021b0 ---")
    for r in refm.getReferencesTo(A(0x400021b0)):
        print("   from",r.getFromAddress(),r.getReferenceType())
    mem=prog.getMemory()
    import jarray
    b=jarray.zeros(4,'b'); mem.getBytes(A(0x400021b0),b)
    val=((b[0]&0xff)<<24)|((b[1]&0xff)<<16)|((b[2]&0xff)<<8)|(b[3]&0xff)
    print("word@0x400021b0 =",hex(val))
finally:
    gp.close()
