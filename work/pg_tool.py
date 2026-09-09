import os, pyghidra, sys
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.scalar import Scalar

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
monitor = ConsoleTaskMonitor()
af = program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
listing = program.getListing()
fm = program.getFunctionManager()

def decompile(entry):
    di = DecompInterface(); di.openProgram(program)
    f = fm.getFunctionAt(A(entry)) or fm.getFunctionContaining(A(entry))
    if not f:
        print("no function at", hex(entry)); return
    res = di.decompileFunction(f, 60, monitor)
    print("==== %s @ %s ====" % (f.getName(), f.getEntryPoint()))
    if res and res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("decompile failed:", res.getErrorMessage() if res else "none")

try:
    cmd = sys.argv[1] if len(sys.argv)>1 else "flexcan"
    if cmd == "flexcan":
        # find e_lis/e_or2is building 0xFFFCxxxx or 0xFFFDxxxx (FlexCAN bases)
        import collections
        hits = collections.Counter()
        funcs = {}
        for ins in listing.getInstructions(True):
            mn = ins.getMnemonicString()
            for oi in range(ins.getNumOperands()):
                for obj in ins.getOpObjects(oi):
                    if isinstance(obj, Scalar):
                        v = obj.getUnsignedValue() & 0xFFFF
                        if mn in ("e_lis","se_lis") and v in (0xFFFC,0xFFFD):
                            f = fm.getFunctionContaining(ins.getAddress())
                            key = (v, f.getName() if f else "(none)", str(f.getEntryPoint()) if f else "?")
                            hits[key]+=1
        for (v,fn,ep),c in hits.most_common(40):
            print("  0x%04X0000  %-30s %s  x%d"%(v,fn,ep,c))
    else:
        for a in sys.argv[1:]:
            decompile(int(a,16))
finally:
    project.close()
