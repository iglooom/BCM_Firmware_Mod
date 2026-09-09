import os, pyghidra, jpype, json
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
project=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
from ghidra.app.plugin.assembler import Assemblers
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
asm=Assemblers.getAssembler(program.getLanguage())
JB=jpype.JArray(jpype.JByte); CTX=AssemblyPatternBlock.fromBytes(0,JB([0x20,0,0,0]))
def asm1(a,l): return bytes(int(x)&0xFF for x in asm.assembleLine(A(a),l,CTX))
def jb(bs): return JB([b if b<128 else b-256 for b in bs])

def build_cave(cave_addr, ret_addr, mbreg, disp_lines):
    # symbolic program with labels
    P=[
      "e_stwu r1,-0x10(r1)","e_stw r0,0xC(r1)","e_stw r3,0x8(r1)","e_stw r4,0x4(r1)",
      "e_lis r0,0xFFFC","e_or2i r0,0x0080","cmplw %s,r0"%mbreg,("BNE","DONE"),
      "e_lis r3,0xFFFC","e_add16i r3,r3,0x89",
      # ---- RES+ EDGE-LATCHED: decide Res/Plus once at rising edge, hold for whole press ----
      # A single physical press is held ~240ms (frames every 10ms). Resume flips the PCM
      # paused->active mid-press, so a stateless gate would then emit Plus and bump speed.
      # Latch byte L @0x40011000 (proven-unused SRAM, zeroed at boot): 0=idle, 1=Res, 2=Plus.
      # regs: r3=MB d1 ptr(keep), r4=address scratch, r0=value scratch (r0 invalid as load base).
      "e_lbz r0,0x0(r3)","e_andi. r0,r0,0x40",("BEQ","NOTHELD"),      # ResPlus not held -> clear latch
      "e_lis r4,0x4001","e_add16i r4,r4,0x1000",                       # r4 = &L
      "e_lbz r0,0x0(r4)","se_cmpi r0,0x0",("BNE","APPLY"),             # already latched -> just apply (r4=&L kept)
      # --- rising edge: decide once ---
      "e_lis r4,0x4000","e_add16i r4,r4,0x0707","e_lbz r0,0x0(r4)",    # r0 = 0x0C0 d0 status
      "e_andi. r0,r0,0x48",("BEQ","SETPLUS"),                          # not cancelled/paused -> Plus
      "e_lis r4,0x4000","e_add16i r4,r4,0x0705","e_lbz r0,0x0(r4)",    # r0 = 0x060 d6 set-speed
      "se_cmpi r0,0x0",("BEQ","SETPLUS"),                              # no stored speed -> Plus
      "e_li r0,0x1","e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_stb r0,0x0(r4)",("B","APPLY"),  # latch Res, r4=&L
      ("LBL","SETPLUS"),
      "e_li r0,0x2","e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_stb r0,0x0(r4)",  # latch Plus, r4=&L
      # --- apply latched decision (every held frame); here r4=&L ---
      ("LBL","APPLY"),
      "e_lbz r0,0x0(r4)","se_cmpi r0,0x1",("BNE","APLUS"),             # L==1 -> Res
      "e_lbz r4,0x4(r3)","e_or2i r4,0x20","e_stb r4,0x4(r3)",("B","RESCLR"),
      ("LBL","APLUS"),
      "e_lbz r4,0x4(r3)","e_or2i r4,0x80","e_stb r4,0x4(r3)",          # Plus (d5.7)
      ("LBL","RESCLR"),
      "e_lbz r0,0x0(r3)","e_and2i. r0,0xBF","e_stb r0,0x0(r3)",        # clear old ACC_Res_Plus
      ("B","SKIPRES"),
      ("LBL","NOTHELD"),
      "e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_li r0,0x0","e_stb r0,0x0(r4)",  # released -> L=0
      ("LBL","SKIPRES"),
      # ---- LIM: d1.5 -> d6[5:6]=0b10 pressed ----
      "e_lbz r0,0x0(r3)","e_andi. r0,r0,0x20",("BEQ","SKIPLIM"),
      "e_lbz r4,0x5(r3)","e_and2i. r4,0x9F","e_or2i r4,0x40","e_stb r4,0x5(r3)",
      "e_lbz r0,0x0(r3)","e_and2i. r0,0xDF","e_stb r0,0x0(r3)",
      ("LBL","SKIPLIM"),("LBL","DONE"),
    ]
    tail=["e_lwz r0,0xC(r1)","e_lwz r3,0x8(r1)","e_lwz r4,0x4(r1)","e_add16i r1,r1,0x10"]+disp_lines+[("BR",)]
    items=P+tail
    def size(it,a):
        if isinstance(it,tuple):
            k=it[0]
            if k=="BNE": return len(asm1(a,"e_bne cr0,0x%X"%(a+0x40)))
            if k=="BEQ": return len(asm1(a,"e_beq cr0,0x%X"%(a+0x40)))
            if k=="B":   return len(asm1(a,"e_b 0x%X"%(a+0x40)))
            if k=="BR": return len(asm1(a,"e_b 0x%X"%ret_addr))
            if k=="LBL": return 0
        return len(asm1(a,it))
    # pass1
    addrs=[]; a=cave_addr; labels={}
    for it in items:
        if isinstance(it,tuple) and it[0]=="LBL": labels[it[1]]=a
        addrs.append(a); a+=size(it,a)
    end=a
    out=bytearray()
    for it,a in zip(items,addrs):
        if isinstance(it,tuple):
            k=it[0]
            if k=="LBL": continue
            if k=="BNE": line="e_bne cr0,0x%X"%labels[it[1]]
            elif k=="BEQ": line="e_beq cr0,0x%X"%labels[it[1]]
            elif k=="B": line="e_b 0x%X"%labels[it[1]]
            elif k=="BR": line="e_b 0x%X"%ret_addr
        else: line=it
        out+=asm1(a,line)
    return bytes(out),end

CAVE1_ADDR=0x117100; CAVE2_ADDR=0x117300
c1,e1=build_cave(CAVE1_ADDR,0x000FC2C6,"r10",["e_sth r7,0x0(r10)"])
h1=asm1(0x000FC2C2,"e_b 0x%X"%CAVE1_ADDR)
c2,e2=build_cave(CAVE2_ADDR,0x000FC444,"r29",["se_extzh r7","se_sth r7,0x0(r29)"])
h2=asm1(0x000FC440,"e_b 0x%X"%CAVE2_ADDR)
print("cave1 len=%d end=0x%X ; cave2 len=%d end=0x%X"%(len(c1),e1,len(c2),e2))
assert e1<CAVE2_ADDR, "cave1 overruns cave2"

# round-trip verify
mem=program.getMemory(); listing=program.getListing()
ctxreg=program.getLanguage().getContextBaseRegister(); pc=program.getProgramContext()
val=RegisterValue(ctxreg,BigInteger("20000000",16),BigInteger("FFFFFFFF",16))
tid=program.startTransaction("v")
try:
    # clear existing code units across the cave span FIRST (the project may already
    # contain disassembled/annotated instructions there) so the VLE-context set won't conflict
    listing.clearCodeUnits(A(CAVE1_ADDR),A(CAVE2_ADDR+len(c2)+4-1),False)
    pc.setRegisterValue(A(CAVE1_ADDR),A(CAVE2_ADDR+len(c2)+4),val)
    mem.setBytes(A(CAVE1_ADDR),jb(c1)); mem.setBytes(A(CAVE2_ADDR),jb(c2))
    for ha,hb in ((0x000FC2C2,h1),(0x000FC440,h2)):
        listing.clearCodeUnits(A(ha),A(ha+len(hb)-1),False); mem.setBytes(A(ha),jb(hb))
    for lo,hi in ((CAVE1_ADDR,CAVE1_ADDR+len(c1)),(CAVE2_ADDR,CAVE2_ADDR+len(c2)),(0x000FC2C2,0x000FC2C6),(0x000FC440,0x000FC444)):
        listing.clearCodeUnits(A(lo),A(hi-1),False)
        DisassembleCommand(A(lo),AddressSet(A(lo),A(hi-1)),True).applyTo(program)
    print("\n=== CAVE1 (single packer) ===")
    for ins in listing.getInstructions(AddressSet(A(CAVE1_ADDR),A(CAVE1_ADDR+len(c1)-1)),True):
        b=" ".join("%02X"%(x&0xFF) for x in ins.getBytes())
        print("  %s %-12s %s"%(ins.getAddress(),b,ins))
    print("=== HOOK1 %s / HOOK2 %s ==="%(
        listing.getInstructionAt(A(0xFC2C2)),listing.getInstructionAt(A(0xFC440))))
finally:
    program.endTransaction(tid,False)
json.dump({"c1":list(c1),"h1":list(h1),"c2":list(c2),"h2":list(h2),"cave1":CAVE1_ADDR,"cave2":CAVE2_ADDR},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"patch_blobs.json"),"w"))
print("saved patch_blobs.json")
project.close()
