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

# ---- Two-pass symbolic cave builder (same engine as acc-fix build_caves.py) ----
def build(cave_addr, ret_addr, items):
    def size(it,a):
        if isinstance(it,tuple):
            k=it[0]
            if k in ("BNE","BEQ"): return len(asm1(a,"e_%s cr0,0x%X"%("bne" if k=="BNE" else "beq",a+0x40)))
            if k=="B":  return len(asm1(a,"e_b 0x%X"%(a+0x40)))
            if k=="BR": return len(asm1(a,"e_b 0x%X"%ret_addr))
            if k=="LBL": return 0
        return len(asm1(a,it))
    addrs=[]; a=cave_addr; labels={}
    for it in items:
        if isinstance(it,tuple) and it[0]=="LBL": labels[it[1]]=a
        addrs.append(a); a+=size(it,a)
    end=a; out=bytearray()
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

# ---- acc-fix cave body (verbatim from acc-fix/build_caves.py) ----
def accfix_body(mbreg):
    return [
      "e_stwu r1,-0x10(r1)","e_stw r0,0xC(r1)","e_stw r3,0x8(r1)","e_stw r4,0x4(r1)",
      "e_lis r0,0xFFFC","e_or2i r0,0x0080","cmplw %s,r0"%mbreg,("BNE","RKE"),   # not MB0 -> RKE gate
      "e_lis r3,0xFFFC","e_add16i r3,r3,0x89",
      "e_lbz r0,0x0(r3)","e_andi. r0,r0,0x40",("BEQ","NOTHELD"),
      "e_lis r4,0x4001","e_add16i r4,r4,0x1000",
      "e_lbz r0,0x0(r4)","se_cmpi r0,0x0",("BNE","APPLY"),
      "e_lis r4,0x4000","e_add16i r4,r4,0x0707","e_lbz r0,0x0(r4)",
      "e_andi. r0,r0,0x48",("BEQ","SETPLUS"),
      "e_lis r4,0x4000","e_add16i r4,r4,0x0705","e_lbz r0,0x0(r4)",
      "se_cmpi r0,0x0",("BEQ","SETPLUS"),
      "e_li r0,0x1","e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_stb r0,0x0(r4)",("B","APPLY"),
      ("LBL","SETPLUS"),
      "e_li r0,0x2","e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_stb r0,0x0(r4)",
      ("LBL","APPLY"),
      "e_lbz r0,0x0(r4)","se_cmpi r0,0x1",("BNE","APLUS"),
      "e_lbz r4,0x4(r3)","e_or2i r4,0x20","e_stb r4,0x4(r3)",("B","RESCLR"),
      ("LBL","APLUS"),
      "e_lbz r4,0x4(r3)","e_or2i r4,0x80","e_stb r4,0x4(r3)",
      ("LBL","RESCLR"),
      "e_lbz r0,0x0(r3)","e_and2i. r0,0xBF","e_stb r0,0x0(r3)",
      ("B","SKIPRES"),
      ("LBL","NOTHELD"),
      "e_lis r4,0x4001","e_add16i r4,r4,0x1000","e_li r0,0x0","e_stb r0,0x0(r4)",
      ("LBL","SKIPRES"),
      "e_lbz r0,0x0(r3)","e_andi. r0,r0,0x20",("BEQ","SKIPLIM"),
      "e_lbz r4,0x5(r3)","e_and2i. r4,0x9F","e_or2i r4,0x40","e_stb r4,0x5(r3)",
      "e_lbz r0,0x0(r3)","e_and2i. r0,0xDF","e_stb r0,0x0(r3)",
      ("LBL","SKIPLIM"),("B","DONE"),
    ]

# ---- RKE 0x3A block (v5: fire-ONCE-per-press latch + INDEPENDENT re-strobe suppression window).
#      Two separate scratch bytes (v4 conflated them -> 5 clicks):
#        L2 @0x40011001 = press latch: 0=armed, 1=already fired this press; re-armed only on button RELEASE.
#        L3 @0x40011002 = suppress countdown (frames): >0 => clear d1 bit6 on outgoing d3==01 frames,
#                         decremented every 0x3A frame (time-based) so it always expires.
#      The bug in v4: it closed the window on every native d3==02 frame the BCM streams for ~0.5 s
#      BEFORE it accepts the lock, which re-armed the latch and re-fired ~once per 2 frames.
#      Registers: only r0,r3,r4 are saved by acc-fix tail; r4 doubles as ign-addr temp then reloaded. ----
SUPP=30   # frames (~1.2 s at ~40 ms 0x3A) — covers the BCM re-strobe (~0.45 s later) with margin
def rke_body(mbreg):
    return [
      ("LBL","RKE"),
      # gate: this mailbox == CAN1 MB1 (0xFFFC4090) = 0x3A ?
      "e_lis r0,0xFFFC","e_or2i r0,0x4090","cmplw %s,r0"%mbreg,("BNE","DONE"),
      # r3 = 0x100 RX image base 0x40000918 ; r4 = &L2 (0x40011001, L3 at +1)
      "e_lis r3,0x4000","e_add16i r3,r3,0x0918",
      "e_lis r4,0x4001","e_add16i r4,r4,0x1001",
      # button held? (d7 bit0)  no -> re-arm latch then run suppression
      "e_lbz r0,0x7(r3)","e_andi. r0,r0,0x01",("BEQ","RELEASED"),
      # held: already fired this press? (L2!=0) -> just run suppression
      "e_lbz r0,0x0(r4)","se_cmpi r0,0x0",("BNE","SUPPRESS"),
      # armed (L2==0): remaining fire conditions; if any fail -> suppression (no fire, stay armed)
      # NOTE: UB (d6 bit2 "decrypted-msg-valid") was DROPPED as a gate — it is asserted per-press only
      # after the RFA validates the rolling code, which can lag several presses (log rke_lock6: presses
      # 1-3 had lock+keyout+ign all set but UB=0 -> ignored). Our own d7-bit0 rising-edge latch already
      # gives reliable per-press detection; UB adds no CAN-layer security (lock-only, key-outside, ign-on).
      "e_lbz r0,0x1(r3)","e_andi. r0,r0,0x80",("BEQ","SUPPRESS"),   # key outside?
      "e_lis r4,0xFFFC","e_add16i r4,r4,0x42C8","e_lbz r0,0x0(r4)", # ign 0x3A0 d0 (r4 temp)
      "e_andi. r0,r0,0xF0","e_cmpli cr0,r0,0x40",("BNE","SUPPRESS"),# ign == Run?  (r4 reloaded in SUPPRESS)
      # RISING EDGE, all met: FIRE one strobe, latch, open window, and SKIP suppression this frame
      "e_lis r4,0x4001","e_add16i r4,r4,0x1001",                   # reload &L2 (was clobbered by ign temp)
      "e_li r0,0x1","e_stb r0,0xB(%s)"%mbreg,                      # d3 = 01 (CLockCmd LOCK)
      "e_lbz r0,0x9(%s)"%mbreg,"e_or2i r0,0x42","e_stb r0,0x9(%s)"%mbreg,  # d1 |= bit6(execute)+bit1(UB)
      "e_li r0,0x1","e_stb r0,0x0(r4)",                            # L2 = 1 (fired this press)
      "e_li r0,0x%X"%SUPP,"e_stb r0,0x1(r4)",                      # L3 = SUPP (open suppress window)
      ("B","DONE"),                                                # protect our own strobe (no kill this frame)
      ("LBL","RELEASED"),
      "e_li r0,0x0","e_stb r0,0x0(r4)",                            # button up -> re-arm latch (r4 still &L2)
      # fall through to SUPPRESS
      ("LBL","SUPPRESS"),
      "e_lis r4,0x4001","e_add16i r4,r4,0x1001",                   # ensure r4 = &L2
      "e_lbz r0,0x1(r4)","se_cmpi r0,0x0",("BEQ","DONE"),          # L3==0 -> window closed
      # window active: kill d1 bit6 only on outgoing LOCK frames (d3==01); leave unlock/idle alone
      "e_lbz r0,0xB(%s)"%mbreg,"se_cmpi r0,0x1",("BNE","SKIPKILL"),
      "e_lbz r0,0x9(%s)"%mbreg,"e_and2i. r0,0xBF","e_stb r0,0x9(%s)"%mbreg,  # clear bit6 (kill re-strobe)
      ("LBL","SKIPKILL"),
      "e_lbz r0,0x1(r4)","e_add16i r0,r0,-0x1","e_stb r0,0x1(r4)", # L3-- (time-based expiry)
      ("LBL","DONE"),
    ]

def tail(disp_lines):
    return ["e_lwz r0,0xC(r1)","e_lwz r3,0x8(r1)","e_lwz r4,0x4(r1)","e_add16i r1,r1,0x10"]+disp_lines+[("BR",)]

# CAVE1 = single-frame packer (FUN_000fc218, hook 0xFC2C2, ret 0xFC2C6, mbreg r10, displaced e_sth r7,0x0(r10))
# CAVE2 = walker (FUN_000fc2f6, hook 0xFC440, ret 0xFC444, mbreg r29, displaced se_extzh r7;se_sth r7,0x0(r29))
# Both get acc-fix body + RKE body so either packer path handles 0x3A too.
CAVE1=0x117100; CAVE2=0x117400
def full(mbreg,disp): return accfix_body(mbreg)+rke_body(mbreg)+tail(disp)
c1,e1=build(CAVE1,0x000FC2C6,full("r10",["e_sth r7,0x0(r10)"]))
h1=asm1(0x000FC2C2,"e_b 0x%X"%CAVE1)
c2,e2=build(CAVE2,0x000FC444,full("r29",["se_extzh r7","se_sth r7,0x0(r29)"]))
h2=asm1(0x000FC440,"e_b 0x%X"%CAVE2)
print("cave1 len=%d end=0x%X ; cave2 len=%d end=0x%X"%(len(c1),e1,len(c2),e2))
assert e1<CAVE2, "cave1 overruns cave2 base 0x%X"%CAVE2
assert e2<0x117700, "cave2 end 0x%X overruns"%e2

# round-trip: write, set VLE ctx, disassemble, print
mem=program.getMemory(); listing=program.getListing()
ctxreg=program.getLanguage().getContextBaseRegister(); pc=program.getProgramContext()
val=RegisterValue(ctxreg,BigInteger("20000000",16),BigInteger("FFFFFFFF",16))
tid=program.startTransaction("v")
try:
    listing.clearCodeUnits(A(CAVE1),A(CAVE2+len(c2)+4-1),False)
    pc.setRegisterValue(A(CAVE1),A(CAVE2+len(c2)+4),val)
    mem.setBytes(A(CAVE1),jb(c1)); mem.setBytes(A(CAVE2),jb(c2))
    for ha,hb in ((0x000FC2C2,h1),(0x000FC440,h2)):
        listing.clearCodeUnits(A(ha),A(ha+len(hb)-1),False); mem.setBytes(A(ha),jb(hb))
    for lo,hi in ((CAVE1,CAVE1+len(c1)),(CAVE2,CAVE2+len(c2)),(0x000FC2C2,0x000FC2C6),(0x000FC440,0x000FC444)):
        listing.clearCodeUnits(A(lo),A(hi-1),False)
        DisassembleCommand(A(lo),AddressSet(A(lo),A(hi-1)),True).applyTo(program)
    print("\n=== CAVE2 walker (acc-fix + RKE) ===")
    for ins in listing.getInstructions(AddressSet(A(CAVE2),A(CAVE2+len(c2)-1)),True):
        b=" ".join("%02X"%(x&0xFF) for x in ins.getBytes())
        print("  %s %-14s %s"%(ins.getAddress(),b,ins))
    print("HOOK1 %s / HOOK2 %s"%(listing.getInstructionAt(A(0xFC2C2)),listing.getInstructionAt(A(0xFC440))))
finally:
    program.endTransaction(tid,False)
json.dump({"c1":list(c1),"h1":list(h1),"c2":list(c2),"h2":list(h2),"cave1":CAVE1,"cave2":CAVE2},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"patch_blobs.json"),"w"))
print("saved patch_blobs.json")
project.close()
