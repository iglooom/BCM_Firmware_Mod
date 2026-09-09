import os, pyghidra, jpype, json
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger
ROOT="/home/gl/Projects/ford/BCM/Research"
project=GhidraProject.openProject(ROOT+"/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)   # readOnly=False -> writable
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
st=program.getSymbolTable(); listing=program.getListing()
mem=program.getMemory(); pc=program.getProgramContext()
ctxreg=program.getLanguage().getContextBaseRegister()

bl=json.load(open(ROOT+"/work/acc-fix/patch_blobs.json"))
c1=bytes(bl["c1"]); h1=bytes(bl["h1"]); c2=bytes(bl["c2"]); h2=bytes(bl["h2"])
CAVE1=bl["cave1"]; CAVE2=bl["cave2"]
def jb(bs): return jpype.JArray(jpype.JByte)([b if b<128 else b-256 for b in bs])

tid=program.startTransaction("acc-fix annotate")
try:
    # 1) write the patched bytes into the program image so the DB reflects the mod
    for lo,blob in ((CAVE1,c1),(CAVE2,c2),(0xFC2C2,h1),(0xFC440,h2)):
        listing.clearCodeUnits(A(lo),A(lo+len(blob)-1),False)
        mem.setBytes(A(lo),jb(blob))
    # set VLE context on the caves so they disassemble
    val=RegisterValue(ctxreg,BigInteger("20000000",16),BigInteger("FFFFFFFF",16))
    for lo,blob in ((CAVE1,c1),(CAVE2,c2)):
        pc.setRegisterValue(A(lo),A(lo+len(blob)-1),val)
        DisassembleCommand(A(lo),AddressSet(A(lo),A(lo+len(blob)-1)),True).applyTo(program)
    for lo,blob in ((0xFC2C2,h1),(0xFC440,h2)):
        DisassembleCommand(A(lo),AddressSet(A(lo),A(lo+len(blob)-1)),True).applyTo(program)

    def lbl(a,name):
        for s in st.getSymbols(A(a)):
            if not s.isDynamic(): s.delete()
        st.createLabel(A(a),name,SourceType.USER_DEFINED)
    from ghidra.program.model.listing import CodeUnit
    def pcmt(a,txt): listing.setComment(A(a),CodeUnit.PLATE_COMMENT,txt)
    def ecmt(a,txt): listing.setComment(A(a),CodeUnit.EOL_COMMENT,txt)

    # 2) labels
    lbl(CAVE1,"accfix_cave_single_packer")
    lbl(CAVE2,"accfix_cave_walker_packer")
    lbl(0x40000707,"RAM_0C0_d0_cruise_status")   # note: RAM, may already be defined
    # 3) plate comments
    pcmt(CAVE1,
"""ACC-FIX code cave (single-frame TX packer hook target).
Reached from FUN_000fc218+0xAA (0xFC2C2), which had:  e_sth r7,0x0(r10)
replaced by:  e_b accfix_cave_single_packer.
Runs at CAN0 MB0 (=HS-CAN 0x030) transmit-arm time. Gate: cmplw r10,0xFFFC0080.
Transforms the assembled 0x030 mailbox payload, then replays the displaced store
and returns to 0xFC2C6.

  RES+ (d1&0x40): EDGE-LATCHED via L @0x40011000 (proven-unused SRAM, zeroed at boot; 0=idle 1=Res 2=Plus).
     A press is held ~240ms (frames every 10ms); Resume flips PCM paused->active mid-press, so a
     stateless gate would then emit Plus and bump speed. So decide ONCE at the rising edge:
       rising edge & ((0x0C0 d0 @0x40000707 & 0x48) && (0x060 d6 @0x40000705 != 0)) -> L=1 (Res) else L=2 (Plus)
       every held frame: d5 |= (L==1 ? 0x20 CC_Res : 0x80 CC_Set_Plus); d1 &= ~0x40
       released (d1.6==0): L=0
     0x0C0 d0 alone is ambiguous (fresh cancel 0x40/0x48 DECAYS after ~2s to engaged-not-set 0x18/0x38);
     0x060 d6 stored set-speed disambiguates.
  LIM  (d1&0x20): d6 = (d6 & ~0x60) | 0x40   -> CC_Lim field d6[5:6]=0b10 pressed
     d1 &= ~0x20   (clear ACC_Lim; native baseline d6=0xB3 already codes 0b01 released)

See docs/acc-fix.md and AGENTS.md.""")
    pcmt(CAVE2,
"""ACC-FIX code cave (periodic walker TX packer hook target).
Reached from FUN_000fc2f6+0x14A (0xFC440), which had:  se_extzh r7 ; se_sth r7,0x0(r29)
replaced by:  e_b accfix_cave_walker_packer.
Same transform as accfix_cave_single_packer but MB pointer is r29; replays BOTH
displaced instructions and returns to 0xFC444. Gate: cmplw r29,0xFFFC0080.""")
    pcmt(0x40000707,
"""ACC-FIX read source #1: BCM decoded RAM frame-image byte d0 of received HS-CAN 0x0C0
(PCM cruise/limiter status). Verbatim byte copy from FlexCAN MB30 by RX copier
FUN_000fc63e (record @0x14ADB8, dest word0=0x40000707, copymask 0x13 covers d0).
Layout preserved: bit3(0x08)=StandBy, bits4..6(0x70)=mode/status.
Cruise: 0x18 engaged-not-set / 0x10 active / 0x40 cancel(fresh)->decays to 0x18.
Limiter: 0x38 engaged-not-set / 0x30 active / 0x48 cancel->decays to 0x38.
ACC-FIX Resume gate: (d0 & 0x48) AND (0x060 d6 @0x40000705 != 0). The 0x060 d6 stored
set-speed resolves the post-decay ambiguity (cancelled 0x18/0x38 vs never-set 0x18/0x38).""")
    lbl(0x40000705,"RAM_060_d6_set_speed")
    pcmt(0x40000705,
"""ACC-FIX read source #2: BCM decoded RAM frame-image byte for received HS-CAN 0x060 d6
= current cruise/limiter STORED SET-SPEED (0 until a speed is set; e.g. 0x1E=30 km/h).
0x060 = FlexCAN MB22 (RX). RX copier FUN_000fc63e record @0x14ACD8: dest word0=0x40000700,
copymask 0xFE (COMPACTED copy: only set mask bits advance dest). d6 is preceded by 5 set
mask bits {1,2,3,4,5} -> lands at 0x40000700+5 = 0x40000705. Used by the RES+ gate to tell
'cancelled with a stored speed' (Resume) from 'engaged-not-set-yet' (Set+).""")
    lbl(0x40011000,"RAM_accfix_resplus_latch")
    pcmt(0x40011000,
"""ACC-FIX persistent state: RES+ edge-latch (1 byte). 0=idle, 1=Res, 2=Plus.
Proven-unused SRAM (see docs/scratch_ram.md): inside startup ECC/zero-init range
[0x400039A0..0x40014000] so it powers up 0; above stack top SP=0x4000CAC8; below SDA
base 0x40017920; zero references anywhere in flash. Written/read ONLY by the two ACC-FIX
caves. Holds the Res-vs-Plus decision for the whole ~240ms button press so the mid-press
PCM paused->active transition cannot flip a held Resume into a speed-bumping Plus.""")
    # hook-site EOL comments
    ecmt(0xFC2C2,"ACC-FIX: was 'e_sth r7,0x0(r10)'; now e_b accfix_cave_single_packer")
    ecmt(0xFC440,"ACC-FIX: was 'se_extzh r7; se_sth r7,0x0(r29)'; now e_b accfix_cave_walker_packer")
    # bookmark
    program.getBookmarkManager().setBookmark(A(CAVE1),"Note","ACC-FIX","SWM cruise-button remap (RES+/LIM) - see AGENTS.md")
    program.getBookmarkManager().setBookmark(A(CAVE2),"Note","ACC-FIX","SWM cruise-button remap walker copy")
    program.getBookmarkManager().setBookmark(A(0xFC2C2),"Note","ACC-FIX","hook: single-frame packer")
    program.getBookmarkManager().setBookmark(A(0xFC440),"Note","ACC-FIX","hook: walker packer")
    print("annotations applied")
finally:
    program.endTransaction(tid,True)
project.save(program)
print("program saved")
project.close()
