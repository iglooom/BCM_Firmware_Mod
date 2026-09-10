import os, pyghidra, jpype, json
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.listing import CodeUnit
from java.math import BigInteger

ROOT="/home/gl/Projects/ford/BCM/Research"
# Annotate a SEPARATE project copy so the acc-fix-only project (cave2=0x117300) is untouched.
# This project carries the COMBINED acc-fix + rke-lock image (cave2=0x117400).
PROJ=ROOT+"/ghidra_proj_accfix_rkelock"
project=GhidraProject.openProject(PROJ,"BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)   # readOnly=False -> writable
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
st=program.getSymbolTable(); listing=program.getListing()
mem=program.getMemory(); pc=program.getProgramContext()
ctxreg=program.getLanguage().getContextBaseRegister()

bl=json.load(open(ROOT+"/work/rke-lock/patch_blobs.json"))
c1=bytes(bl["c1"]); h1=bytes(bl["h1"]); c2=bytes(bl["c2"]); h2=bytes(bl["h2"])
CAVE1=bl["cave1"]; CAVE2=bl["cave2"]   # 0x117100, 0x117400
def jb(bs): return jpype.JArray(jpype.JByte)([b if b<128 else b-256 for b in bs])

tid=program.startTransaction("accfix+rkelock annotate")
try:
    # 1) write the combined patched bytes into the program image so the DB reflects the mod
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
    def pcmt(a,txt): listing.setComment(A(a),CodeUnit.PLATE_COMMENT,txt)
    def ecmt(a,txt): listing.setComment(A(a),CodeUnit.EOL_COMMENT,txt)

    # ---------- shared caves (acc-fix body FIRST, RKE body appended) ----------
    lbl(CAVE1,"mod_cave_single_packer")
    lbl(CAVE2,"mod_cave_walker_packer")
    pcmt(CAVE1,
"""COMBINED MOD cave (single-frame TX packer hook target).
Reached from FUN_000fc218+0xAA (0xFC2C2), which had:  e_sth r7,0x0(r10)  -> replaced by e_b here.
Layout: [acc-fix body][rke-lock body][tail: restore r0/r3/r4, replay displaced store, return 0xFC2C6].
 * ACC-FIX part runs at CAN0 MB0 (=HS-CAN 0x030) TX-arm. Gate cmplw r10,0xFFFC0080. (see accfix_cave_walker_packer / docs/acc-fix.md)
 * RKE-LOCK part runs at CAN1 MB1 (=MS-CAN 0x3A)  TX-arm. Gate cmplw r10,0xFFFC4090. (see below)
mbreg for this packer = r10.""")
    pcmt(CAVE2,
"""COMBINED MOD cave (periodic walker TX packer hook target) -- ACTIVE path for 0x3A.
Reached from FUN_000fc2f6+0x14A (0xFC440), which had:  se_extzh r7 ; se_sth r7,0x0(r29)  -> replaced by e_b here.
Layout: [acc-fix body][rke-lock body][tail: restore, replay BOTH displaced insns, return 0xFC444].
mbreg for this packer = r29.

--- ACC-FIX (HS-CAN 0x030, gate cmplw r29,0xFFFC0080) ---
Remaps new-SWM cruise buttons so the old PCM understands them; RES+ decision edge-latched in
RAM_accfix_resplus_latch (0x40011000). Full detail: docs/acc-fix.md.

--- RKE-LOCK (MS-CAN 0x3A CLockCmd, gate cmplw r29,0xFFFC4090) ---
Lets the remote key LOCK the car with ignition ON (stock BCM blocks it), only when the key is
OUTSIDE. Reproduces the BCM's own native lock: ONE frame with d1 bit6=1 (execute STROBE) + d3=01,
then hands back to the native stream. d1 bit6 is a one-shot strobe, NOT a level.

Inputs (0x100 RX image base 0x40000918):
  d7 @0x4000091F bit0 = LOCK button ;  d1 @0x40000919 bit7 = key-outside
  ign = 0x3A0 d0 @0xFFFC42C8 hi-nibble==4 (Run)
  (d6 bit2 UB is deliberately NOT gated -- RFA asserts it only after rolling-code validation, which
   lagged 3+ presses on the car; the d7-bit0 rising edge is the reliable press detector.)
Mailbox 0x3A (CS 0xFFFC4090): d1=CS+9 (0xFFFC4099), d3=CS+0xB (0xFFFC409B).

State (proven-unused SRAM, see RAM_rkelock_press_latch / RAM_rkelock_suppress_ctr):
  L2 @0x40011001 press latch: 0=armed, 1=fired-this-press; re-armed ONLY on button release.
  L3 @0x40011002 suppress countdown (frames): >0 clears d1 bit6 on outgoing d3==01 frames, --each frame.

Per-frame logic:
  if (!(d7&1))              L2=0;                       // released -> re-arm, then suppression
  else if (L2==0 && (d1&0x80) && ((ign&0xF0)==0x40)) { // RISING EDGE, key-out, ign Run
      mbreg[0xB]=1; mbreg[0x9]|=0x42;                   // d3=LOCK ; d1|=bit6(strobe)+bit1(UB)
      L2=1; L3=30; return;                              // latch + open ~1.2s window; protect our strobe
  }
  if (L3>0){ if(mbreg[0xB]==1) mbreg[0x9]&=~0x40; L3--; } // kill BCM's follow-up re-strobe (else double click)

Why the suppression: when WE inject the lock (ign on), the BCM learns via DDM and emits its OWN
follow-up execute-strobe ~0.45s later -> 2nd click. L3 neutralises it (bit6 stripped) for a window.
On-vehicle debug arc v1..v6 (too-brief / rapid-click / double-click / 5-click / ignored-presses /
FIXED). Full history + captures: docs/rke-lock.md, docs/key_outside_gate.md. Register note: r0 is
invalid as a load/store base on PPC, so ign addr is kept in r4 (reloaded with &L2 afterwards).""")

    # ---------- acc-fix read/state RAM (same as acc-fix project) ----------
    lbl(0x40000707,"RAM_0C0_d0_cruise_status")
    pcmt(0x40000707,
"""ACC-FIX read source #1: BCM decoded RAM image byte d0 of received HS-CAN 0x0C0 (PCM cruise/limiter
status). Verbatim copy from FlexCAN MB30. bit3=StandBy, bits4..6=mode/status. Resume gate:
(d0 & 0x48) AND (0x060 d6 @0x40000705 != 0). See docs/acc-fix.md.""")
    lbl(0x40000705,"RAM_060_d6_set_speed")
    pcmt(0x40000705,
"""ACC-FIX read source #2: BCM decoded RAM image byte for received HS-CAN 0x060 d6 = stored cruise
SET-SPEED (0 until set). Resolves the post-decay ambiguity in the RES+ gate. See docs/acc-fix.md.""")
    lbl(0x40011000,"RAM_accfix_resplus_latch")
    pcmt(0x40011000,
"""ACC-FIX persistent state: RES+ edge-latch (1 byte, 0=idle/1=Res/2=Plus). Proven-unused SRAM
(docs/scratch_ram.md). Byte 0 of the shared mod scratch block 0x40011000..2.""")

    # ---------- rke-lock read/state RAM ----------
    lbl(0x40000918,"RAM_100_rke_image_base")
    pcmt(0x40000918,
"""RKE-LOCK inputs: BCM decoded RAM image of received MS-CAN 0x100 (RFA/keyless), verbatim 8-byte copy
(copier record @0x1520F8, mask 0xFF). d1 @+1 (0x40000919) bit7 = key-outside; d6 @+6 (0x4000091E)
bit2 = _UB (NOT gated); d7 @+7 (0x4000091F) bit0 = LOCK, bit1 = UNLOCK. See docs/rke_0x100_lock.md.""")
    lbl(0x40000919,"RAM_100_d1_keyout")
    ecmt(0x40000919,"RKE-LOCK: 0x100 d1; bit7=key-outside gate")
    lbl(0x4000091F,"RAM_100_d7_rke_buttons")
    ecmt(0x4000091F,"RKE-LOCK: 0x100 d7; bit0=LOCK (press detector), bit1=UNLOCK")
    lbl(0xFFFC42C8,"RAM_3A0_d0_ignition")
    pcmt(0xFFFC42C8,
"""RKE-LOCK ignition source: raw TX-mailbox d0 of MS-CAN 0x3A0 (Ignition_Switch_Position), CAN1 MB36.
hi-nibble == 4 => Run (0x1_=Off). Gate: (d0 & 0xF0)==0x40. See docs/rke-lock.md / docs/ign_powermode_0x80.md.""")
    lbl(0xFFFC4090,"MB_3A_clockcmd_cs")
    pcmt(0xFFFC4090,
"""RKE-LOCK target mailbox: CAN1 MB1 CS = MS-CAN 0x3A (BCM->door modules central-lock). Data bytes:
d0=CS+8. d1=CS+9 (0xFFFC4099) flags (bit6 execute strobe, bit1 CLockCmd_UB). d3=CS+0xB (0xFFFC409B)
CLockCmd (01=LOCK,02=UNLOCK). The cave rewrites d3/d1 here at TX-arm. See docs/clockcmd_0x3a.md.""")
    lbl(0x40011001,"RAM_rkelock_press_latch")
    pcmt(0x40011001,
"""RKE-LOCK persistent state L2: press latch (1 byte). 0=armed, 1=already fired this press. Re-armed
ONLY when the RKE-lock button releases (0x100 d7 bit0 clears) -> exactly one strobe per press.
Proven-unused SRAM (docs/scratch_ram.md), byte 1 of the shared scratch block 0x40011000..2.""")
    lbl(0x40011002,"RAM_rkelock_suppress_ctr")
    pcmt(0x40011002,
"""RKE-LOCK persistent state L3: re-strobe suppression countdown (1 byte, frames). Set to 30 (~1.2s)
when we fire; while >0 it clears d1 bit6 on outgoing 0x3A LOCK (d3==01) frames and decrements every
frame (time-based, never keyed on d3). Neutralises the BCM's OWN follow-up execute-strobe (~0.45s
later) that would otherwise cause a second click. Byte 2 of the shared scratch block. See docs/rke-lock.md.""")

    # ---------- hook-site EOL comments ----------
    ecmt(0xFC2C2,"MOD: was 'e_sth r7,0x0(r10)'; now e_b mod_cave_single_packer (acc-fix + rke-lock)")
    ecmt(0xFC440,"MOD: was 'se_extzh r7; se_sth r7,0x0(r29)'; now e_b mod_cave_walker_packer (acc-fix + rke-lock)")

    # ---------- bookmarks ----------
    bm=program.getBookmarkManager()
    bm.setBookmark(A(CAVE1),"Note","MOD","acc-fix + rke-lock cave (single-frame packer)")
    bm.setBookmark(A(CAVE2),"Note","MOD","acc-fix + rke-lock cave (walker; active 0x3A path)")
    bm.setBookmark(A(0xFC2C2),"Note","MOD","hook: single-frame packer")
    bm.setBookmark(A(0xFC440),"Note","MOD","hook: walker packer")
    bm.setBookmark(A(0xFFFC4090),"Note","RKE-LOCK","0x3A CLockCmd target mailbox")
    bm.setBookmark(A(0x40011001),"Note","RKE-LOCK","press latch L2")
    bm.setBookmark(A(0x40011002),"Note","RKE-LOCK","re-strobe suppress L3")
    print("annotations applied")
finally:
    program.endTransaction(tid,True)
project.save(program)
print("program saved")
project.close()
print("done")
