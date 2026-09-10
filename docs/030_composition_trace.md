# BCM HS-CAN 0x030 Cruise-Button Composition Trace + Remap/Injection Design

**Task:** locate exactly where the transmitted HS-CAN `0x030` cruise-button bits are composed in
application code, prove they originate from the LIN/SWM bus, and deliver a byte/offset-level map
suitable for a safe binary patch that remaps **ACC_Res_Plus** (`0x030` d1.6, mask `0x40`) to
**CC_Set_Plus** (`0x030` d5.7, mask `0x80`). Analysis only — nothing patched or flashed.

Evidence tags: **(a)** decompiled/disassembled-code proof · **(b)** validated table structure ·
**(c)** capture / ground-truth · **(d)** inferred.

---

## 0. Executive summary

- **The 0x030 button working image is `0x40001F80`** — confirmed (a)(b)(c). It is the frame-table
  entry at flash `0x1B7CC` (16-byte stride, entry index 0), and its **byte0 = CAN d1** (proven by
  matching handler bit-writes to the CAN capture).
- **RES+ (d1.6) is written by `FUN_000ebf00`** at `0x000EBF48` (`se_stb r0,0x0(r7)` with
  `r7 = 0x40001F80`, bit set via `se_bseti r0,0x19`). Ghidra auto-xref missed this because the
  address is built with `e_lis/e_add16i` (computed pointer). (a)
- **RES+ originates on the LIN/SWM bus.** `FUN_000ebf00` is reached ONLY from the SWM LIN signal
  dispatcher `FUN_000e853a`, which is driven by the LIN receive task (`0x000E8480`/`0x000E84AA`)
  that pulls a decoded LIN frame via `FUN_000f74a0`; the physical LIN layer is `FUN_000fad06`
  (LINFlex_0 @ `0xFFE40000`), SWM buffer `0x40007B3C`. The RES+ source byte is `se_lbz r31,0x0(r3)`
  in `FUN_000ebf00`. (a)
- **d5.7 (CC_Set_Plus) is FREE** — d5 is `0x00` in all 622 captured frames; its working cell
  `0x40001F84` has **0 writers** in Ghidra. (b)(c)
- **CRITICAL STRUCTURAL FINDING:** RES+ (d1) and CC_Set_Plus (d5) do **not** live in the same
  packed PDU image. The `0x030` button working image `0x40001F80` copies only **4 bytes**
  (`d1..d4`) into frame image `0x40005AE0`. **d5 is a different byte, populated by a different
  contributor.** A within-PDU "move the bit to d5" composition edit is therefore *not*
  possible on this 4-byte image — this is exactly why the two remap strategies below differ so much.

---

## 1. Q1 — Which RAM buffer is the 0x030 working image?  → `0x40001F80` (a)(b)(c)

Frame table at flash `0x1B7CC`, 16-byte stride, `[+0 work][+4 frame][+8 f10aoff][+0xC lenword]`:

| idx | @flash | work img | frame img | f10aoff | lenword | copy bytes |
|----|--------|----------|-----------|---------|---------|-----------|
| **0** | `0x01B7CC` | **`0x40001F80`** | **`0x40005AE0`** | `0x12000`→siglist `0x152000` | `0x08` | **4** |
| 1 | `0x01B7DC` | `0x40002860` | `0x400063C0` | … | `0x40` | 60 |
| 2 | `0x01B7EC` | `0x40001F88` | `0x40005AE8` | … | `0x2E0` | 732 |

The packer `FUN_0005049c` reads this table via a **computed pointer** (disassembly @`0x000504B6`):
```
e_slwi   r31,r30,0x4        ; r31 = idx*16
e_add16i r31,r31,-0x4834    ; + (-0x4834)
e_add2is r31,0x2            ; + (0x2<<16)   => r31 = 0x1B7CC + idx*16
se_lwz   r29,0x4(r31)       ; r29 = frame img  (= *0x1B7D0 = 0x40005AE0 for idx0)
se_lwz   r5, 0xc(r31)       ; r5  = lenword    (= *0x1B7D8 = 8)
se_lwz   r4, 0x0(r31)       ; r4  = work img   (= *0x1B7CC = 0x40001F80)
se_subi  r5,0x4             ; len -= 4         => 4
e_bl     0x0010db0c         ; memcpy(frame, work, 4)
```
This is the memcpy packer `FUN_0010db0c(dst=frame, src=work, len)` named in the task. Because the
base `0x1B7CC` is synthesized as `-0x4834 + 0x20000` (never a single 32-bit immediate), **no
absolute xref exists** — a raw immediate scan for `0x4000`/`0x1F8x` pairs in the whole app block
found the value `0x40001F80` **only** in the frame table itself (`0x1B7CC`), confirming no code
hardcodes the buffer. (a)(b)

**Byte-semantic proof that working `0x40001F80` byte0 = CAN d1** (c): the three button handlers
write only byte0 (`._0_1_`) and byte2 (`._2_1_`) of `0x40001F80`, with these bit ops —

| handler | bit op on byte0 | button (from captures) |
|---------|-----------------|--------------|
| `FUN_000ebae0` | `\| 0x08` (bit3) | (ACC Cruise / d1.3) |
| `FUN_000ebf00` | `\| 0x40` (bit6) | **ACC_Res_Plus / d1.6** |
| `FUN_000ebf5a` | bits4/5 (`0x10`/`0x30`) | ACC_Lim / d1.5 |

The capture's d1 byte distribution across 622 frames uses **exactly** bits {0,3,6}:
`0x00, 0x01, 0x08, 0x09, 0x40, 0x41, 0x48`. Handler bit3 (`0x08`) and bit6 (`0x40`) match observed
d1 bits precisely; LIM (bits4/5) simply wasn't pressed during capture (no `0x10`/`0x20` seen).
⇒ working `0x40001F80` byte0 ≡ CAN **d1**. (c)

---

## 2. Q2 — Who WRITES d1 (RES+), and with what bit logic?  → `FUN_000ebf00` (a)

Ghidra decompile:
```c
undefined8 FUN_000ebf00(void) {
  pbVar3 = (byte *)FUN_0010dfe4();          // -> source signal pointer (LIN-delivered)
  bVar1  = *pbVar3;                          // source byte
  iVar4  = (*PTR_FUN_0001fdfc)(0x22);         // enable/precondition gate
  if ((iVar4==1) || ((DAT_40001f80._0_1_>>6 & 1)!=0) || ((bVar1 & 0x7f)!=0))
      return 0x31;                            // reject
  DAT_40001f80._0_1_ = bVar1 & 0x80 | DAT_40001f80._0_1_ & 0x7f | 0x40;  // SET d1 bit6 = RES+
  FUN_0005049c(0);                            // repack frame index 0 (the 0x030 button PDU)
  return 0;
}
```
Raw disassembly (address-exact):
```
000ebf08  e_bl     0x0010dfe4          ; fetch source-signal pointer into r3
000ebf0c  se_lbz   r31,0x0(r3)         ; r31 = source LIN button byte
000ebf22  e_lis    r7,0x4000
000ebf26  e_add16i r7,r7,0x1f80        ; r7 = 0x40001F80  (working image, COMPUTED)
000ebf40  se_lbz   r0,0x0(r7)          ; r0 = current d1
000ebf42  e_rlwimi r0,r6,0x7,0x18,0x18 ; insert source-derived bit7 copy
000ebf46  se_bseti r0,0x19             ; SET bit6 (0x40) = RES+
000ebf48  se_stb   r0,0x0(r7)          ; STORE -> 0x40001F80 byte0  == CAN d1
000ebf4c  e_bl     0x0005049c          ; FUN_0005049c(0): memcpy working->frame image
```
`se_bseti r0,0x19` sets bit index 25 of the (big-endian) word view = **bit6 of byte0** = mask
`0x40` = **d1.6 = ACC_Res_Plus**. The companion handlers `FUN_000ebf5a` (LIM, bits4/5) and
`FUN_000ebae0` (bit3) use the same `e_lis 0x4000 / e_add16i 0x1f80` computed-address idiom into the
same working image — which is why the direct xref search returned "zero writers for `0x40001F81`
and only 4 for `0x40001F80`". The 4 that *were* found (`FUN_0002e7b6`, `FUN_000ebae0`,
`FUN_000ebf00`, `FUN_000ebf5a`) are the real writers; the RES+ writer is `FUN_000ebf00`. (a)

**Note:** `0x40001F81` (task's "d1") has 0 writers because the buttons pack into **byte0**, and
byte0 = CAN d1. The task's byte-offset assumption (d1 = image+1) is off by the frame's leading
constant byte; the capture-anchored truth is **image byte0 = CAN d1**.

---

## 3. Q3 — Backward trace to the LIN source  → RES+ IS a LIN/SWM signal (a)

Call graph (all edges are decompiled/disassembled `e_bl`/`se_bl`, i.e. proven):

```
LINFlex_0 hardware @0xFFE40000
   └─ FUN_000fad06  (LIN driver; param==4 branch reads SWM frame @0x40007B3C +0x18..+0x1B)
        SWM LIN RX bytes stored by FUN_000fa30a / FUN_000faaf8 into 0x40007B3C.. region
   └─ LIN RX task (function containing 0x000E8440..0x000E84C0)
        0x000E8474  e_bl FUN_000f74a0     ; decode received LIN frame into a local descriptor
        0x000E8480  se_bl FUN_000e853a    ; dispatch pass 1  (param_4=0)
        0x000E84AA  se_bl FUN_000e853a    ; dispatch pass 2  (param_4=1, commit)
             └─ FUN_000e853a  (SWM signal dispatcher — large switch on signal id FUN_0010df50())
                  case 0x194 -> FUN_000ebf5a   (LIM  -> 0x40001F80 byte0 bits4/5)
                  case ...   -> FUN_000ebae0   (      -> 0x40001F80 byte0 bit3)
                  case ...   -> FUN_000ebf00   (RES+  -> 0x40001F80 byte0 bit6)   <=== target
```

`FUN_000ebf00`'s source byte comes from `FUN_0010dfe4()` (a compiler thunk that returns the
caller-passed signal pointer in r3) → `se_lbz r31,0x0(r3)`. That pointer is the SWM LIN signal
value delivered by `FUN_000e853a(param_2=…)`, whose payload was produced by `FUN_000f74a0` reading
the LIN frame the LINFlex_0 driver received from the steering-wheel module. **The RES+ bit that
ends up on HS-CAN 0x030 d1.6 is therefore sourced from the LIN/SWM bus** — there is no other
producer of `0x40001F80` byte0 bit6 in the image. (a)

`FUN_000ebf00` is called by **only** `FUN_000e853a` (single xref @`0x000E904C`), and `FUN_000e853a`
is called by **only** the LIN RX task (2 xrefs). The chain is exclusive — no CAN-RX or other path
feeds this bit. (a)(b)

---

## 4. Q4 — Destination d5.7 (CC_Set_Plus): status & cost  → FREE (b)(c)

- **Capture:** d5 = `0x00` in **all 7 distinct payloads / 622 frames**. CC_Set_Plus is never
  emitted today. (c)
- **Ghidra xref of the working image bytes:**
  `0x40001F80`=4W/124R, `0x40001F82`=1W, and **`0x40001F81, F83, F84, F85, F86, F87 = 0 writers,
  0 readers`**. If working byte0 = d1, then d5 = byte4 = **`0x40001F84`** → 0 writers → free. (b)
- **Cost to write d5.7 in the working image:** `0x40001F84` is *outside* the 4-byte button PDU
  (only `0x40001F80..0x40001F83` = d1..d4 are copied to the frame image). Setting byte4 in the
  working image would **not** propagate to the transmitted frame unless the frame-table copy length
  (`lenword` @`0x1B7D8` = 8 → copies 4) were also enlarged and the frame image `0x40005AE0` were
  actually 8 bytes of this PDU. It is not — d5 of the emitted 0x030 comes from a *different*
  contributor image. **⇒ You cannot reach d5 by editing this button PDU.** (b)(d)

---

## 5. Full data-flow chain (LIN → signal → 0x030 d1.6)

```
SWM module (LIN bus)
  → LINFlex_0 @0xFFE40000  →  FUN_000fad06 (driver)  →  SWM RX buffer 0x40007B3C
  → LIN RX task @0x000E8440.. :  FUN_000f74a0 (decode)  →  se_bl FUN_000e853a (dispatch)
  → FUN_000e853a switch  →  FUN_000ebf00 (RES+ handler)
        r31 = *sourceLINbyte (se_lbz)              [LIN signal value]
        r7  = 0x40001F80 (e_lis+e_add16i)          [0x030 button working image]
        se_bseti r0,0x19 ; se_stb r0,0(r7)         [SET working byte0 bit6 = d1.6 = RES+]
        e_bl 0x0005049c  →  FUN_0010db0c(0x40005AE0, 0x40001F80, 4)   [memcpy work→frame image]
  → (CAN TX task)  flexcan_tx_packer FUN_000fc218 / FUN_000fc2f6
        reads frame image  →  writes FlexCAN CAN0 MB0 payload, sets CODE 0xC40 (transmit)
  → HS-CAN 500k, ID 0x030, d1.6 set  →  legacy TriCore PCM decodes @0x80381B88
```

Every arrow above is a decompiled/disassembled call (a), except the final MB write which is the
generic FlexCAN packer (a) whose per-frame byte layout is table-driven (b).

---

## 6. Remap strategy A — data-composition edit (the "spec" approach)

The existing `docs/swm_030_remap_spec.md` proposed editing F10A routing records + EXE image-byte
pointers for the `0x40007Axx` pool. **That pool is the RX/gateway path (walked by
`flexcan_rx_copier FUN_000fc63e`), NOT the transmitted 0x030** — confirmed by the prior reverted
no-op edit and by the capture. The *real* TX composition is the `0x40001F80`→`0x40005AE0` path
proven here.

To move RES+ off d1.6 within composition you would:
1. Stop `FUN_000ebf00` writing d1.6 — e.g. patch `se_bseti r0,0x19` (`0xE646` @`0x000EBF46`) so it
   sets a different bit, and/or
2. Cause d5.7 to be written from the same LIN source.

**Problem:** d5 is not in this 4-byte PDU. There is no routing record that packs this LIN signal
into d5 of the transmitted frame, and creating one requires locating d5's real contributor image
(a different frame-table/working image) and adding a signal there. This is invasive, spans the F10A
cal block, and was the source of the earlier wrong-buffer mistake. **Not recommended as the primary
path.** (d)

---

## 7. Remap strategy B — frame post-process injection (RECOMMENDED)

### 7.1 Where is the last-write-before-TX choke point?

- `FUN_000ebf00` sets working byte0, then calls `FUN_0005049c(0)` which memcpy's the **4-byte**
  button PDU (`0x40001F80`→`0x40005AE0`). This runs on every button change. (a)
- `FUN_000503cc` / `FUN_00050416` are the **bulk** copy loops (all 28 frames, working↔frame) run at
  init (`FUN_00050460` @`0x0002F13C`), not per-TX. They copy the *same* per-frame lengths, so they
  do not clobber a working-image edit but also would re-copy over a **frame-image** edit if run
  again. (a)
- The **true final choke point** is the FlexCAN TX packer **`FUN_000fc218`** (single-MB) /
  **`FUN_000fc2f6`** (walk), bound via the master net table (`0x178B8/0x17A84/0x17AE0`). It reads
  the frame image and writes the 8-byte MB payload, then stamps `CODE=0xC40` (transmit-once). This
  is the **only place where all 8 CAN bytes (d0..d7) of 0x030 are contiguous**. (a)(b)

**Consequence:** because d1 and d5 are in *different* frame-image PDUs, the bit-move
`frame[5] |= (frame[1]&0x40)<<1; frame[1] &= ~0x40;` MUST operate on the **assembled MB payload**
(or a buffer where d0..d7 are contiguous), i.e. inside/after `FUN_000fc218` for MB0. Doing it on
the 4-byte image `0x40005AE0` can clear d1.6 but **cannot set d5.7** (d5 isn't there).

### 7.2 Recommended hook site

Hook `FUN_000fc218` (`0x000FC218`), gated on **MB index 0** (`param_2[0x1a]==0`, which is 0x030 —
CAN0 MB0, the first HS-CAN TX filter entry `@0x146530 id=0x030 TX`), **immediately before** the
`*puVar6 = … | 0xc40` transmit-trigger store. At that point the MB payload bytes have been written
from the frame image; post-process them:
```
MBpay = *(int*)(iVar1+0x10) + 0x80 + MBidx*0x10 + 8   ; MB0 data bytes d0..d7
d1 = MBpay[1]; d5 = MBpay[5];
if (d1 & 0x40) { MBpay[5] = d5 | 0x80; MBpay[1] = d1 & ~0x40; }
```
This is robust: it runs on the final buffer regardless of how many PDUs contributed, and it is the
last touch before hardware transmit.

> Confidence: choke-point identity (a); exact MB-payload base offset for MB0 must be read live from
> the CAN0 controller-state block (`ctrlDesc+0x20 = 0x40000618`, `+0x10` → RAM window) or confirmed
> on-bench — standard SPC560B FlexCAN places MB0 at `RAMn+0x80`, data at `+0x88`. (b)(d)

### 7.3 Code cave (in-block, covered by the internal sum8)

Scan of `0x10000..0x13FFFE` for ≥48-byte runs of `0x00`/`0xFF`:

| addr | size | fill | note |
|------|------|------|------|
| **`0x1170F3`** | **167661 B** | `0xFF` | huge tail padding — **best cave** |
| `0x011228` | 1496 B | `0xFF` | early padding |
| `0x01000C` | 4084 B | `0xFF` | reset-block padding (avoid — near RCHW) |

Use `0x1170F3` (round up to alignment, e.g. `0x117100`). It is inside the app block so the internal
`sum8(0x10000..0x13FFFE)` covers it — the rebuild recomputes all three integrity layers anyway. (b)

### 7.4 VLE trampoline template (assembly intent — verify encodings before use)

Replace one instruction at the hook site with a branch to the cave; the cave does the bit-move,
runs the displaced original instruction, and branches back. VLE uses `e_b` (24-bit signed
displacement, opcode form `0x78000000 | (disp&0x1FFFFE)` for `e_b`, `|1` for `e_bl`); prefer a
32-bit `e_b` since the cave is far. Address loads use `e_lis`+`e_add16i` (as the firmware itself
does at `0x000EBF22`).

```asm
; --- at hook site (inside FUN_000fc218, MB0 gate, before the 0xC40 store) ---
;   original:  <INSN_ORIG>            ; e.g. the se/e_ instruction computing/storing the code word
;   patched :  e_b   cave             ; 4-byte e_b to 0x117100  (displaced insn moves to cave)

; --- cave @0x117100 ---
cave:
    ; r-scratch must be a register free at this point (confirm via live regs at the site;
    ; e200z0 VLE: save/restore if unsure)
    ; compute MB0 data pointer into rP (example uses the same iVar1 already in a reg at the site;
    ; if not available, reload from controller state)
    se_lbz   rD1, 1(rP)        ; d1
    e_andi.  rT, rD1, 0x40     ; test d1.6
    se_beq   cr0, skip
    se_lbz   rD5, 5(rP)        ; d5
    se_bseti rD5, 0x18         ; set bit7 of d5  (0x80)   [bit index 24 in word view = byte bit7]
    se_stb   rD5, 5(rP)
    e_andi.  rD1, rD1, 0xBF    ; clear d1.6 (~0x40 = 0xBF)  -- use e_and2i/e_andi. form
    se_stb   rD1, 1(rP)
skip:
    <INSN_ORIG>                ; execute the displaced original instruction
    e_b   hook_site+ilen       ; branch back to the instruction after the patched one
```

> Encoding caveat (honest): I have **not** hand-assembled the exact `e_b`
> displacement words or verified which scratch registers are dead at the chosen store — those must
> be produced with a VLE assembler (or `llvm-mc -triple=powerpc -mcpu=e200 -mattr=+spe`/Ghidra
> patch-instruction) and checked against the live register state at the hook PC. The **intent** and
> operations above are exact; the byte encodings are to be assembled/verified separately.
> `se_bseti rX,0x18` sets word-bit 24 = byte-bit7 of the low byte only when rX holds a single byte
> in bits 24..31 — since `se_lbz` zero-extends into bits 24..31, `se_bseti rX,0x18` correctly ORs
> `0x80` into the byte. (a for the firmware's own idiom; (d) for this specific sequence.)

---

## 8. Approach comparison & recommendation

| Criterion | A: composition edit | B: frame post-process hook |
|-----------|--------------------|-----------------------------|
| Can set d5.7? | **No** (d5 not in the 4-byte button PDU) | **Yes** (operates on contiguous 8-byte MB) |
| Clears old d1.6? | Yes (stop the setter) | Yes (`&= ~0x40`) |
| Files touched | EXE + **F10A** (2 checksum domains) | **EXE only** (1 checksum domain besides the container CRCs) |
| Needs code cave | No | Yes (`0x1170F3`, ample) |
| Risk of wrong-buffer repeat | High (prior mistake class) | Low (acts on final MB) |
| Reversibility | table edits | restore original insn + zero cave |
| Robustness vs firmware repack/alignment | data-dependent | code-local, deterministic |

**Recommendation: Strategy B (frame post-process injection at the FlexCAN MB0 TX packer
`FUN_000fc218`, using cave `0x1170F3`).** It is the only approach that can actually *set* d5.7
(d1 and d5 are in different composition PDUs), it touches a single flash region, and it acts on the
final contiguous frame so it is immune to the multi-PDU composition structure that defeated the
earlier data edit. Repair all three integrity layers on rebuild (internal `sum8`@`0x13FFFE`,
per-block CRC-16, file CRC-32) exactly as documented in README §2.1.

**Before flashing (on-bench):** (1) confirm MB0 is CAN0's 0x030 (read the CAN0 MB0 CS/ID after
boot); (2) confirm the MB0 data pointer arithmetic at the hook PC and a dead scratch register;
(3) assemble/verify the `e_b` displacements; (4) live-read HS-CAN 0x030 after the edit to confirm
d1.6→d5.7 movement — the image→MB binding is the project's known #1 not-yet-decompiler-closed item,
so a bus read is the final proof.

---

## 9. Address index (quick reference)

| Symbol / item | Address | Kind |
|---------------|---------|------|
| 0x030 button working image | `0x40001F80` (byte0 = CAN d1) | RAM (a)(b)(c) |
| 0x030 frame image (button PDU, 4B) | `0x40005AE0` | RAM (b) |
| 0x030 working cell for d5 (free) | `0x40001F84` (0 writers) | RAM (b) |
| Frame table entry (idx0) | flash `0x1B7CC` (stride 0x10) | data (b) |
| 28-byte frame descriptor (0x030) | flash `0x1B35C` (ctrl/stat `0x400044B0`, image `0x40005AE0`, dlcw `0x04041000`) | data (a)(b) |
| Sig list (0x030) | flash `0x152000` (= F10A+0x12000) | data (b) |
| **RES+ writer** | **`FUN_000ebf00` @`0x000EBF00`**, store @`0x000EBF48` | code (a) |
| LIM writer | `FUN_000ebf5a` @`0x000EBF5A` | code (a) |
| bit3 writer | `FUN_000ebae0` @`0x000EBAE0` | code (a) |
| SWM LIN signal dispatcher | `FUN_000e853a` @`0x000E853A` | code (a) |
| LIN RX task (dispatch calls) | `0x000E8480`, `0x000E84AA` | code (a) |
| LIN frame decode | `FUN_000f74a0` @`0x000F74A0` | code (a) |
| LINFlex_0 driver | `FUN_000fad06` @`0x000FAD06` (base `0xFFE40000`) | code (a) |
| SWM LIN RX buffer | `0x40007B3C` (+0x18..0x1B read) | RAM (a) |
| memcpy packer (work→frame) | `FUN_0005049c` @`0x0005049C` → `FUN_0010db0c` @`0x0010DB0C` | code (a) |
| bulk copy loops | `FUN_000503cc` (work→frame all), `FUN_00050416` (frame→work all) | code (a) |
| **FlexCAN TX packer (choke point)** | **`FUN_000fc218` @`0x000FC218`**, variant `FUN_000fc2f6` @`0x000FC2F6` | code (a) |
| **Code cave (recommended)** | **`0x1170F3`** (167661 B of `0xFF`) | data (b) |
| Internal checksum word | `0x13FFFE` (`sum8(0x10000..0x13FFFE)`) | data (b) |

## 10. Answers to the four questions

1. **Working image = `0x40001F80`** (frame-table idx0 @`0x1B7CC`, byte0 = CAN d1). Confirmed by
   computed-pointer disassembly in the packer and by matching handler bit-writes to the capture.
2. **d1(RES+) writer = `FUN_000ebf00`** (`se_bseti r0,0x19; se_stb r0,0x0(r7)`, `r7=0x40001F80`
   built with `e_lis/e_add16i` — the computed-address idiom that defeated auto-xref). Sibling
   writers `FUN_000ebf5a` (LIM) and `FUN_000ebae0` (bit3) use the same idiom.
3. **RES+ is a LIN/SWM signal.** Exclusive chain: LINFlex_0/`FUN_000fad06` → LIN RX task →
   `FUN_000e853a` (SWM dispatcher) → `FUN_000ebf00`, whose source byte is the dispatched LIN signal
   value (`se_lbz r31,0x0(r3)`). No non-LIN producer of d1.6 exists.
4. **d5.7 is FREE** (d5 = `0x00` in all 622 frames; cell `0x40001F84` has 0 writers) — **but it is
   in a different composition PDU**, so it can only be written by post-processing the assembled MB
   (Strategy B), not by editing the 4-byte button image.
