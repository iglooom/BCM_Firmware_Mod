# ACC-FIX — SWM cruise-button remap in TX HS-CAN `0x030` (BCM → old PCM)

**Status:** ✅ on-vehicle proven. **Artifact:** `work/acc-fix/JV6T-14C094-AD_acc-fix.VBF`
(APP/EXE VBF only). **Base OEM:** `JV6T-14C094-AD.VBF` (sha256 of OEM app block backup in
`work/backups/`). **Patched sha256:** `f5fb75e33398f860d17b1b21496fdc9c8ca525bc55a446ef82f3278a1b02c9eb`.

This document is the exact, reproducible record of the modification. For a version-agnostic porting
guide (how to redo this on a *different* OEM BCM firmware), read **`../AGENTS.md`**.

---

## 1. Problem

A **new SWM** (steering-wheel module) is being fitted to a car with an **old PCM**. The BCM reads
the SWM buttons over **LIN** and composes them into the TX HS-CAN frame **`0x030`** (BCM→bus). The
new SWM's cruise combo buttons are emitted on bits/positions the old PCM does not act on, so
cruise/limiter control does not work. The LIN side is fine and is **not** touched — we only rewrite
the composed `0x030` payload so the old PCM sees the signals it expects.

## 2. Target bit map (HS-CAN `0x030`, bytes d0..d7)

Confirmed against firmware composition code, the PCM-side doc
(`/home/gl/Projects/ford/PCM/PCM_Research/SWM_CRUISE_BUTTONS.md` §3), a HS-CAN signal database, and
bus captures.

| Button (as SWM composes it) | Source bit | Old-PCM target | Target bit(s) |
|---|---|---|---|
| `ACC_Res_Plus` (combo) | d1 bit6 `0x40` | `CC_Res` **or** `CC_Set_Plus` | d5 bit5 `0x20` / d5 bit7 `0x80` |
| `ACC_Lim` | d1 bit5 `0x20` | `CC_Lim` (2-bit field) | d6[5:6] = `0b10` pressed |

Baseline `0x030` at rest: `80 00 A1 80 A0 00 B3 07`. Note **d6 = 0xB3** always at rest, i.e. the
CC_Lim field `d6[5:6]` already reads `0b01` = *released* natively — so LIM only needs to write
`0b10` (pressed) when active and leave the byte otherwise.

## 3. RES+ context gate — read the PCM status back

`ACC_Res_Plus` is a **combo** button. It must act as **Resume** only when cruise/limiter is
*cancelled with a stored set-speed*, otherwise as **Set+**. Two received frames are combined:
**`0x0C0` d0** (cruise/limiter status) and **`0x060` d6** (current stored set-speed).

The status byte `0x0C0` d0 is **ambiguous on its own** — a *fresh* cancel decays after ~2 s to the
same value as *engaged-but-no-speed-set-yet*:

| mode | engaged-not-set | active | cancel (fresh) | cancel (after ~2 s) |
|---|---|---|---|---|
| **cruise** | `0x18` | `0x10` | `0x40` | **→ `0x18`** |
| **limiter** | `0x38` | `0x30` | `0x48` | **→ `0x38`** |

So `0x18`/`0x38` mean *either* "just engaged, no speed" *or* "cancelled a while ago" — the status
byte cannot tell them apart. The tie-breaker is **`0x060` d6 = the stored set-speed** (`0x00` until a
speed has ever been set; e.g. `0x1E` = 30 km/h once set).

**Gate = `(d0 & 0x48) != 0` AND `(0x060 d6 != 0)`** → **Resume**, else **Set+**:
- `d0 & 0x48` = bit3 (StandBy, set in all decayed cancel + the `0x48` fresh-limiter-cancel) OR bit6
  (set in the `0x40`/`0x48` fresh cancels) — covers every cancelled/paused state, fresh or decayed.
- `d6 != 0` requires a speed to actually be stored → excludes "engaged-not-set-yet" (`0x18`/`0x38`
  with `d6==0`) and plain off.

| d0 | 060 d6 | state | RES+ |
|---|---|---|---|
| `0x00` | 0 | off | Set+ |
| `0x18` | 0 | cruise engaged-not-set | Set+ |
| `0x10` | ≠0 | cruise active | Set+ |
| `0x40` | ≠0 | cruise cancel (fresh) | **Resume** |
| `0x18` | ≠0 | cruise cancel (decayed) | **Resume** |
| `0x38` | 0 | limiter engaged-not-set | Set+ |
| `0x30` | ≠0 | limiter active | Set+ |
| `0x48` | ≠0 | limiter cancel (fresh) | **Resume** |
| `0x38` | ≠0 | limiter cancel (decayed) | **Resume** |

> ⚠ **Gate history — each corrected on the car:** (1) bit3-alone mis-fires on limiter no-speed
> standby `0x38` (`candump-2026-09-09_175536.log`); (2) interim `(d0&0x28)==0x08` came from misreading
> cruise-*started* `0x18`/*active* `0x10` as paused; (3) bit6-alone (`0x40`) worked briefly but
> **the status byte decays** so cancelled cruise/limiter drop to `0x18`/`0x38` after ~2 s and could
> no longer be told from engaged-not-set (`candump-2026-09-09_191816.log`). The **two-frame**
> `(d0 & 0x48) && (0x060 d6 != 0)` rule is the robust fix.

**Read sources (both plain decoded RAM frame-images, verbatim byte copies by RX copier
`FUN_000fc63e` — see `docs/0c0_standby_read.md`):**
- `0x0C0` d0 at **`0x40000707`** (MB30, copymask `0x13`).
- `0x060` d6 at **`0x40000705`** (MB22, dest base `0x40000700`, copymask `0xFE`). The copy is
  **compacted** (dest advances only for set mask bits): d6 is preceded by 5 set bits {1,2,3,4,5} →
  `0x40000700 + 5`. Do **not** read the raw FlexCAN mailboxes from a TX hook (CODE/BUSY+lock, can tear).

### 3.1 Edge-latch — hold the decision for the whole press (on-vehicle fix)

The gate above is correct *per frame*, but a single physical press is **held ~240 ms** and `0x030` is
sent every ~10 ms while held. Resume works — but it flips the PCM **paused → active mid-press**, so
from the next frame the per-frame gate sees "active" and emits **Set+**, bumping the set-speed
(`candump-2026-09-09_214156.log`: brief `d5.5` Res then a long run of `d5.7` Plus, `0x060` d6
`0x50→0x55`). Fix: latch the Res-vs-Plus decision at the **rising edge** and hold it until release,
in a persistent byte **`L @0x40011000`** (0=idle, 1=Res, 2=Plus):

```c
if (d1 & 0x40) {                        // ResPlus held
    if (L == 0)                         // rising edge -> decide once
        L = ((c0d0 & 0x48) && setspeed) ? 1 : 2;
    d5 |= (L == 1) ? 0x20 : 0x80;       // apply latched decision each held frame
    d1 &= ~0x40;
} else L = 0;                           // released -> reset
```

**`0x40011000` is proven-unused SRAM** (full analysis in `docs/scratch_ram.md`): it sits inside the
startup ECC/zero-init range `[0x400039A0..0x40014000]` (so it powers up as 0), **above** the stack
top (SP=`0x4000CAC8`, grows down), **below** the SDA base (`0x40017920`), and has **zero references
anywhere in flash** (checked against 28,536 resolved SRAM refs + raw pointer scan). Both caves share
this one byte. No stock code is modified — deliberately *not* reusing SWM button-state RAM, because
the LIN button handlers still write those bytes every frame (they'd fight the latch).

## 4. Why an injection hook (not a data-table edit)

`0x030` is composed from **multiple PDUs**: the button PDU copies only d1..d4, while d5 and d6 are
separate sub-PDUs. There is no point during signal packing where d1 and d5/d6 are together, so the
bit cannot be "moved" by editing routing records. The only place all 8 bytes of `0x030` are
contiguous and final is the **FlexCAN mailbox** just before transmit. So we hook the TX packers and
post-process the assembled mailbox payload.

Two packers can emit `0x030` (button-change vs periodic), both hooked, each **gated on CAN0 MB0**
(the mailbox that carries `0x030`; its CS register is at `0xFFFC0080`, data d0 at `+0x88`):

| Packer | Role | Hook site | Displaced instruction(s) | Cave |
|---|---|---|---|---|
| `FUN_000fc218` | single-frame TX | `0xFC2C2` | `e_sth r7,0x0(r10)` | `accfix_cave_single_packer` @ `0x117100` |
| `FUN_000fc2f6` | periodic walker | `0xFC440` | `se_extzh r7; se_sth r7,0x0(r29)` | `accfix_cave_walker_packer` @ `0x117300` |

The gate is by **absolute MB-CS address** (`cmplw mbreg, 0xFFFC0080`), not MB index — exact, and a
no-op for any packer call that serves a different mailbox.

## 5. Cave logic (verified VLE disassembly, single-packer cave)

`mbreg` = r10 (single) / r29 (walker). `r3` holds `0xFFFC0089` (MB0 d1), so d5=`0x4(r3)`, d6=`0x5(r3)`.
RES+ is **edge-latched** through `L @0x40011000` (0=idle,1=Res,2=Plus). r4=address scratch, r0=value
scratch (r0 is invalid as a load base register, so the address always goes in r4).

```
00117100  e_stwu r1,-0x10(r1)     ; save frame (r0,r3,r4)
00117104  e_stw  r0,0xc(r1)
00117108  e_stw  r3,0x8(r1)
0011710C  e_stw  r4,0x4(r1)
00117110  e_lis  r0,0xfffc        ; r0 = 0xFFFC0080 (CAN0 MB0 CS addr)
00117114  e_or2i r0,0x80
00117118  cmplw  r10,r0           ; GATE: is this MB0 (=0x030)?
0011711C  e_bne  cr0,0x001171FE   ;   no -> done
00117120  e_lis  r3,0xfffc        ; r3 = 0xFFFC0089 (MB0 d1)
00117124  e_add16i r3,r3,0x89
                                    ; ---- RES+ edge-latched ----
00117128  e_lbz  r0,0x0(r3)       ; d1
0011712C  e_andi. r0,r0,0x40      ; ACC_Res_Plus held?
00117130  e_beq  cr0,0x001171C6   ;   not held -> NOTHELD (reset latch)
00117134  e_lis  r4,0x4001        ; r4 = &L (0x40011000)
00117138  e_add16i r4,r4,0x1000
0011713C  e_lbz  r0,0x0(r4)       ; L
00117140  se_cmpi r0,0x0
00117142  e_bne  cr0,0x00117190   ;   already latched -> APPLY
                                    ; -- rising edge: decide once --
00117146  e_lis  r4,0x4000        ; r4 = 0x40000707 (0x0C0 d0)
0011714A  e_add16i r4,r4,0x707
0011714E  e_lbz  r0,0x0(r4)       ; c0 d0
00117152  e_andi. r0,r0,0x48      ; cancelled/paused? (bit3 | bit6)
00117156  e_beq  cr0,0x00117180   ;   no -> SETPLUS
0011715A  e_lis  r4,0x4000        ; r4 = 0x40000705 (0x060 d6 set-speed, compacted)
0011715E  e_add16i r4,r4,0x705
00117162  e_lbz  r0,0x0(r4)       ; set-speed
00117166  se_cmpi r0,0x0          ; speed stored?
00117168  e_beq  cr0,0x00117180   ;   no speed -> SETPLUS (engaged-not-set)
0011716C  e_li   r0,0x1           ; latch L=1 (Res)
00117170  e_lis  r4,0x4001
00117174  e_add16i r4,r4,0x1000
00117178  e_stb  r0,0x0(r4)
0011717C  e_b    0x00117190       ; -> APPLY
00117180  e_li   r0,0x2           ; SETPLUS: latch L=2 (Plus)
00117184  e_lis  r4,0x4001
00117188  e_add16i r4,r4,0x1000
0011718C  e_stb  r0,0x0(r4)
                                    ; -- APPLY latched decision (r4=&L) --
00117190  e_lbz  r0,0x0(r4)       ; L
00117194  se_cmpi r0,0x1
00117196  e_bne  cr0,0x001171AA   ;   L!=1 -> APLUS
0011719A  e_lbz  r4,0x4(r3)       ; Res: d5 |= 0x20 (CC_Res)
0011719E  e_or2i r4,0x20
001171A2  e_stb  r4,0x4(r3)
001171A6  e_b    0x001171B6
001171AA  e_lbz  r4,0x4(r3)       ; APLUS: d5 |= 0x80 (CC_Set_Plus)
001171AE  e_or2i r4,0x80
001171B2  e_stb  r4,0x4(r3)
001171B6  e_lbz  r0,0x0(r3)       ; clear old ACC_Res_Plus
001171BA  e_and2i. r0,0xbf        ;   d1 &= ~0x40
001171BE  e_stb  r0,0x0(r3)
001171C2  e_b    0x001171D6       ; -> SKIPRES (skip NOTHELD)
001171C6  e_lis  r4,0x4001        ; NOTHELD: L = 0 (released -> reset latch)
001171CA  e_add16i r4,r4,0x1000
001171CE  e_li   r0,0x0
001171D2  e_stb  r0,0x0(r4)
                                    ; ---- LIM : d1.5 -> d6[5:6]=0b10 pressed ----
001171D6  e_lbz  r0,0x0(r3)       ; d1
001171DA  e_andi. r0,r0,0x20      ; ACC_Lim?
001171DE  e_beq  cr0,0x001171FE   ;   no -> done
001171E2  e_lbz  r4,0x5(r3)       ; d6
001171E6  e_and2i. r4,0x9f        ;   clear field d6[5:6]
001171EA  e_or2i r4,0x40          ;   set 0b10 (pressed)
001171EE  e_stb  r4,0x5(r3)
001171F2  e_lbz  r0,0x0(r3)       ; clear old ACC_Lim
001171F6  e_and2i. r0,0xdf        ;   d1 &= ~0x20
001171FA  e_stb  r0,0x0(r3)
001171FE  e_lwz  r0,0xc(r1)       ; done: restore frame
00117202  e_lwz  r3,0x8(r1)
00117206  e_lwz  r4,0x4(r1)
0011720A  e_add16i r1,r1,0x10
0011720E  e_sth  r7,0x0(r10)      ; REPLAY displaced store (arms the mailbox)
00117212  e_b    0x000fc2c6       ; return after hook
```

The walker cave `0x117300` is identical except: `mbreg`=r29; the two displaced instructions
`se_extzh r7; se_sth r7,0x0(r29)` are replayed; return to `0xFC444`. **Both caves share the same
latch byte `L @0x40011000`** (same logical button, so a press seen by either packer is consistent).

## 6. Integrity (see README §2.1) — repaired by the build

Any app-block edit invalidates three layers; `build_vbf.py` repairs all in order:
1. internal `sum8 @0x13FFFE = Σ bytes[0x10000..0x13FFFE] & 0xFFFF`
2. per-block CRC-16/CCITT-FALSE
3. file CRC-32 in the header

Caves sit in the app block's `0xFF` padding (`0x117100`, `0x117300`) so they are covered by sum8.
Only the APP VBF changes — no F10A edit — because the hook lives entirely in EXE code.

## 7. Files

- Build: `work/acc-fix/build_caves.py` → `patch_blobs.json` → `build_vbf.py` → the VBF.
- Verify: `work/acc-fix/verify.py` (CRCs + sum8 + cave re-disasm + behavior sim + diff-vs-OEM).
- Ghidra annotations: `work/acc-fix/annotate_ghidra.py` (labels/plate comments/bookmarks).
- Evidence: `docs/0c0_standby_read.md` (0x0C0 read address), `docs/scratch_ram.md` (latch-byte
  proof), `docs/030_composition_trace.md` (0x030 composition/LIN chain), and the candumps
  (`..._175536` state encoding, `..._191816` decay, `..._214156` held-press bump).

## 8. On-vehicle behavior (final, matches simulation)

| Press | Condition | Result on `0x030` |
|---|---|---|
| RES+ | off / engaged-not-set (`0x18`/`0x38`, d6=0) / active (`0x10`/`0x30`) | d5.7 set (**CC_Set_Plus**) |
| RES+ | cancelled (`0x40`/`0x48` fresh, or `0x18`/`0x38` decayed) AND `0x060` d6 ≠ 0 | d5.5 set (**CC_Res**) |
| LIM | any | d6 `0xB3→0xD3` (**CC_Lim** field `0b10` pressed) |
| RES+ & LIM together | cancelled-with-speed | d5.5 + d6.field both set |

**Held-press behavior (edge-latch):** the decision is made once at the rising edge and held for the
whole press, so a Resume that flips the PCM paused→active mid-press stays Resume (no Set+ speed-bump)
until the button is released. Verified by the held-press regression in `verify.py`.
