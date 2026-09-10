# BCM HS-CAN 0x030 Cruise-Button Composition — Location & Remap Spec

**Task:** retarget the BCM's transmitted HS-CAN `0x030` frame so the two buttons now
emitted as **ACC_Lim (d1.5)** and **ACC_Res_Plus (d1.6)** are instead emitted as
**CC_Lim** and **CC_Set_Plus**, so the legacy TriCore PCM (`SWM_CRUISE_BUTTONS.md`)
understands the new SWM module.

Confidence tags: **(a)** decompiled-code proof · **(b)** validated table structure · **(c)** inferred.

---

## 1. The BCM *does* transmit 0x030 on HS-CAN — it is Mailbox 0  (b)

HS-CAN acceptance/ID-filter list (`work/gw_mbfull.py`), first TX entry:
```
@0x146530: id=0x030 flags=0x08080000 mask=0xFFFFFFFF [TX]   ← HS-CAN (CAN0/500k), TX group
```
This is the frame the PCM receives & decodes at `0x80381B88`.

## 2. "Composition" = table-driven Volcano packer, not a hand-written function  (a)

The frame is assembled by the generic TX packer **`FUN_000fc218`** / `FUN_000fc2f6`,
which walks per-signal descriptor records and packs each button's signal-RAM cell into
a frame-image byte/bit. No CAN ID / bit position is a code immediate — all data.

- HS net: net0, ctrlDesc `0x1464E0`, FlexCAN `0xFFFC0000` (500k), descriptor table `ctrlDesc+0x44 = 0x18000`. (a)(b)
- 0x030 frame image buffer = RAM pool base **`0x40007AF8`** (d0). Byte `dN` = `0x40007AF8+N`. (b)
- Net-bringup `FUN_000fbc48` zeroes this pool at boot. (a)

### Per-signal descriptor record (flash template, 32 B)  (b)
```
+0x00 0   +0x04 0   +0x08 mbbit(IFLAG)   +0x0C routePtr→F10A(0x14xxxx)
+0x10 0x146FA0   +0x14 0x146FA4   +0x18 frame-image BYTE ptr (0x40007Axx)   +0x1C 0
```
### F10A routing record (20 B, the calibration map)  (b)
```
+0x00 sigA(src)   +0x04 sigB(dst)   +0x08 frameObj   +0x0C spec1   +0x10 spec2
  spec1 low byte  = target bitmask ;  spec2 high byte = target bitmask (redundant copies)
```

## 3. Cross-checked bit map (firmware ∧ PCM doc ∧ HS-CAN capture)  (b)

TX HS-CAN `0x030` (transmitted by the BCM), verified by decoding HS-CAN bus captures:
| signal (role) | bit | byte.bit | = |
|---|---|---|---|
| LIM on/off/cancel press | 13 | d1.5 | **ACC_Lim** (LIM) |
| Cruise resume/inc press | 14 | d1.6 | **ACC_Res_Plus** (RES+) |
| packed cruise-button status | 34 (11-bit) | d4[0:2]+d5 | packed CC word the PCM reads |

Capture `80 02 A1 80 20 00 BB 07`: d1 nibble `0x20`=LIM, `0x40`=RES+. ✓ all agree.

## 4. The two records to change  (located, verified)

| Button | descriptor (APP/EXE) | routing rec (F10A) | src sig-RAM | now writes |
|---|---|---|---|---|
| **ACC_Lim** (LIM) | `0x017CE0` +0x18 | `0x141CD8` | `0x40000832` | d1 mask `0x20` |
| **ACC_Res_Plus** (RES+) | `0x017CA0` +0x18 | `0x141C74` | `0x4000081C` | d1 mask `0x40` |

Both have `frameObj=0x400002E0` (virtual source-PDU net2 that contributes into the 0x030 image).

## 5. Desired targets
- **CC_Lim** pressed = d6 bit6 (mask `0x40` at `0x40007AFE`; PCM reads `extr.u d6,5,2`, pressed=`0x2`).
- **CC_Set_Plus** = d5.7 (mask `0x80` at `0x40007AFD`).

## 6. Proposed minimal edits (per record: image-byte ptr in EXE + bitmask in F10A)

**LIM  (d1.5 → d6.6):**
- EXE `0x017CE0+0x18`: image ptr `0x40007AF9` → `0x40007AFE`
- F10A `0x141CD8+0x0C` spec1: `0x00000020` → `0x00000040`
- F10A `0x141CD8+0x10` spec2: `0x20080200` → `0x40080200`

**RES+ (d1.6 → d5.7):**
- EXE `0x017CA0+0x18`: image ptr `0x40007AF9` → `0x40007AFD`
- F10A `0x141C74+0x0C` spec1: `0x00000040` → `0x00000080`
- F10A `0x141C74+0x10` spec2: `0x40080200` → `0x80080200`

(Old d1.5/d1.6 writers are these same two records — moving them automatically STOPS emitting the old ACC bits, per the chosen remap.)

## 7. ⚠ OPEN RISKS to resolve before writing bytes

1. **d6.6 target is NOT free — collision.** `work/gw_collide.py`:
   - d5.7 (CC_Set_Plus) = **FREE** ✓
   - d6.6 (CC_Lim) is **already written** by `fo=0x400001A1` (net0/HS), routing `0x14007C`,
     desc `0x0181A0`, from sig `0x40000683→0x40000685` — this is the BCM's **native CC_Lim**
     contributor. Two writers into one bit = OR/overwrite ordering hazard. Must decide:
     redirect LIM into the *existing* native CC_Lim signal-RAM instead, or accept/relocate.
2. **Edit spans two flash regions** (EXE image-ptr + F10A masks), i.e. **two VBF files**
   (`JV6T-14C094-AD.VBF` app + `JV6T-14C403-AB.VBF` F10A) → two checksum domains to repair.
3. **image→MB0 binding is structurally consistent but not yet decompiler-proven** (the project's
   known #1 open item). Decoded captures + PCM doc + byte map triangulate it, but a live HS-CAN read of the
   edited frame is the only on-target proof.
