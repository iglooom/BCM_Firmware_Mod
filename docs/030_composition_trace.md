# HS-CAN `0x030` composition trace — LIN/SWM → transmitted frame

**Why this exists:** evidence backing the `acc-fix` mod (`acc-fix.md`). It answers where the
`0x030` cruise-button bits are composed, that they originate on the LIN/SWM bus, and **why the remap
had to be done at TX time** rather than by editing composition data.

Evidence tags: **(a)** decompiled/disassembled code · **(b)** validated table structure ·
**(c)** capture / on-bus ground truth · **(d)** inferred.

---

## 1. Result in brief

| Question | Answer |
|---|---|
| `0x030` button working image | **`0x40001F80`**, and its **byte0 = CAN d1** (a)(b)(c) |
| Who sets RES+ (d1 bit6) | **`FUN_000ebf00`**, store at `0x000EBF48` (a) |
| Where RES+ comes from | the **LIN/SWM** bus — exclusive chain, no CAN-RX producer (a) |
| Is d5 reachable from that image | **No** — d5 belongs to a different contributor PDU (b)(d) |
| ⇒ where the remap must happen | on the assembled frame — TX frame image or FlexCAN mailbox (a)(b) |

---

## 2. The working image is `0x40001F80`, byte0 = CAN d1 (a)(b)(c)

Frame table at flash `0x1B7CC`, 16-byte stride, `[+0 work][+4 frame][+8 f10aoff][+0xC lenword]`:

| idx | @flash | work img | frame img | lenword | copy bytes |
|---|---|---|---|---|---|
| **0** | `0x01B7CC` | **`0x40001F80`** | **`0x40005AE0`** | `0x08` | **4** |
| 1 | `0x01B7DC` | `0x40002860` | `0x400063C0` | `0x40` | 60 |
| 2 | `0x01B7EC` | `0x40001F88` | `0x40005AE8` | `0x2E0` | 732 |

The packer `FUN_0005049c` reaches the table through a **computed pointer** (@`0x000504B6`):

```
e_slwi   r31,r30,0x4        ; idx*16
e_add16i r31,r31,-0x4834
e_add2is r31,0x2            ; => r31 = 0x1B7CC + idx*16
se_lwz   r29,0x4(r31)       ; frame image  = 0x40005AE0
se_lwz   r5, 0xc(r31)       ; lenword      = 8
se_lwz   r4, 0x0(r31)       ; work image   = 0x40001F80
se_subi  r5,0x4             ; => len 4
e_bl     0x0010db0c         ; memcpy(frame, work, 4)
```

Because the base is synthesised as `-0x4834 + 0x20000` and never appears as a single immediate,
**no absolute xref exists**. A raw immediate scan of the whole app block found `0x40001F80` only in
the frame table itself — no code hardcodes the buffer. (a)(b)

**Byte semantics, anchored on captures (c):** the three button handlers write only byte0 and byte2
of the working image:

| handler | bit op on byte0 | button |
|---|---|---|
| `FUN_000ebae0` | `\| 0x08` (bit3) | ACC Cruise (d1.3) |
| `FUN_000ebf00` | `\| 0x40` (bit6) | **ACC_Res_Plus** (d1.6) |
| `FUN_000ebf5a` | bits 4/5 (`0x10`/`0x30`) | ACC_Lim (d1.5) |

The captured d1 byte distribution across 622 frames uses exactly bits {0,3,6}
(`0x00 0x01 0x08 0x09 0x40 0x41 0x48`) — matching handler bits 3 and 6 precisely (LIM was not
pressed during that capture). ⇒ **working byte0 ≡ CAN d1**, not `0x40001F81` as first assumed.

---

## 3. RES+ writer — `FUN_000ebf00` (a)

```c
undefined8 FUN_000ebf00(void) {
  pbVar3 = (byte *)FUN_0010dfe4();            // -> LIN-delivered source signal pointer
  bVar1  = *pbVar3;
  iVar4  = (*PTR_FUN_0001fdfc)(0x22);          // enable/precondition gate
  if ((iVar4==1) || ((DAT_40001f80._0_1_>>6 & 1)!=0) || ((bVar1 & 0x7f)!=0))
      return 0x31;                             // reject
  DAT_40001f80._0_1_ = bVar1 & 0x80 | DAT_40001f80._0_1_ & 0x7f | 0x40;  // SET d1 bit6
  FUN_0005049c(0);                             // repack frame index 0
  return 0;
}
```

```
000ebf08  e_bl     0x0010dfe4          ; source-signal pointer -> r3
000ebf0c  se_lbz   r31,0x0(r3)         ; source LIN button byte
000ebf22  e_lis    r7,0x4000
000ebf26  e_add16i r7,r7,0x1f80        ; r7 = 0x40001F80 (COMPUTED address)
000ebf40  se_lbz   r0,0x0(r7)
000ebf42  e_rlwimi r0,r6,0x7,0x18,0x18
000ebf46  se_bseti r0,0x19             ; set bit6 (0x40) = RES+
000ebf48  se_stb   r0,0x0(r7)          ; -> working byte0 == CAN d1
000ebf4c  e_bl     0x0005049c          ; memcpy work -> frame image
```

`se_bseti r0,0x19` sets word-bit 25 = byte0 bit6 = `0x40`. The sibling handlers use the same
`e_lis/e_add16i` computed-address idiom into the same image — which is why an xref search alone
misses them.

---

## 4. RES+ originates on LIN/SWM — exclusive chain (a)

```
LINFlex_0 @0xFFE40000
  └─ FUN_000fad06 (LIN driver; SWM frame @0x40007B3C +0x18..+0x1B)
  └─ LIN RX task (0x000E8440..0x000E84C0)
       0x000E8474  e_bl  FUN_000f74a0    ; decode LIN frame
       0x000E8480  se_bl FUN_000e853a    ; dispatch pass 1
       0x000E84AA  se_bl FUN_000e853a    ; dispatch pass 2 (commit)
            └─ FUN_000e853a  (SWM signal dispatcher, switch on signal id)
                 case 0x194 -> FUN_000ebf5a   (LIM,   byte0 bits4/5)
                 case ...   -> FUN_000ebae0   (       byte0 bit3)
                 case ...   -> FUN_000ebf00   (RES+,  byte0 bit6)
```

`FUN_000ebf00` has exactly **one** caller (`FUN_000e853a` @`0x000E904C`), and `FUN_000e853a` has
exactly two (the LIN RX task's two dispatch passes). No CAN-RX or other path feeds this bit.

The LIN side is mapped in full in `owner_flash_layers.md` §24.2 (LINFlex_0 master driver).

---

## 5. Why a TX-time hook and not a data edit (b)(d)

- The button PDU copies **4 bytes only** (`d1..d4`, working `0x40001F80` → frame image
  `0x40005AE0`). **d5 is not in it** — it is populated by a different contributor.
- d5 in the working image (`0x40001F84`) has **0 writers and 0 readers**, and writing it would not
  propagate: the frame-table copy length is 4.
- ⇒ **The bit cannot be "moved" inside composition.** Any remap must run where d1 and d5/d6 are
  simultaneously present in one buffer.

Two such places exist, and the earlier claim that only the mailbox qualifies was **too strong**:

| Stage | Address | Note |
|---|---|---|
| **assembled TX frame image** | `0x40000760` (d0), present mask `0xFF` — TX record array `0x0014AA0C`, MB0 | d1 `…61`, d5 `…65`, d6 `…66`. No other TX record's window overlaps. Earliest point where all three coexist. |
| **FlexCAN mailbox** | CAN0 MB0 CS `0xFFFC0080`, d0 `0xFFFC0088` | the last touch before hardware transmit — **what acc-fix hooks** |

acc-fix hooks the two TX packers (`FUN_000fc218` single-frame, `FUN_000fc2f6` periodic walker) and
rewrites the mailbox payload; it is on-vehicle proven. The frame-image stage is recorded here only
as a cheaper alternative hook site if the mod is ever reworked.

> **Retracted approach — do not revive.** An earlier spec proposed editing F10A routing records plus
> EXE image-byte pointers in the `0x40007Axx` pool. That pool is the **RX/gateway** path (walked by
> `FUN_000fc63e`), not the transmitted `0x030`; the edit was flashed and was a confirmed no-op.
> A composition-side remap is additionally impossible for the PDU reason above.

---

## 6. Address index

| Item | Address | Kind |
|---|---|---|
| `0x030` button working image | `0x40001F80` (byte0 = CAN d1) | RAM (a)(b)(c) |
| `0x030` button-PDU frame image (4 B) | `0x40005AE0` | RAM (b) |
| Assembled `0x030` TX frame image (8 B) | `0x40000760` | RAM (a) |
| Frame table entry idx0 | flash `0x1B7CC` (stride `0x10`) | data (b) |
| TX descriptor array (HS) | flash `0x0014AA0C` | data (a) |
| **RES+ writer** | `FUN_000ebf00` @`0x000EBF00`, store @`0x000EBF48` | code (a) |
| LIM writer | `FUN_000ebf5a` @`0x000EBF5A` | code (a) |
| Cruise-bit3 writer | `FUN_000ebae0` @`0x000EBAE0` | code (a) |
| SWM LIN signal dispatcher | `FUN_000e853a` @`0x000E853A` | code (a) |
| LIN RX task dispatch calls | `0x000E8480`, `0x000E84AA` | code (a) |
| LIN frame decode | `FUN_000f74a0` | code (a) |
| LINFlex_0 driver | `FUN_000fad06` (base `0xFFE40000`) | code (a) |
| SWM LIN RX buffer | `0x40007B3C` (+0x18..0x1B) | RAM (a) |
| work→frame memcpy packer | `FUN_0005049c` → `FUN_0010db0c` | code (a) |
| **FlexCAN TX packers** | `FUN_000fc218`, `FUN_000fc2f6` | code (a) |
| acc-fix caves | `0x117100`, `0x117300`/`0x117400` | code (a) |
| Internal checksum word | `0x13FFFE` (`sum8(0x10000..0x13FFFE)`) | data (b) |
