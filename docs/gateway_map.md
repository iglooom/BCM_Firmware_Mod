# Ford BCM (C1MCA) — CAN gateway reference

Single reference for **how the BCM's CAN behaviour is described in flash** and **what is actually
proven about it**: the Volcano table stack, the per-bus CAN-ID inventory, the frame maps, and the
cross-bus routing model.

Supersedes the earlier `volcano_calibration_documentation.md`, `gateway_map_format.md`,
`gateway_map_current.md` and `gateway_id_interaction_map.md` (merged here; their disproven parts are
recorded in §7 instead of being repeated).

- **MCU:** SPC560B64L7 (MPC5607B family), PowerPC e200z0h, **big-endian**, VLE. Flash base `0x0`.
- **Images:** `backups/owner-backup-20260911T090300Z/cflash.bin` (owner full flash — primary) and
  `work/flash_merged.bin` (OEM VBFs re-assembled — the image the shipped mods are built against).
- **Ghidra:** `ghidra_proj_fullflash/BCM_OwnerFlash` (primary), `ghidra_proj/BCM_C1MCA` (mod builds).
- **Deeper analysis:** `owner_flash_layers.md` — this doc is the condensed, stable result; that doc
  is the derivation and the per-layer evidence.

> Confidence tags: **(a)** proven via decompiled code · **(b)** proven via validated table
> structure · **(c)** inferred / not fully decoded.

---

## 0. The model in one paragraph

The BCM is a **table-driven Volcano gateway** (F10A header: *"Generated with Volcano5.6x release
6bp_1_6"*). The application is generic; every CAN behaviour — which frames exist, on which bus, at
which ID, carrying which signals — is **data** in the calibration blocks, walked at runtime by
`FUN_0004471a → FUN_000fbc48(&PTR_00140000)`. **Proof (a):** no CAN ID and no FlexCAN base address
appears as a code immediate anywhere in the application.

Gateway translation is **not** frame forwarding. A signal cell in RAM is written while unpacking an
RX frame and read while packing a TX frame; that shared cell *is* the route. Same CAN-ID number on
two buses proves nothing (§7.1).

---

## 1. Table stack and the master network table — `0x000178B0` (a)(b)

```
[1] Master network table   0x0178AC / 0x017A78 / 0x017AD4   one record per CAN network
       +0x08 → controller descriptor
[2] Controller descriptors 0x1464E0 / 0x146900 / 0x146C50   FlexCAN base, CTRL/baud
       followed by ↓
[3] MB acceptance/ID filter list 0x146530 / 0x146950 / 0x146CA0   (12 B/record: id, dir, mask)
[4] RX/TX descriptor arrays — anchored at RUNTIME via S+0x44 → T (§1.2), not from flash
[5] Signal-routing records 0x140000–0x15BF00   (28 B/record, §3)
[6] Signal descriptors 0x15A920 (24 B) + defaults in F124 @0xC000
```

### 1.1 Network record layout (a)

Read out of the TX packer's own dereference chain (it derives the FlexCAN base from
`*(param_1+8)+0x10`):

| Offset | Meaning |
|---|---|
| `+0x00` | → per-net **config block** in flash (`0x144B90` / `0x146060` / `0x146330`) |
| `+0x04` | → **`S`**, the per-net **RAM state block** (`0x400001A0` / `0x400004FC` / `0x40000588`) |
| `+0x08` | → **controller descriptor** (`0x1464E0` / `0x146900` / `0x146C50`) |
| `+0x0C`… | codec function pointers |

Real record bases are `0x0178AC`, `0x017A78`, `0x017AD4` and the **stride is not uniform**
(`0x1CC`, then `0x5C`) — the net table cannot be indexed as a flat array.

### 1.2 Descriptor arrays are anchored at runtime (a)

`VOL_network_bringup` installs the anchor: **`S+0x44 → T`**, then `T+0x04` = TX descriptor array,
`T+0x08` = RX record array, `T+0x10`/`T+0x11` = the two counts. This is why **no flash pointer to
the descriptor arrays exists**, and why the old "`ctrlDesc+0x44` is the descriptor table" reading
was wrong (§7.2).

| `T` block | RX arrival-flag page | Net |
|---|---|---|
| `0x144C20`, `0x144CB0` | `0x400001A0..A7` | CAN_0 HS |
| `0x146180`, `0x146210` | `0x400004FC..FF` | CAN_1 MS |

(Two blocks per bus; which one is live is selected at bring-up — **resolve this before any
record-level patch**, §8. Frame-image addresses are shared between the pair and therefore safe.)

### 1.3 Controller descriptor (a)(b)

| Offset | Meaning |
|---|---|
| `+0x00` | flags (`0x03020007` / `0x03000007`) |
| `+0x04` | network index |
| `+0x10` | **FlexCAN peripheral base** |
| `+0x14`,`+0x18` | sub-config tables (`0x15AExx`) |
| `+0x20` | controller runtime state block (`0x40000618` / `638` / `658`) |
| `+0x30` | **FlexCAN CTRL register value** (baud) |
| `+0x50` | start of the 12-byte MB filter list (§2) |

**Baud** = `f_can / ((PRESDIV+1)·TQ)` with `TQ = 1+(PROPSEG+1)+(PSEG1+1)+(PSEG2+1)`, f_can = 30 MHz:

| Net | Ctrl desc | FlexCAN base | CTRL | Baud | Bus |
|---|---|---|---|---|---|
| net0 | `0x1464E0` | `0xFFFC0000` | `0x05492004` | **500 kbps** | **HS-CAN** |
| net5 | `0x146900` | `0xFFFC4000` | `0x17DB2000` | **125 kbps** | **MS-CAN** (body) |
| net6 | `0x146C50` | `0xFFFC8000` | `0x17DB2000` | **125 kbps** | **MSX-CAN** (side/parking modules) |

Nets 1–4 (`0x146830/64/98/CC`) are virtual/internal signal groups, off the primary gateway path.

---

## 2. MB acceptance / ID filter list (b)

Array of **12-byte** records directly after each controller descriptor:

| Offset | Meaning |
|---|---|
| `+0x00` | **`CAN_id << 18`** (standard-ID position, bits 28:18) |
| `+0x04` | flags — high byte **`0x08` = TX**, **`0x04` = RX** |
| `+0x08` | acceptance mask (`0xFFFFFFFF` = exact match) |

**Filter-list position = hardware mailbox index.** Proven by the bring-up loop `FUN_000fceb8`,
which walks the list sequentially writing `MB[i].ID = list[i]` at `base + 0x80 + i*0x10`. Hence:

```
MB CS word  = CAN_base + 0x80 + MBidx*0x10
data d0..d7 = CS + 0x8 .. CS + 0xF
```

Worked examples used by the shipped mods: `0x030` = CAN0 MB0 → CS `0xFFFC0080`;
`0x3A` = CAN1 MB1 → CS `0xFFFC4090`; `0x0C0` = CAN0 MB30 → CS `0xFFFC0260`, d0 `0xFFFC0268`.

All 140 mailboxes across the three controllers are labelled in `ghidra_proj_fullflash` with their
computed addresses, direction, domain and cycle time (`work/owner/27_annotate_mailboxes.py`).

### 2.1 Per-bus CAN-ID inventory (authoritative) (b)

From the filter lists (`python3 work/gw_mbfull.py`). Direction is from the BCM's perspective.

**HS-CAN (net0, 500 kbps) — list `0x146530`**

- RX (46): `0x010 0x020 0x040 0x04A 0x04B 0x060 0x06A 0x070 0x080 0x090 0x0A0 0x0A5 0x0B0 0x0C0
  0x0D0 0x0E0 0x0F8 0x100 0x120 0x130 0x138 0x140 0x160 0x170 0x180 0x190 0x1A0 0x1A8 0x1B0 0x1B5
  0x1C0 0x1D0 0x1E0 0x1E8 0x200 0x208 0x210 0x218 0x229 0x250 0x252 0x269 0x270 0x280 0x298 0x500`
- TX (17): `0x030 0x0C8 0x150 0x17E 0x260 0x290 0x310 0x360 0x380 0x3B4 0x400 0x405 0x40A 0x420
  0x435 0x581 0x72E`

**MS-CAN (net5, 125 kbps) — list `0x146950`**

- RX (14): `0x010 0x030 0x090 0x0A0 0x100 0x108 0x130 0x150 0x160 0x180 0x190 0x1A0 0x1B8 0x500`
- TX (49): `0x020 0x03A 0x040 0x060 0x070 0x080 0x083 0x110 0x1A4 0x1A8 0x1B0 0x1B4 0x1C0 0x1E0
  0x215 0x217 0x220 0x230 0x240 0x241 0x250 0x265 0x270 0x280 0x281 0x290 0x295 0x2A0 0x2A7 0x300
  0x320 0x340 0x360 0x361 0x363 0x370 0x3A0 0x400 0x405 0x40A 0x415 0x435 0x440 0x501 0x581 0x690
  0x72E 0x7CC 0x7CE`

**MSX-CAN (net6, 125 kbps) — list `0x146CA0`:** 14 mailboxes, obstacle/parking IDs only
(`0x120 0x370 0x380 0x400 0x405 0x501 0x581 0x7C4 0x7C6 0x7DF …`). No `0x020/0x060/0x0C0`.

**External validation:** the filter tables were cross-checked against the vehicle CAN databases
(the MS-CAN CSV carries a per-ECU send/receive column = ground truth): **58 MS directions agree, 0
mismatches**; 62 of 63 HS mailboxes present in the DBC (`work/owner/25_can_db_xref.py`). This is
the only external confirmation of the decoding the whole gateway model rests on.

**Bus character:** HS = 17 TX / 46 RX mailboxes (the BCM mostly *listens* to powertrain/chassis);
MS = 49 TX / 14 RX (the BCM is the *authority* body modules obey). The runtime descriptor arrays
carry slightly different counts (MS: 43 TX + 30 RX records) because several mailboxes share or
multiplex records — the filter list is the authority for "which IDs exist on which bus".
Biggest TX domain is exterior lighting (21 frames); doors/locks are a **single** TX frame — which is
why `rke-lock` is a one-byte injection rather than a state-machine patch.

Diagnostic identity (VBF headers): `ecu_address = 0x726`, `network = CAN_HS`,
`frame_format = CAN_STANDARD`. Diagnostic IDs in the tables: `0x72E`, `0x7CC`, `0x7CE`.

---

## 3. Frame maps — RX and TX, per byte (a)

Both ends of the codec are decoded from the consuming code, so **every frame's bytes have absolute
addresses**. Machine-readable: `work/owner/rx_frame_map.json` / `tx_frame_map.json`
(**279 RX frames, 15 HS TX, 43 MS TX**). Index: `owner_artifacts.md`.

### 3.1 RX record (stride `0x1C`), read out of `VOL_rx_copy_to_image` (a)

| Offset | Meaning |
|---|---|
| `+0x00` | destination frame-image base (packed) |
| `+0x04` | second buffer (previous value, for the change compare) |
| `+0x08` | **RX-arrival flag byte** |
| `+0x0C` | gate byte pointer (software-triggered mode) |
| `+0x14` | mode: 0 = hardware mailbox |
| `+0x15` | compare-before-copy enable |
| `+0x16` | this frame's **bit** in the arrival-flag byte |
| `+0x18` | expected DLC (checked against `CS & 0xF`) |
| `+0x19` | **mailbox index** → CAN ID via the filter list (§2) |
| `+0x1A` | **byte-present copymask** |

**⚠ The copy compacts** — the destination pointer advances only for set mask bits:

```c
for (m = copymask; m; m >>= 1) { if (m & 1) *dst++ = *src; src++; }
```

⇒ **CAN byte `k` lives at `image_base + popcount(copymask & ((1<<k)-1))`, and only if bit `k` is
set.** The copy is verbatim per byte (no bit repack), so the RAM image preserves the wire layout.

After a successful copy: `*(u8*)rec[0x08] |= rec[0x16]` — the **arrival-flag** bytes
(`0x400001A0..A7` HS, `0x400004FC..FF` MS). Each byte carries "frame received" bits for up to eight
frames; 7 of 8 HS bytes carry exactly 8 frames with a distinct bit each (e.g. `0x400001A2` =
`0x060`:b0 … `0x0C0`:b5 … `0x130`:b7). These are the concrete hook points for any future
"react when frame X arrives" work.

**Validation (level 5):** both addresses the on-vehicle-proven `acc-fix` depends on fall straight
out of the formula, matching the original hand-traced derivation:

| Signal | MB | copymask | image base | offset | address |
|---|---|---|---|---|---|
| `0x0C0` d0 (PCM cruise status) | 30 | `0x13` | `0x40000707` | 0 | **`0x40000707`** ✓ |
| `0x060` d6 (stored set-speed) | 22 | `0xFE` | `0x40000700` | 5 | **`0x40000705`** ✓ |

### 3.2 TX side (a)

The TX descriptor array (`T+0x04`) carries the same shape: present-mask + frame-image base. For
`0x030` (array `0x0014AA0C`, MB0): present mask `0xFF`, image base **`0x40000760`** — so the
assembled TX frame image already holds d0..d7 contiguously, one stage **before** the mailbox
(d1 `0x40000761`, d5 `0x40000765`, d6 `0x40000766`). No other TX record's window overlaps those
8 bytes. MS-CAN: `T` `0x146180`, TX array `0x00151A68` (43 records), RX array `0x00152088`.

Codec code (a): RX copier `FUN_000fc63e`, TX packers `FUN_000fc218` (single frame) /
`FUN_000fc2f6` (periodic walker), bring-up `FUN_000fbc48`, hardware init `FUN_000fceb8`.

---

## 4. Signal-routing records — `0x00140000 … ~0x0015BF00` (b)

The dense core of the map. Records are **28 bytes (`0x1C`)**, anchored on a marker word of the form
`0x08_mmmm_00`. Layout relative to the marker:

| Offset | Meaning |
|---|---|
| `−4` | attributes |
| `0` | marker |
| `+4` | **signal cell** (signal-RAM pointer) |
| `+8` | optional second signal |
| `+12` | **frame object** |
| `+16` | optional |
| `+20` | zero |

94 signal cells across 14 frame objects, grouping cleanly by net (`0x400001A0..A7` HS,
`0x400004FC..500` MS, `0x40000588` MSX). Two columns are SRAM pointers in **298 of 298** records —
the alignment test that the old 20-byte parse fails (§7.3).

Signals live in RAM `0x40000600 – 0x40000D2F`. **Null placeholder:** `0x40000614` appears in >100
unrelated records — a Volcano default/unused sink; exclude it from every routing conclusion.

**Open:** the per-signal bit binding (`start_bit, length, byte_order, scaling`). Three models have
been refuted; the geometry is solved, the binding is not (`owner_flash_layers.md` §16.1).

---

## 5. Signal-descriptor table — `0x0015A920+` (b)

Independent **24-byte** table giving a signal's byte/bit position:

| Offset | Meaning |
|---|---|
| `+0x00` | mask |
| `+0x04` | signal-RAM address |
| `+0x08` | frameObj |
| `+0x0C` | handler/selector |
| `+0x10` | 0 |
| `+0x14` | `(byteIndex << 8) \| bitmask` |

Proven positions (MSX frame, frameObj `0x400005A8`): `0x40000B58` = byte 0 mask `0x01`;
`0x40000B7B` = byte 3 mask `0x08`; `0x40000B46` = byte 5 mask `0x08`; `0x40000B72` = byte 8 mask
`0x40`. This table is the ground truth for cracking the pack-spec format (§4 open item).

---

## 6. Cross-bus routing — what is actually proven

A translation = **a signal-RAM cell written by an RX-side record and read by a TX-side record on
another bus**. That is the only admissible evidence.

**Proven link (b): HS-CAN `0x0C0` → MS-CAN `0x020`**, via 7 shared signal-RAM cells:

| # | shared cell | written by HS records @flash | read by MS record @flash |
|---|---|---|---|
| 1 | `0x40000751` | `0x141170, 0x141198, 0x14142C, 0x141440, 0x141454` | `0x148BC4` |
| 2 | `0x40000774` | `0x140F7C, 0x141364` | `0x149604` |
| 3 | `0x4000077B` | `0x14110C, 0x141134, 0x141148, 0x14115C, 0x1414A4, 0x1415F8` | `0x147684, 0x1481E4, 0x1495C4` |
| 4 | `0x4000078A` | `0x140FCC, 0x140FF4, 0x141008` | `0x149184` |
| 5 | `0x4000078D` | `0x140FE0, 0x141238, 0x14124C` | `0x147424` |
| 6 | `0x4000079F` | `0x1412C4, 0x1414CC` | `0x148C24` |
| 7 | `0x400007A1` | `0x14138C` | `0x148C44` |

HS frameObj `0x400001C0` ↔ MS frameObj `0x400004FC`. This answers the `0x0C0` half of the project's
original task. **The `0x060` path is not mapped** (its records were never isolated — the filter that
was supposed to find them rested on the disproven `spec1 = id<<18` reading, §7.4).

Everything else is **consumed-only or independently produced**. Do not infer a forward from an ID
number appearing on both buses (§7.1).

---

## 7. Retracted readings — do not reintroduce

1. **"Same CAN-ID RX on one bus + TX on the other = forwarding" — FALSE.** Acceptance-filter
   coincidence. No shared signal-RAM exists between the HS-receive and MS-transmit paths for these
   IDs; the BCM independently consumes the incoming frame and independently builds its own
   same-numbered frame (user-confirmed for `0x040`). Affected IDs previously listed as "bridges":
   `0x020 0x040 0x060 0x070 0x080 0x1A8 0x1B0 0x1C0 0x1E0 0x250 0x270 0x280` (HS-RX/MS-TX),
   `0x030 0x150` (MS-RX/HS-TX).
2. **"`ctrlDesc+0x44` points at the RX descriptor table" — FALSE.** The controller descriptor hangs
   off net record `+0x08`, not `+0x04`; `+0x44` is a field of the per-net **RAM** state block `S`,
   and the array anchor is built at bring-up (§1.2). Disproof: CAN_0's `+0x44` landed at record 36
   of 361, CAN_2's inside PBL code space, CAN_1's was `0` although MS-CAN demonstrably transmits.
3. **"Routing records are 20 bytes" — FALSE, they are 28.** The 20-byte parse is misaligned: it
   yields `spec2` bytes 2–3 zero in *all* 447 records and a flat column profile. The 28-byte stride
   makes columns specialise (298/298 SRAM pointers). All `spec1`/`spec2` field semantics derived
   from the 20-byte reading are therefore shifted and **unproven**.
4. **"`spec1` = `CAN_id << 18`" — FALSE.** `(spec1>>18)` matches the bus ID list 23.8 % of the time
   = chance (`work/gw_test_spec1.py`). CAN IDs come from §2/§3 only, never from routing records.
5. **"frameObj numeric range identifies the bus" — FALSE.** Ranges are not bus-exclusive.
   `0x400004FC..FF`, once labelled "MS", is the **MS-CAN RX arrival-flag page** (§3.1) — an address,
   not a frame object. The reliable per-net discriminator is the arrival-flag page (§1.2).
6. **"MS-CAN is TX-only" — FALSE.** 63 configured mailboxes, 14 RX / 49 TX in the filter list
   (30 RX + 43 TX runtime records). The claim rested on retraction 2.
7. **"`0x40006400–0x400064FF` is a CAN TX change-flag bus" — FALSE.** It is the per-signal
   validity / error-substitution layer; no CAN code reads it.
8. **"The mailbox is the only place a frame's 8 bytes are contiguous" — TOO STRONG.** The assembled
   TX frame image holds d0..d7 adjacently one stage earlier (§3.2).
9. **"frameObj membership tables carry a usable bus column" — FALSE.** The bus labels in the old
   membership dump came from a first-seen heuristic on the frameObj range (retraction 5). Only the
   record/signal counts from `work/gw_membership.py` are trustworthy.

Full evidence for each: `owner_flash_layers.md` §26.

---

## 8. Open items

1. **The unpack stage** — packed RX images (`0x40000600…`) and the app signal planes
   (`0x40001E00`/`0x40002800`/`0x40003C00`) are disjoint memory, and **zero** app functions touch
   image bytes by absolute address. Static scanning is proven ineffective; use bench instrumentation
   or trace from an arrival-flag byte (§3.1).
2. **Pack-spec decode** into `(start_bit, length, byte_order, scaling)`, using §5 as ground truth
   and the codec bit-loops as reference. Read the refuted models first (`owner_flash_layers.md` §16.1).
3. **Which paired control block is live** per bus (§1.2) — required before any record-level patch.
4. **Real forwarding map** — intersect shared signal-RAM between RX-path and TX-path frameObjs per
   ID (extend `work/gw_shared.py`) and confirm/deny each same-ID pair.
5. **MSX control block** — its 23 RX records are scattered, not arrayed.
6. **Frame periods / TX cycle times** (0x90-stride records near `0x146060`); signal defaults and
   timeout-substitution values (F124 @`0xC000`).

---

## 9. Re-parsing recipe

```bash
cd /home/gl/Projects/ford/BCM/Research
python3 work/gw_mbfull.py       # MB filter lists  -> every CAN ID + direction (§2.1)
python3 work/gw_nettbl.py       # master net table -> controllers + code pointers (§1)
python3 work/gw_shared.py       # shared signal-RAM HS<->MS -> route candidates (§6)
python3 work/gw_rxdesc.py       # reception descriptors (§3.1)
python3 work/gw_membership.py   # frameObj groups — counts only, ignore the bus column (§7.9)
. .venv/bin/activate            # pyghidra (single writer, read-only opens)
python3 work/gw_dec.py 0xfc63e 0xfc218 0xfc2f6   # RX copier / TX packers
# owner project: regenerate the frame maps
python3 work/owner/80_rx_record_decode.py && python3 work/owner/83_annotate_l13_rxmap.py
```

⚠ `work/gw_aligned.py` still emits the **20-byte** parse (`aligned_records.txt`) — kept only for
historical comparison; see §7.3 before using its output for anything.
