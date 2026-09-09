# Ford BCM (C1MCA) — CAN Gateway Map: On-Flash Format Specification

Reference document describing **where the gateway routing map lives** in the BCM firmware and
**how the tables are structured**, so the map can be re-parsed / extended later.

- **MCU:** SPC560B64L7 (MPC5607B family), PowerPC e200z0h, **big-endian**, VLE. Flash base `0x0`.
- **Merged image:** `work/flash_merged.bin` (base 0x0, 0xFF-filled gaps).
- **Gateway map source:** Calibration CONFIG block **F10A** (`JV6T-14C403-AB.VBF`), a
  *Volcano5.6x*-generated CAN network database loaded at flash **0x00140000**.
- **Ghidra project:** `ghidra_proj/BCM_C1MCA`, program `flash_merged.bin`, lang
  `PowerPC:BE:64:VLE-32addr`, entry `0x0010F4A0` (VLE context bit must be set on code).

> Confidence tags: **(a)** proven via decompiled code · **(b)** proven via validated
> descriptor-table structure · **(c)** inferred / not yet fully decoded.

---

## 0. Where everything lives (address map of the gateway data)

| Region (flash) | Content | Confidence |
|----------------|---------|------------|
| `0x00140000 – ~0x0015BF00` | **Signal-routing record array** — the core gateway map (§3) | (b) |
| `0x000178B0 –  0x00017B??` | **Master network table** — one 0x5C-byte record per CAN network, binds controllers + codec code ptrs (§1) | (a)+(b) |
| `0x001464E0` | Controller descriptor — **net0 = HS-CAN 500k** (FlexCAN base 0xFFFC0000) | (a)+(b) |
| `0x00146900` | Controller descriptor — **net5 = MS-CAN 125k** (FlexCAN base 0xFFFC4000) | (a)+(b) |
| `0x00146C50` | Controller descriptor — **net6 = MSX-CAN 125k** (FlexCAN base 0xFFFC8000; L/R obstacle modules) | (a)+(b) |
| `0x00146530+` / `0x00146950+` / `0x00146CA0+` | **FlexCAN MB acceptance/ID filter lists** (12-byte records) per controller (§2) | (b) |
| `0x0015A920+` | **24-byte signal-descriptor table** (bit-position "Rosetta stone", §4) | (b) |
| `0x0001B35C` | 28-byte frame-descriptor table for one **low-speed** net (model for RX descriptors) | (a) |
| SRAM `0x40000000+` | Runtime frame-image + signal-value buffers referenced by the map (§3, `sigA/sigB`, `frameObj`) | (b) |

Codec code (in the main application, **not** in F10A), bound via the net table's code pointers:

| Function | Role | Confidence |
|----------|------|------------|
| `FUN_000fc63e` | **RX**: FlexCAN MB → frame-image copier (walks 28-byte reception descriptors at `ctrlDesc+0x44`) | (a) |
| `FUN_000fc218` / `FUN_000fc2f6` | **TX**: frame-image → FlexCAN MB packer (sets CODE 0xC40, applies byte masks) | (a) |
| `FUN_000fbc48` | network bring-up / image reset / defaults | (a) |
| `FUN_0004471a` | top-level net-table walker → calls `FUN_000fbc48(&PTR_00140000)` | (a) |

> **Note:** pointers seen *inside* F10A that look like code (`0x00144B10`, `0x00144DD0`, …) are
> **data**, not functions — they decompile to garbage/`halt_baddata`. Real codec code is only the
> `0x000FCxxx` / `0x000FDxxx` main-app functions. (a)

---

## 1. Master network table — `0x000178B0`  (b)

Array of fixed-size **0x5C-byte** records, one per CAN network. Confirmed fields:

| Offset | Type | Meaning |
|--------|------|---------|
| `+0x00` | u32 (RAM ptr) | base of this net's **frameObj** control-block region in SRAM |
| `+0x04` | u32 (flash ptr) | → **controller descriptor** (§1.1) |
| `+0x08 … +0x48` | u32 flash ptrs | codec/handler function pointers (e.g. `0x000FC218`, `0x000FC2F6`, `0x000FC63E`, …) |
| `+0x58` | u32 ptr | MB-status / auxiliary pointer array |

Known records:

| Net | net-record @ | frameObj base (+0x00) | ctrl desc (+0x04) | Bus |
|-----|--------------|-----------------------|-------------------|-----|
| net0 | `0x178B0` | `0x400001A0`-ish | `0x1464E0` | **HS-CAN 500k** |
| net5 | `0x17A7C` | `0x400004FC`-ish | `0x146900` | **MS-CAN 125k** |
| net6 | `0x17AD8` | `0x40000588`-ish | `0x146C50` | **MSX-CAN 125k** |

(nets 1–4: ctrl descs `0x146830/0x146864/0x146898/0x1468CC` — additional/virtual, off the primary path.)

### 1.1 Controller descriptor record  (a)+(b)

| Offset | Type | Meaning |
|--------|------|---------|
| `+0x00` | u32 | flags (`0x03020007` / `0x03000007`) |
| `+0x04` | u32 | network index |
| `+0x10` | u32 | **FlexCAN peripheral base** (`0xFFFC0000` / `0xFFFC4000` / `0xFFFC8000`) |
| `+0x14`,`+0x18` | u32 ptrs | sub-config tables (`0x15AExx`) |
| `+0x1C` | u32 | `0xFFF48000` (SIU/other periph) |
| `+0x20` | u32 (RAM ptr) | controller runtime state block (`0x40000618/638/658`) |
| `+0x30` | u32 | **FlexCAN CTRL register value** (baud — see below) |
| `+0x44` | u32 ptr | → **RX reception-descriptor table** (28-byte records; consumed by `FUN_000fc63e`) — *not yet fully parsed for CAN0* (c) |
| `+0x??`  | — | followed by the 12-byte MB filter list (§2) |

**Baud from CTRL (`+0x30`)** — decode bit-fields, TQ = 1+(PROPSEG+1)+(PSEG1+1)+(PSEG2+1),
`baud = f_can / ((PRESDIV+1)·TQ)`, with **f_can = 30 MHz**:

| Value | PRESDIV | TQ | Baud | Bus |
|-------|---------|----|------|-----|
| `0x05492004` | 5 | 10 | **500 kbps** | HS-CAN |
| `0x17DB2000` | 23 | 10 | **125 kbps** | MS-CAN / MSX-CAN |

---

## 2. FlexCAN MB acceptance / ID filter list  (b)

Immediately after each controller descriptor: array of **12-byte** records.

| Offset | Type | Meaning |
|--------|------|---------|
| `+0x00` | u32 | **`CAN_id << 18`** (standard-ID position, bits 28:18) |
| `+0x04` | u32 | flags — high byte **`0x08` = TX group**, **`0x04` = RX group** |
| `+0x08` | u32 | acceptance mask (`0xFFFFFFFF` = exact match) |

This defines *which message buffers each controller opens* (acceptance filtering). It is **not**
the signal routing. Located target frames:

| Bus | list @ | 0x020 | 0x060 | 0x0C0 |
|-----|--------|-------|-------|-------|
| HS-CAN (RX group `0x04……`) | `0x146530` | `0x146608` | `0x146638` | `0x146698` |
| MS-CAN (TX group `0x08……`) | `0x146950` | `0x146950` | `0x146974` | — |
| MSX-CAN | `0x146CA0` | *(only 0x1xx/0x3xx/0x7xx obstacle IDs)* | — | — |

⇒ **HS-CAN receives 0x0C0 & 0x060; MS-CAN transmits 0x020.** MSX-CAN does **not** carry
0x020/0x060/0x0C0. (b)

---

## 3. Signal-routing record array — `0x00140000 … ~0x0015BF00`  ★ the gateway map ★

The dense core of the gateway. Records are **20 bytes**, five big-endian u32 words. Parsed cleanly
as 1229 aligned records (`work/aligned_records.txt`, script `gw_aligned.py`).

| Offset | Name | Type | Meaning | Confidence |
|--------|------|------|---------|------------|
| `+0x00` | **frameObj** | u32 RAM ptr | frame / PDU / signal-group control block in SRAM. Its value's high bytes identify the **bus** (0x400001xx=HS, 0x400004/05xx=MS, 0x400005xx=MSX). This is the frame identity within the map. | (b) |
| `+0x04` | **spec1** | u32 | **bit-packing / conversion spec** — encodes bit position, length, and (likely) default/scale/type. **NOT the CAN ID.** See caveat below. | (c) |
| `+0x08` | **spec2** | u32 | packing spec cont'd. **High byte = bitmask** within the target byte (validated against §4). Remaining nibbles encode byte-index / bit-length / direction. Low half-word always `0x0000`. | (b) high byte / (c) rest |
| `+0x0C` | **sigA** | u32 RAM ptr | **source** signal-value address (`0x40000600…0x40000E00`) | (b) |
| `+0x10` | **sigB** | u32 RAM ptr | **destination** signal-value address (often == sigA for a plain store) | (b) |

Example (`0x141150`): `frameObj=0x400001C0  spec1=0x03000000  spec2=0x08B20000  sigA=sigB=0x4000077B`.

### ⚠ Important caveat on `spec1` (retracted hypothesis — now disproven)

An earlier working hypothesis read `spec1 == CAN_id << 18`. **This is disproven by measurement:**
testing `(spec1>>18)&0x7FF` against the bus's own acceptance-filter ID list over all 1229 routing
records gives only **23.8% hits (221/928)** — i.e. chance-level coincidence, not a real encoding
(`work/gw_test_spec1.py`). Real `spec1` values are packing/conversion attributes, e.g.
`0x10048001, 0x80070220, 0x03000440, 0xFF000008, 0x1C022010, 0x3F000002`. This is also why an
"ID = spec1>>18" filter found **zero** records for 0x060 (`0x0180`) and 0x020 (`0x0080`).
The authoritative CAN-ID source is the **acceptance-filter list (§2)** and the **reception-descriptor
chain**: HS reception descriptors at `ctrlDesc(0x1464E0)+0x44 → 0x18000` are 32-byte records
`[..][..][MB-bit][handler→routing-record ptr 0x14xxxx][..][..][frame-image RAM ptr 0x40007Axx][..]`,
linking each MB (hence CAN ID) to its frame image and routing records. **The CAN ID of a routed signal must be
taken from the frame it belongs to (via the frameObj → reception/transmission descriptor →
MB-id chain, §1.1 `+0x44`), not from spec1.** Fully decoding `spec1`/`spec2` into
`(start_bit, length, byte_order, scaling)` is an open task.

### How a gateway translation is expressed

Volcano gateways route by **shared signal-RAM**, not by copying whole frames:

```
RX frame image  --(unpack record: sigA=frame byte/bit → sigB=signal RAM)-->  signal RAM addr X
signal RAM addr X  --(pack record: sigA=signal RAM X → sigB=TX frame byte/bit)-->  TX frame image
```

So a **translation** = a signal-RAM address that is written by an RX-side record (frameObj on one
bus) and read by a TX-side record (frameObj on another bus). Enumerating records that share a
`sigA`/`sigB` address between an HS frameObj and an MS frameObj yields the gateway links (§ current map).

> **Null-signal caveat:** `0x40000614` appears "shared" across nearly all frameObj pairs — it is a
> Volcano default/placeholder sink, **not** a real translation. Ignore any link whose only shared
> address is `0x40000614`. (b)

---

## 4. Signal-descriptor table (bit-position Rosetta) — `0x0015A920+`  (b)

Independent **24-byte** table used to validate the `spec2` bitmask semantics. Per record:

| Offset | Meaning |
|--------|---------|
| `+0x00` | mask |
| `+0x04` | signal-RAM addr |
| `+0x08` | frameObj |
| `+0x0C` | handler/selector |
| `+0x10` | 0 |
| `+0x14` | `(byteIndex << 8) | bitmask` |

Proven bit positions (MSX frame, frameObj `0x400005A8`) — used only to crack the packspec format:

| sigRAM | byte | bitmask | desc @ |
|--------|------|---------|--------|
| `0x40000B58` | 0 | `0x01` | `0x15A920` |
| `0x40000B7B` | 3 | `0x08` | `0x15A980` |
| `0x40000B46` | 5 | `0x08` | `0x15A9E0` |
| `0x40000B72` | 8 | `0x40` | `0x15AA40` |

These confirm **spec2 high byte = bitmask** in the §3 routing records.

---

## 5. Re-parsing recipe

```bash
cd /home/gl/Projects/ford/BCM/Research/work
python3 gw_nettbl.py     # master net table @0x178B0  -> controllers + code ptrs
python3 gw_mblist.py     # 12-byte MB filter lists     -> CAN IDs per controller
python3 gw_aligned.py    # 20-byte routing records     -> aligned_records.txt (the map)
python3 gw_shared.py     # sigRAM shared HS<->MS        -> gateway link candidates
# pyghidra (needs: . ../.venv/bin/activate ; GHIDRA_INSTALL_DIR=/opt/ghidra ; single-writer):
python3 gw_dec.py 0xfc63e 0xfc218 0xfc2f6   # decompile the RX copier / TX packer
```

Open items to finish the format spec: (1) decode `spec1`/`spec2` fully into
`(start_bit,length,byte_order,scale)`; (2) parse the CAN0 RX reception-descriptor table at
`ctrlDesc(0x1464E0)+0x44` to bind frameObj ↔ MB-id ↔ frame-image authoritatively.
