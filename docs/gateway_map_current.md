# Ford BCM (C1MCA) — CAN Gateway Map (current, human-readable)

**Status: WORK IN PROGRESS / checkpoint.** This is what has been *proven* from the firmware so far,
in plain terms. Companion to `gateway_map_format.md` (which explains the on-flash table layout).
Every claim cites a flash/code address. Confidence: **(a)** decompiled code · **(b)** validated
table structure · **(c)** inferred / unproven.

---

## The buses

| Bus | FlexCAN | Speed | Role | Ctrl desc @ |
|-----|---------|-------|------|-------------|
| **HS-CAN** | CAN_0 @ `0xFFFC0000` | 500 kbps | Main high-speed bus — **receives 0x0C0, 0x060** | `0x1464E0` (b) |
| **MS-CAN** | CAN_1 @ `0xFFFC4000` | 125 kbps | Mid-speed body bus — **transmits 0x020** | `0x146900` (b) |
| **MSX-CAN** | CAN_2 @ `0xFFFC8000` | 125 kbps | Parking-assist: left/right side **obstacle modules** (IDs 0x1xx/0x3xx/0x7xx) | `0x146C50` (b) |

The BCM is a **table-driven Volcano gateway**: no CAN IDs or bus addresses are hard-coded in
program logic (verified — zero `e_lis 0xFFFC` immediates). All routing lives in the F10A
calibration tables and is executed by generic codec code (RX copier `FUN_000fc63e`, TX packer
`FUN_000fc218`/`FUN_000fc2f6`). (a)

---

## How translation works here (important)

This gateway does **not** copy whole frames. It routes **individual signals through shared
signal-RAM**:

```
   HS-CAN 0x0C0 frame  ──unpack──▶  signal-RAM cell  ──pack──▶  MS-CAN frame
   (received bytes)     (RX record)   0x400007xx      (TX record)  (transmitted bytes)
```

A "translation" therefore = one signal-RAM address that is **written while unpacking an HS frame**
and **read while packing an MS frame**. Find those shared cells → you have the map.

---

## Confirmed gateway link (the headline result) — (b)

**HS-CAN 0x0C0 signal block → an MS-CAN frame, via 7 shared signal-RAM cells.**

HS records live under frame object `0x400001C0`; the MS side is frame object `0x400004FC`.
The seven genuinely-shared signals (excluding the `0x40000614` null placeholder):

| # | shared signal-RAM | written by HS record(s) @flash | read by MS record @flash |
|---|-------------------|-------------------------------|--------------------------|
| 1 | `0x40000751` | `0x141170, 0x141198, 0x14142C, 0x141440, 0x141454` | `0x148BC4` |
| 2 | `0x40000774` | `0x140F7C, 0x141364` | `0x149604` |
| 3 | `0x4000077B` | `0x14110C, 0x141134, 0x141148, 0x14115C, 0x1414A4, 0x1415F8` | `0x147684, 0x1481E4, 0x1495C4` |
| 4 | `0x4000078A` | `0x140FCC, 0x140FF4, 0x141008` | `0x149184` |
| 5 | `0x4000078D` | `0x140FE0, 0x141238, 0x14124C` | `0x147424` |
| 6 | `0x4000079F` | `0x1412C4, 0x1414CC` | `0x148C24` |
| 7 | `0x400007A1` | `0x14138C` | `0x148C44` |

The HS side of these is confirmed part of the **0x0C0** signal set: 17 HS routing records
carry the `0x0C0` frame and unpack into exactly this `0x40000751 / 0x4000077x / 0x4000079x`
neighbourhood (e.g. record @`0x141150`: frameObj `0x400001C0`, sigA=sigB=`0x4000077B`). (b)

> **Caveat (honest):** that the destination MS frame is **0x020 specifically** is *not yet
> proven* — the MS records above are confirmed to be MS-CAN frame objects, but the 0x020 frame's
> own records have not been isolated yet (see "Not yet resolved"). The RX-0x0C0-signal → MS-CAN
> flow itself **is** proven.

---

## RX HS-CAN 0x0C0 — signal-RAM cells it populates — (b)

From the routing records whose HS frame = 0x0C0 (`work/aligned_records.txt`,
`gw_targets.py`). The 0x0C0 frame unpacks into signal-RAM including:

`0x40000688, 0x400006AC, 0x4000074A, 0x40000751, 0x4000077B, 0x4000077C, 0x4000077E,
0x40000797, 0x40000799, 0x4000079F, 0x400007A1` …

Representative records (`@flash  frameObj  spec1  spec2  sigA→sigB`):

```
@141150  400001C0  03000000  08B20000   4000077B → 4000077B
@141128  400001C0  03000200  08720000   4000077E → 4000077B
@1411A0  400001C0  03000000  80B20000   40000797 → 40000799
@141498  400001C0  03000000  01F10000   4000077B → 4000077C
@141170  400001C0  ........  ........   40000751 → 40000751
```

`spec2` high byte = the bit mask within the target byte (e.g. `0x08`, `0x80`, `0x01`, `0x02`).
The full byte-offset + bit-length decode of `spec1`/`spec2` is still in progress, so exact
`byte.bit` positions are **not published yet** to avoid guessing.

---

## Bit-position decoding status

- **Proven bitmasks (spec2 high byte)** cross-validated against the 24-byte descriptor table at
  `0x15A920+` (e.g. `0x40000B72` = byte 8 / mask `0x40`). (b)
- **Not yet decoded:** the mapping of `spec1`/`spec2`'s remaining nibbles into
  `(start_bit, bit_length, byte_order, scaling)`. Until that's done, no complete
  "HS 0x0C0 byte.bit → MS 0x020 byte.bit" row is asserted. (c)

---

## Not yet resolved (what a resume must finish)

1. **Isolate the 0x060 and 0x020 records.** An "ID = spec1>>18" filter returned **zero** hits for
   0x060/0x020 — because `spec1` is a packing spec, **not** the CAN ID (corrected; see format doc).
   The ID must come from the frameObj → reception/transmission descriptor → MB-id chain
   (`ctrlDesc 0x1464E0 +0x44`), which is not yet parsed for CAN0. (c)
2. **Confirm the 7 shared signals really pack into 0x020** (vs another MS frame) by decompiling the
   MS-CAN (net5) periodic TX packer and checking the 0x020 frame image. (c)
3. **Map the 0x060 path** identically to 0x0C0 once its records are located. (c)
4. **Finish spec1/spec2 → (start_bit, length, scale) decode** to produce the final bit-level table. (c)

---

## One-line summary

HS-CAN **0x0C0** signal data provably flows through **7 shared signal-RAM cells**
(`0x40000751/774/77B/78A/78D/79F/7A1`) into the **MS-CAN** transmit side (frame object
`0x400004FC`); confirming the destination is exactly frame **0x020** and producing the
byte/bit-level field mapping is the remaining work. The **0x060 path is not yet mapped.**

*Source of truth: `work/aligned_records.txt`, `work/gateway_translation_report.md` (full checkpoint),
and the Ghidra project `ghidra_proj/BCM_C1MCA`.*
