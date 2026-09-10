# Ford BCM (C1MCA) — Volcano CAN Calibration Files: Extensive Documentation

Reverse-engineering reference for the **Volcano-generated CAN network database** embedded in the
Ford BCM (Body Control Module) firmware on the C1MCA platform. Covers what the calibration files
are, how their tables are laid out, the full CAN-ID inventory with routing, and signal-to-frame
membership.

- **MCU:** SPC560B64L7 (MPC5607B family), PowerPC e200z0h, **big-endian**, VLE. Flash base `0x0`.
- **Merged analysis image:** `work/flash_merged.bin`. Ghidra project `ghidra_proj/BCM_C1MCA`.
- **Companion docs:** `gateway_map_format.md` (raw table byte-layouts),
  `gateway_id_interaction_map.md` (HS↔MS ID interaction), `gateway_map_current.md` (signal notes).

> Confidence tags: **(a)** proven via decompiled code · **(b)** proven via validated table
> structure · **(c)** inferred / not fully decoded.

---

## 1. What these files are

The BCM firmware ships as three VBF containers:

| VBF file | Volcano part type | Load addr | Role |
|----------|-------------------|-----------|------|
| `JV6T-14C094-AD.VBF` | Application (EXE) | 0x10000 | Main firmware + generic CAN driver/codec |
| `JV6T-14C403-AB.VBF` | **Calibration Config (F10A)** | **0x140000** | **The Volcano CAN network database** (this doc) |
| `JV6T-14C095-AB.VBF` | **Calibration Data (F124)** | **0x0C000** | Signal defaults / local configuration data |

**Volcano** (Mentor/Volcano VCT, used across Volvo and Ford) is a **signal-oriented** network
design tool. The ECU application is *generic and network-agnostic*; all CAN behavior — which frames
exist, on which bus, at what ID and timing, and which signals they carry — is **compiled into the
F10A calibration block as data tables** and interpreted at runtime. The F10A header confirms:
*"Generated with Volcano5.6x release 6bp_1_6."*

**Proof it is fully table-driven (a):** no CAN ID and no FlexCAN base address appears as a code
immediate anywhere in the application (verified: zero `e_lis 0xFFFC` hits; the target IDs
0x0C0/0x060/0x020 never occur as instruction operands). The application simply walks the tables via
`FUN_0004471a → FUN_000fbc48(&PTR_00140000)`.

### 1.1 Diagnostic identity (from VBF headers)
- `ecu_address = 0x726` (BCM diagnostic address; VBF headers)
- `network = CAN_HS`, `frame_format = CAN_STANDARD` (11-bit IDs)
- Diagnostic CAN IDs visible in the MB tables: **0x72E** (functional/response), **0x7CC / 0x7CE**
  (TX on MS-CAN — likely diag/gateway responses).

---

## 2. Architecture: layers of the Volcano config

The config is a stack of cross-referencing tables. From hardware up to signals:

```
 [1] Master network table  (0x178B0)         one record per CAN network
        │  +0x04 → controller descriptor
        ▼
 [2] Controller descriptors (0x1464E0 …)      FlexCAN base, bit-timing/baud, RX-desc ptr
        │  MB filter list follows
        ▼
 [3] MB acceptance/ID filter lists (0x146530…) every CAN ID + direction (RX/TX) + mask
        │  +0x44 → reception descriptor table
        ▼
 [4] Reception descriptors (0x18000)          MB → frame-image RAM → routing-record handler
        │
        ▼
 [5] Signal-routing records (0x140000…0x15BF00) frameObj + pack-spec + src/dst signal-RAM
        │
        ▼
 [6] Signal descriptors / defaults (0x15A920, F124@0xC000)  bit positions, init/invalid values
```

### 2.1 FlexCAN controllers (b)+(a)

| Net | Ctrl desc @ | FlexCAN base | CTRL reg (+0x30) | Baud | Bus role |
|-----|-------------|--------------|------------------|------|----------|
| net0 | 0x1464E0 | 0xFFFC0000 | 0x05492004 | **500 kbps** | **HS-CAN** (main high-speed) |
| net5 | 0x146900 | 0xFFFC4000 | 0x17DB2000 | **125 kbps** | **MS-CAN** (mid-speed body) |
| net6 | 0x146C50 | 0xFFFC8000 | 0x17DB2000 | **125 kbps** | **MSX-CAN** (L/R side obstacle / parking-assist modules) |

Nets 1–4 (ctrl descs 0x146830/0x146864/0x146898/0x1468CC) are additional/virtual networks (LIN or
internal signal groups) — they appear in the routing table as frameObj groups `n1..n4` (§5) but are
off the primary HS↔MS gateway path.

Baud decodes from CTRL bit-fields with CAN clock = 30 MHz:
`TQ = 1+(PROPSEG+1)+(PSEG1+1)+(PSEG2+1)`, `baud = 30 MHz / ((PRESDIV+1)·TQ)`.
`0x05492004` → PRESDIV 5, TQ 10 → 500 k. `0x17DB2000` → PRESDIV 23, TQ 10 → 125 k.

### 2.2 What each layer stores (field summary)

- **MB filter record (12 B):** `[CAN_id << 18][dir flag: 0x04=RX / 0x08=TX][acceptance mask]`.
- **Reception descriptor (32 B):** `[..][..][MB-bit][→routing-record ptr 0x14xxxx][..][..][frame-image RAM ptr 0x40007Axx][..]` — binds a hardware message buffer to its RAM frame image and its per-frame handler.
- **Signal-routing record (20 B):** `[frameObj][spec1 pack-spec][spec2 pack-spec (hi byte=bitmask)][sigA src signal-RAM][sigB dst signal-RAM]`.
  - ⚠ `spec1` is a **packing/conversion spec, NOT the CAN ID** — measured: `(spec1>>18)` matches the bus ID list only 23.8 % of the time (chance level). CAN IDs come from layer [3]/[4], not from routing records.
- **Signal descriptor (24 B, 0x15A920):** `[mask][signal-RAM][frameObj][handler][0][(byteIdx<<8)|bitmask]` — gives a signal's byte/bit position.

---

## 3. FULL CAN-ID INVENTORY (authoritative, from MB filter lists) (b)

Direction is from the BCM's perspective: **RX** = BCM listens, **TX** = BCM sends.

### 3.1 HS-CAN (net0, 500 kbps) — list @0x146530

**RX (46 IDs):**
`0x010 0x020 0x040 0x04A 0x04B 0x060 0x06A 0x070 0x080 0x090 0x0A0 0x0A5 0x0B0 0x0C0 0x0D0 0x0E0
0x0F8 0x100 0x120 0x130 0x138 0x140 0x160 0x170 0x180 0x190 0x1A0 0x1A8 0x1B0 0x1B5 0x1C0 0x1D0
0x1E0 0x1E8 0x200 0x208 0x210 0x218 0x229 0x250 0x252 0x269 0x270 0x280 0x298 0x500`

**TX (17 IDs):**
`0x030 0x0C8 0x150 0x17E 0x260 0x290 0x310 0x360 0x380 0x3B4 0x400 0x405 0x40A 0x420 0x435 0x581 0x72E`

### 3.2 MS-CAN (net5, 125 kbps) — list @0x146950

**RX (14 IDs):**
`0x010 0x030 0x090 0x0A0 0x100 0x108 0x130 0x150 0x160 0x180 0x190 0x1A0 0x1B8 0x500`

**TX (49 IDs):**
`0x020 0x03A 0x040 0x060 0x070 0x080 0x083 0x110 0x1A4 0x1A8 0x1B0 0x1B4 0x1C0 0x1E0 0x215 0x217
0x220 0x230 0x240 0x241 0x250 0x265 0x270 0x280 0x281 0x290 0x295 0x2A0 0x2A7 0x300 0x320 0x340
0x360 0x361 0x363 0x370 0x3A0 0x400 0x405 0x40A 0x415 0x435 0x440 0x501 0x581 0x690 0x72E 0x7CC 0x7CE`

### 3.3 MSX-CAN (net6, 125 kbps) — list @0x146CA0
Carries only obstacle/parking IDs (0x1xx / 0x3xx / 0x5xx / 0x7xx range), e.g.
`0x120 0x370 0x380 0x400 0x405 0x501 0x581 0x7C4 0x7C6 0x7DF …`. **No 0x020/0x060/0x0C0.**

---

## 4. WHERE EACH ID IS ROUTED (gateway forwarding)

### 4.1 Same-ID on both buses — ⚠ NOT proven to be forwarding

Many IDs appear as **RX on one bus and TX on the other** (e.g. 0x020, 0x040, 0x060, 0x070, 0x080,
0x1A8, 0x1B0, 0x1C0, 0x1E0, 0x250, 0x270, 0x280 as HS-RX/MS-TX; 0x030, 0x150 as MS-RX/HS-TX). An
earlier draft listed these as "bridges" — **that was wrong.** These pairs are only
*acceptance-filter coincidence*; there is **no shared-signal-RAM evidence** that content crosses.

**Correct interpretation:** the BCM **independently consumes** the incoming frame and
**independently produces its own, separately-built frame of the same ID number** on the other bus.
Same ID number ≠ forward. (User-confirmed example: **0x040** — HS-CAN 0x040 in and MS-CAN 0x040 out
are independent frames.) To upgrade any such pair to a real forward, shared signal-RAM must be proven
via the reception/transmission descriptor chain (§6 open item).

### 4.2 Cross-ID translation — signals repacked into a different ID

| Source | → | Target | Basis |
|--------|---|--------|-------|
| HS-CAN **0x0C0** | → | MS-CAN **0x020** | 7 shared signal-RAM cells 0x40000751/774/77B/78A/78D/79F/7A1 (b) |

> This is the **only proven cross-bus signal link** so far. A complete routing map requires the
> frameObj→CAN-ID binding via the descriptor chain (§6).

### 4.3 Consumed-only / independently-produced IDs
Most IDs are received and used internally, or produced by the BCM from its own logic (door/lock/
lighting/body status), with no proven cross-bus content link. Do not infer forwarding from ID
number alone.

---

## 5. SIGNAL ↔ FRAME MEMBERSHIP

Volcano groups signals into **frame objects** (frameObj) — RAM control blocks that own a set of
signals. The routing records (§2, layer 5) are grouped by frameObj; each record moves one signal
between a **frame image** and a **signal-RAM cell**. Signals live at RAM `0x40000600–0x40000D2F`.

### 5.1 frameObj membership table (from 1229 routing records) (b)

⚠ **Bus column is UNRELIABLE — do not trust it.** It was assigned by a first-seen heuristic on the
frameObj numeric range, which the authoritative reception-descriptor chain has since **disproven**:
frameObj ranges are *not* bus-exclusive. For example `0x400004FC/FD/FE/FF` (labelled "MS" below)
actually appear on the **HS receive path** in the reception descriptors at 0x18000. Treat the bus
labels as rough hints only; the real bus/ID of a frameObj must come from the descriptor chain
(§6 open item). The `#recs`/`#sig`/span columns are accurate (raw counts from the routing records).

`#recs` = routing operations in that group; `#sig` = distinct signal-RAM cells touched
(the 0x40000614 null-placeholder excluded); span = signal-RAM address range.

| frameObj | bus? | #recs | #sig | signal-RAM span |
|----------|-----|-------|------|-----------------|
| 0x400001A0 | HS | 10 | 14 | 0x400006B9–0x40000B90 |
| 0x400001A1 | HS | 24 | 28 | 0x40000678–0x40000BD5 |
| 0x400001A2 | HS | 15 | 24 | 0x4000067E–0x40000BDA |
| 0x400001A3 | HS | 30 | 38 | 0x4000067B–0x40000BC0 |
| 0x400001A4 | HS | 26 | 24 | 0x4000068C–0x40000BBE |
| 0x400001A5 | HS | 8 | 11 | 0x4000069E–0x40000717 |
| 0x400001A6 | HS | 11 | 11 | 0x4000067B–0x40000BBC |
| 0x400001A7 | HS | 2 | 2 | 0x4000072D–0x40000BC4 |
| **0x400001C0** | HS | **137** | **148** | 0x40000687–0x40000D28 |
| 0x400001C1 | HS | 37 | 51 | 0x400006A8–0x40000D19 |
| 0x4000022C | n1 | 52 | 21 | 0x400007D4–0x40000BE5 |
| 0x4000024C | n1 | 22 | 13 | 0x4000068E–0x40000D1D |
| 0x400002E0 | n2 | 15 | 14 | 0x40000824–0x40000BF9 |
| 0x400002E1 | n2 | 17 | 19 | 0x4000081C–0x4000084E |
| 0x40000300 | n2 | 56 | 43 | 0x40000694–0x40000CFB |
| 0x40000301 | n2 | 8 | 8 | 0x40000879–0x40000BFB |
| 0x40000394 | n3 | 4 | 4 | 0x40000889–0x40000C05 |
| 0x400003B4 | n3 | 14 | 27 | 0x400006B0–0x40000D21 |
| 0x40000448 | n4 | 44 | 23 | 0x400008A0–0x40000C29 |
| 0x40000449 | n4 | 8 | 11 | 0x400008A0–0x400008DA |
| 0x40000468 | n4 | 28 | 11 | 0x400008E3–0x400008FB |
| 0x400004FC | MS | 29 | 29 | 0x400008FF–0x40000C62 |
| 0x400004FD | MS | 43 | 42 | 0x400008FF–0x40000C6F |
| 0x400004FE | MS | 29 | 31 | 0x40000902–0x40000C4A |
| 0x400004FF | MS | 19 | 24 | 0x40000909–0x40000C70 |
| 0x40000500 | MS | 2 | 2 | 0x4000097B–0x40000983 |
| **0x4000051C** | MS | **123** | **161** | 0x4000067D–0x40000D2F |
| 0x4000051D | MS | 80 | 113 | 0x40000697–0x40000D10 |
| 0x4000051E | MS | 96 | 127 | 0x4000068B–0x40000D25 |
| 0x4000051F | MS | 122 | 155 | 0x4000067F–0x40000D2E |
| 0x40000520 | MS | 64 | 83 | 0x40000682–0x40000D27 |
| 0x40000521 | MS | 21 | 27 | 0x400006C0–0x40000CFF |
| 0x40000588 | MSX | 2 | 2 | 0x40000B2F–0x40000CA1 |
| 0x400005A8 | MSX | 31 | 48 | 0x4000068B–0x40000D2B |

### 5.2 How to read membership / gateway flow

- A **frameObj is a signal-group container**, mapped to CAN IDs via the reception/transmission
  descriptors (layer 4). It is **many-to-many** with CAN IDs: one frameObj can service several IDs,
  and one ID's signals can span several frameObjs (verified — the 0x0C0 signal set spans
  0x400001A0–A7 and 0x400001C0/C1).
- **A gateway translation** = a signal-RAM cell that is a *destination* (sigB) in an RX-bus
  frameObj record and a *source* (sigA) in a TX-bus frameObj record. Enumerating shared signal-RAM
  between an HS frameObj and an MS frameObj yields the signal-level gateway links.
- **Example (proven, b):** HS frameObj **0x400001C0** and MS frameObj **0x400004FC** share 7 real
  signal-RAM cells → the HS 0x0C0 → MS 0x020 translation of §4.2.
- **Null placeholder:** signal-RAM `0x40000614` appears in >100 unrelated records — a Volcano
  default/unused sink; **exclude it** from any membership or routing conclusion.

### 5.3 Bit positions (partial, b)
Exact byte/bit positions come from the 24-byte signal-descriptor table at `0x15A920+`
(`[mask][signal-RAM][frameObj][handler][0][(byteIdx<<8)|bitmask]`). Proven examples (MSX frame,
frameObj 0x400005A8): signal 0x40000B58 = byte 0 mask 0x01; 0x40000B7B = byte 3 mask 0x08;
0x40000B46 = byte 5 mask 0x08; 0x40000B72 = byte 8 mask 0x40. Full per-signal byte.bit + length +
scaling decode of `spec1`/`spec2` is an open task (§6).

---

## 6. What is proven vs. open

**Proven (a/b):** the three controllers + baud + bus roles; the *complete* per-bus CAN-ID inventory
with direction; the table-driven RX copier (`FUN_000fc63e`) and TX packer (`FUN_000fc218/2f6`);
frameObj membership record counts; one proven cross-bus signal link (HS 0x0C0 → MS 0x020) with
7 shared signal-RAM cells.

**Disproven / corrected:** "same-ID = forwarding" (acceptance-filter coincidence only — 0x040 is
independently consumed and independently produced); "spec1 = id<<18" (measured 23.8 % = chance);
"frameObj numeric range = bus" (ranges are not bus-exclusive; 0x400004FC is on the HS receive path).

**Open (c):**
1. **frameObj→CAN-ID binding** via the reception/transmission descriptor chain (`ctrlDesc+0x44`,
   e.g. HS @0x18000) — the key that unlocks real per-ID routing/forwarding and per-ID membership.
2. **Full `spec1`/`spec2` decode** into (start_bit, length, byte_order, scaling).
3. **Frame periods / TX cycle times** (the 0x90-stride timing records near 0x146060).
4. **Signal defaults / timeout-substitution values** (F124 block @0xC000).

Completing #1 + #2 would allow reconstructing a **full signal map** for both
buses directly from the firmware's own embedded routing tables.

---

## 7. Extraction scripts (in `work/`)

| Script | Produces |
|--------|----------|
| `gw_mbfull.py` | full MB filter lists (§3) — every CAN ID + direction |
| `gw_forward.py` | same-ID HS↔MS forwarding (§4.1) |
| `gw_membership.py` | frameObj membership groups (§5.1) |
| `gw_aligned.py` | 20-byte routing records → `aligned_records.txt` |
| `gw_shared.py` | shared signal-RAM between HS/MS frameObjs (gateway candidates) |
| `gw_test_spec1.py` | disproves the "spec1 = id<<18" hypothesis (23.8 % hit) |
| `gw_rxdesc.py` | reception-descriptor table dump (layer 4) |
| `decode_baud.py` | CTRL-register → baud |

Data files: `aligned_records.txt`, `routing_records.txt`, `sig24.txt`.
