# Ford BCM (C1MCA) CAN Gateway — Signal-Level Translation: CHECKPOINT REPORT

**Status:** PAUSED mid-investigation (checkpoint). Target: map RX HS-CAN 0x0C0 & 0x060 signal
bit-fields → TX MS-CAN 0x020 via shared signal-RAM, with cited flash/code evidence.
**Firmware:** SPC560B64L7 (MPC5607B), PowerPC e200z0h, big-endian, VLE. Flash base 0x0.
**Image:** `work/flash_merged.bin`. Ghidra project `BCM_C1MCA` / `flash_merged.bin`.

Confidence tags used throughout:
- **(a)** confirmed via decompiled control flow
- **(b)** confirmed via validated descriptor-table structure (multi-record cross-check)
- **(c)** inferred / not yet proven

---

## 1. CONFIRMED FACTS

### 1.1 Three FlexCAN controllers (controller descriptor records) — **(a)+(b)**
Master network table: 0x5C-byte records based at flash **0x0178B0**, field **+0x04 = controller-descriptor ptr**.
Walked at runtime by `FUN_0004471a` → `FUN_000fbc48(&PTR_PTR_00140000)` (decompiled). Controller records:

| Net | Ctrl desc (flash) | FlexCAN base (+0x10) | CTRL reg (+0x30) | Baud | Bus role | net-record @ |
|-----|-------------------|----------------------|------------------|------|----------|--------------|
| net0 | **0x1464E0** | 0xFFFC0000 | **0x05492004** | 500 kbps | **HS-CAN** (RX 0x0C0/0x060) | 0x178B0 |
| net5 | **0x146900** | 0xFFFC4000 | **0x17DB2000** | 125 kbps | **MS-CAN** (TX 0x020) | 0x17A7C |
| net6 | **0x146C50** | 0xFFFC8000 | **0x17DB2000** | 125 kbps | **MSX-CAN** (parking-assist: L/R obstacle modules) | 0x17AD8 |

nets 1–4 (ctrl descs 0x146830/0x146864/0x146898/0x1468CC) are additional/virtual networks (LIN or
internal); not on the primary path. Baud math resolves exactly at 30 MHz CAN clock. **(b)** for CTRL
values (raw bytes at ctrl+0x30); **(a)** for the walker binding these records.

### 1.2 Per-controller FlexCAN MB filter/ID lists — **(b)**
12-byte records `[id<<18][flags][mask]` immediately after each controller descriptor. Flag high-byte
0x08 vs 0x04 splits two groups (TX-slot group vs RX group). Target frames present:

- **CAN0 / HS-CAN** (MB list @0x146530): id 0x020 @**0x146608**, id 0x060 @**0x146638**, id 0x0C0 @**0x146698** (all flags 0x04080000 — RX group).
- **CAN1 / MS-CAN** (MB list @0x146950): id 0x020 @**0x146950**, id 0x060 @**0x146974** (flags 0x08080000 — TX group).
- **CAN2 / MSX-CAN** (MB list @0x146CA0): ids 0x120,0x370,0x380,0x400,0x405,0x501,0x581,0x7C4,0x7C6,0x7DF... (no 0x020/0x060/0x0C0 among the 0x08 group). **⇒ TX 0x020 does NOT source from MSX-CAN's own 0x060/0x0C0; MSX carries obstacle IDs (0x1xx/0x3xx/0x7xx).** (b)

These are FlexCAN acceptance lists (which MBs each controller opens), NOT the signal routing.

### 1.3 20-byte signal-routing record format — **(b), format validated; field semantics partly (c)**
Records densely fill flash **0x140000 – ~0x15BF00** (the F10A "Volcano5.6x" calibration block).
Validated stride/layout by anchoring on a frameObj pointer in word0 and two signal-RAM ptrs in
words 3–4 (1229 aligned records parsed cleanly):

```
offset  field     meaning
+0x00   frameObj  ptr into a per-bus frame/PDU control-block RAM region (see §2)
+0x04   spec1     (CAN_id << 18) | flags     <-- top 11 bits = standard CAN ID
+0x08   spec2     packing spec: high byte = bitmask, plus byte-index / length / dir nibbles
+0x0C   sigA      signal-RAM source addr (0x40000600..0x40000E00)
+0x10   sigB      signal-RAM dest   addr (often == sigA for a plain store)
```
Validation evidence:
- **spec1 = id<<18** proven: every record whose frameObj ∈ HS range and `spec1>>18==0x0C0`
  has `spec1 & 0x3FFFF == 0` and `spec1>>18` = 0x0C0 (0x03000000 base). 17 such records found
  (see §3). Example @**0x141150**: `spec1=03000000` (=0x0C0<<18), sigA=sigB=0x4000077B.
- **spec2 high byte = bitmask** cross-checked against the independent 24-byte signal-descriptor
  table at **0x15A920+** (format `[mask][sigRAM][frameObj][handler][0][(byteIdx<<8)|bitmask]`),
  which lists e.g. sig 0x40000B58=byte0 mask0x01, 0x40000B7B=byte3 mask0x08, 0x40000B46=byte5
  mask0x08, 0x40000B72=byte8 mask0x40 (MSX frame, frameObj 0x400005A8).
  Matching routing records (@0x144940 region) carry the same bitmask in spec2's high byte
  (e.g. @0x1449E0 spec2=`40180600` for the mask-0x40 byte8 signal). **(b)**

### 1.4 FlexCAN RX/TX codec is fully table-driven — **(a)**
No CAN-ID or FlexCAN base appears as a code immediate (confirmed: scan for e_lis 0xFFFC found
zero code hits). Generic codec functions in the main app, bound via the net table's flash code
pointers (net record words 2–18, e.g. 0x000FC218, 0x000FC2F6, 0x000FC4D8, 0x000FC63E ...):
- **`FUN_000fc63e`** (0xFC63E) = **RX MB → frame-image copier**. Decompiled: iterates 28-byte
  reception descriptors from `ctrlDesc+0x44`, reads FlexCAN MB at `MB_base+0x80+idx*0x10`
  (idx at desc+0x19), checks CODE field `& 0xe00`, copies selected data bytes (byte-mask at
  desc+0x1a) into the frame image, sets a "received" flag. **(a)**
- **`FUN_000fc218` / `FUN_000fc2f6`** = **TX frame-image → MB packer** (writes MB words, sets
  CODE 0xC40, applies byte masks). **(a)**
- **`FUN_000fbc48`** = network bring-up/reset (zeroes images, copies defaults). **(a)**
- `FUN_0004f53a` / `FUN_0004ee6a` walk the 28-byte frame table at **0x1B35C** (one network's
  frame set: ids 0x030/0x040/0x060). **(a)** for the walk; that particular table is a LOW-speed
  net, not HS.

NOTE: the "code pointers" seen inside F10A (0x00144B10, 0x00144DD0, 0x00144AB0 ...) are **NOT
code** — they decompile to `halt_baddata()` and are actually data (bitmask lookup tables / handler
selector indices inside the calibration block). Real codec code is only the 0x000FCxxx/0x000FDxxx
main-app functions. **(a)**

---

## 2. frameObj GROUPINGS PER BUS — **(b)**
Each bus has a contiguous RAM region of frame/PDU control-block objects (the routing record's
word0). Ranges derived from net-record word0 (base) and observed record clustering:

| Bus | frameObj range | frameObjs actually seen in routing records |
|-----|----------------|--------------------------------------------|
| HS-CAN (net0) | 0x400001A0–0x400001FF | 0x400001A0,A1,A2,A3,A4,A5,A6,A7, 0x400001C0, 0x400001C1 |
| MS-CAN (net5) | 0x400004FC–0x40000554 | 0x400004FC,FD,FE,FF, 0x40000500, 0x4000051C,51D,51E,51F,520,521 |
| MSX-CAN (net6)| 0x40000588–0x400005E0 | 0x40000588, 0x400005A8 |

### 2.1 frameObj → CAN-ID binding: **NOT fully locked (c)**
CRITICAL nuance discovered right before pause: **a single frameObj carries records for MULTIPLE
CAN IDs**, and conversely one CAN ID (0x0C0) appears under many frameObjs. Example: the 17
HS records with `spec1>>18==0x0C0` are spread across frameObjs 0x400001A0,A1,A2,A3,A4,A5,C0,C1.
⇒ **The authoritative per-record CAN ID is `spec1>>18`, not the frameObj.** The frameObj is a
signal-group/PDU/mux container, not 1:1 with a CAN frame.

Consequently the earlier hypothesis "0x400001C0→0x0C0 vs 0x400001C1→0x060" is **NOT confirmed**:
- Evidence FOR C0↔0x0C0: many `spec1=0x030000xx` records use frameObj 0x400001C0 (@0x141128,
  0x141150, 0x1411A0, 0x141498). 
- Evidence AGAINST a clean split: 0x400001C0 also appears with spec1>>18 = 0x040, 0x1C0, 0x401,
  0x3C0; and 0x400001C1 appears with 0x0C0, 0x206, 0x3C0, 0x406. So both frameObjs are shared
  across several IDs. **Must resolve via the FlexCAN RX reception-descriptor table (ctrlDesc+0x44)
  that ties MB-id → frame-image → frameObj — not yet decompiled/parsed for CAN0.** (c)

---

## 3. GATEWAY LINK FOUND SO FAR

### 3.1 Shared-signal-RAM method
A gateway translation = an RX record stores a HS signal to a signal-RAM addr, and a TX record
reads that SAME signal-RAM addr into the 0x020 image. Cross-referencing all routing records by
shared sigRAM between an HS frameObj and an MS frameObj yields **one strong cluster**:

**HS frameObj 0x400001C0  →  MS frameObj 0x400004FC : 7 genuinely-shared signals** — **(b)**

| shared sigRAM | HS record(s) (flash) | MS record(s) (flash) |
|---------------|----------------------|----------------------|
| 0x40000751 | 0x141170,0x141198,0x14142c,0x141440,0x141454 | 0x148bc4 |
| 0x40000774 | 0x140f7c,0x141364 | 0x149604 |
| 0x4000077B | 0x14110c,0x141134,0x141148,0x14115c,0x1414a4,0x1415f8 | 0x147684,0x1481e4,0x1495c4 |
| 0x4000078A | 0x140fcc,0x140ff4,0x141008 | 0x149184 |
| 0x4000078D | 0x140fe0,0x141238,0x14124c | 0x147424 |
| 0x4000079F | 0x1412c4,0x1414cc,0x14ab10 | 0x148c24 |
| 0x400007A1 | 0x14138c | 0x148c44 |

These 0x4000075x–0x4000_07Ax signals are the HS-CAN 0x0C0 signal block (see §3.3). This is the
concrete evidence that HS 0x0C0 signal data flows into an MS-CAN frame. **Whether that MS frame is
0x020 specifically depends on the MS record's spec1 ID — pending (see NEXT STEPS).** (b for the
shared-RAM link; c for it being TX 0x020 vs another MS frame)

### 3.2 CAVEAT — the 0x40000614 null signal
sigRAM **0x40000614** appears "shared" across virtually every HS↔MS frameObj pair. It is a
default/null/unused-signal sink (a Volcano placeholder), **NOT a real translation**. Ignore it and
any mapping whose only shared addr is 0x40000614. **(b)** (appears in >100 unrelated records).

### 3.3 HS-CAN RX 0x0C0 signal records (spec1>>18 == 0x0C0) — **(b)**
17 records extracted (`gw_targets.py`). Representative (fmt: @flash fo spec1 spec2 sigA→sigB):
```
@141150 fo=400001C0 spec1=03000000 spec2=08B20000 sig 4000077B -> 4000077B
@141128 fo=400001C0 spec1=03000200 spec2=08720000 sig 4000077E -> 4000077B
@1411A0 fo=400001C0 spec1=03000000 spec2=80B20000 sig 40000797 -> 40000799
@141498 fo=400001C0 spec1=03000000 spec2=01F10000 sig 4000077B -> 4000077C
@1411B4 fo=400001C1 spec1=03004000 spec2=02320000 sig 4000074A -> 4000074A
@140124 fo=400001A3 spec1=03000480 spec2=80C20000 sig 400006AC -> 400006AC
@140084 fo=400001A1 spec1=03000440 spec2=40020000 sig 40000688 -> 40000688
... (full list in work/aligned_records.txt filtered by spec1=030000xx)
```
So HS 0x0C0 unpacks into signal-RAM 0x40000688, 0x400006AC, 0x4000074A, 0x4000077B/C/E,
0x40000797/9, 0x40000751, etc. Overlap of 0x4000075x/077x/079x with §3.1 confirms the 0x0C0→MS
path. **(b)**

### 3.4 HS-CAN RX 0x060 and MS-CAN TX 0x020 — NOT yet extracted
`gw_targets.py` returned **0 records** for `spec1>>18==0x060` (HS) and `==0x020` (MS). This means
either (a) those frames encode their ID differently in spec1 (e.g. a different flag layout, or the
records live under a frameObj whose net-range I mis-bounded), or (b) 0x060/0x020 signal records use
a different record variant. **UNRESOLVED — top priority on resume.** (c)

---

## 4. PARTIAL SIGNAL-LEVEL BIT MAPPINGS (decoded so far)

From the MSX 24-byte descriptor table (@0x15A920+, frameObj 0x400005A8) — bit positions PROVEN:
| sigRAM | byte | bitmask | descriptor @ |
|--------|------|---------|--------------|
| 0x40000B58 | 0 | 0x01 | 0x15A920 |
| 0x40000B38 | 1 | 0x02 | 0x15A940 |
| 0x40000B41 | 2 | 0x04 | 0x15A960 |
| 0x40000B7B | 3 | 0x08 | 0x15A980 |
| 0x40000B84 | 4 | 0x10 | 0x15A9A0 |
| 0x40000B46 | 5 | 0x08 | 0x15A9E0 |
| 0x40000B4F | 6 | 0x04 | 0x15AA00 |
| 0x40000B69 | 7 | 0x20 | 0x15AA20 |
| 0x40000B72 | 8 | 0x40 | 0x15AA40 |
| 0x40000B60 | 9 | 0x10 | 0x15AA60 |

These decode `spec2` (high byte = bitmask). **The general spec2→(startbit,length) decode is only
partially done** — high byte is bitmask; the remaining nibbles (0x18/0x02/0x03 patterns, e.g.
`...180600`, `...020000`, `...210000`) are believed to encode byte-index / bit-length / direction
but are **not yet fully decoded (c)**. Note these are MSX signals, not the 0x0C0→0x020 path;
they were used only as a Rosetta stone for the packspec format.

**No complete 0x0C0/0x060-bit → 0x020-bit row is proven yet** because §3.4 (0x020 records) is
unresolved and spec2 length-decode is incomplete. Do NOT report bit-level 0x020 mappings until
those two gaps close.

---

## 5. NEXT STEPS / OPEN QUESTIONS (resume here)

1. **Lock frameObj/record → CAN-ID for CAN0 and find 0x060 & 0x020 records.**
   `gw_targets.py` found 0 records for HS 0x060 and MS 0x020 under the `spec1>>18` filter — resolve
   first. Check: (a) does spec1 for 0x060 = 0x01800000 appear at all in aligned records? grep
   `aligned_records.txt` for spec1 starting 0x0180 and 0x0080. (b) Re-bound the MS frameObj range
   (0x020 TX records may sit under frameObj 0x400004FC–500, which I may have filtered as noise).
   (c) Decompile the CAN0 RX reception-descriptor walk: ctrlDesc 0x1464E0 **+0x44 → 0x00018000**;
   parse the 28-byte reception descriptors there (used by FUN_000fc63e) to map MB-id→image→frameObj
   authoritatively.

2. **Fully decode spec2 packspec** into (start_bit, bit_length, byte_order, scaling). Use the MSX
   Rosetta table (§4) plus multi-bit signals; verify against FUN_000fc63e's byte-copy loop
   (desc+0x1a byte-mask) and the TX packer FUN_000fc218/FUN_000fc2f6 bit loops.

3. **Map the 0x060 path** the same way as 0x0C0 (§3.3): extract all `spec1=0x0180_00xx` records,
   list their sigRAM, intersect with MS-CAN 0x020 sigRAM.

4. **Confirm the TX 0x020 packer**: identify which MS frameObj + spec1 = 0x00800000 corresponds to
   the 0x020 image; decompile the periodic TX for net5 (net record word0 0x400004FC region) and
   verify it reads the 7 shared signals (§3.1) and packs them per spec2.

5. **Verify frame-image addresses** for 0x0C0/0x060/0x020 via the FlexCAN reception/transmission
   descriptor tables (not just the routing table) to satisfy deliverable's "RAM frame-image addr"
   requirement. The 28-byte frame table at 0x1B35C is the model, but for the LOW-speed net; find the
   HS (net0) and MS (net5) equivalents (net record +0x58 → 0x144DD0 for net0, 0x146330 for net5 —
   these turned out to be MB-status pointer arrays; the real image ptrs are the routing record
   frameObjs' backing store — reconcile).

---

## 6. HELPER SCRIPTS (in work/)

Raw-image struct scanners (fast, no Ghidra; operate on work/flash_merged.bin, big-endian):
- **gw_scan.py** — `hdr` / `sigrec` / `dump <start> <end>`: hex/u32 dump utility. Core viewer.
- **gw_idscan.py** — scan whole image for id<<18 and raw-id 4-byte-aligned matches.
- **gw_mblist.py** — parse the 12-byte FlexCAN MB filter lists after each controller (§1.2). ✅ key.
- **gw_nettbl.py** — parse the 0x5C-byte master network table @0x178B0 (§1.1). ✅ key.
- **gw_route.py** — validate/collect 20-byte routing records (method-ptr variant); writes routing_records.txt.
- **gw_route20.py** — routing records as [sigA][sigB][frameObj][pk1][pk2]; MSX Rosetta calibration.
- **gw_aligned.py** — parse aligned [frameObj][spec1][spec2][sigA][sigB] records; writes aligned_records.txt. ✅ key.
- **gw_targets.py** — extract records for HS 0x0C0/0x060 and MS 0x020 by spec1>>18 (§3.3/§3.4). ✅ key (0x060/0x020 returned 0 — see NEXT STEPS).
- **gw_shared.py** — find sigRAM shared between HS and MS frameObjs → gateway candidates (§3.1). ✅ key.
- **gw_sig24.py / gw_sigfull.py / gw_sigtbl.py** — parse the 24/28-byte signal-descriptor tables (0x15A920+, 0x152000+).
- **gw_decode_pk.py** — decode spec2 bit-packing using MSX known-bit signals (§4).
- **gw_foid.py / gw_foid2.py / gw_frefid.py / gw_frefid2.py / gw_objid.py** — various frameObj→CAN-ID co-occurrence attempts (all show frameObj is many-to-many with ID — §2.1).
- **gw_framedesc.py / gw_allframes.py / gw_ftables.py / gw_frames.py / gw_framedef.py** — 28-byte frame-descriptor table scanners (found 0x1B35C low-speed table).

pyghidra scripts (need `. .venv/bin/activate`; set GHIDRA_INSTALL_DIR; project is single-writer):
- **gw_dec.py `<addr...>`** — decompile function(s) at given entry addrs. ✅ key.
- **gw_mkfunc.py / gw_mkfunc2.py `<addr...>`** — create/disassemble functions at addrs (mkfunc2 opens writable + saves). ✅ needed for the 0xFCxxx codecs.
- **gw_refs.py / gw_refs2.py `<addr...>`** — list references to an address (found net table @0x178xx binds ctrl descs). ✅ key.
- **gw_findcan.py** — scan for FlexCAN-base immediates (proved none exist → table-driven).

Output data files written: routing_records.txt, aligned_records.txt, sig_descriptors.txt,
sig_desc_full.txt, sig24.txt, allframes.txt.

Pre-existing reference scripts reused: work/pg_tool.py (decompile helper), decode_ctrl.py,
decode_f10a.py, pg_canptrs.py, scan_frame_ids.py.

---

## 7. SUMMARY OF WHAT IS PROVEN vs OPEN

**Proven (a/b):** the 3 controllers + baud + bus roles; the FlexCAN MB filter lists locating
0x0C0/0x060/0x020 per bus; the 20-byte routing-record format with spec1=id<<18 and spec2 high-byte
= bitmask; the generic table-driven RX copier (FUN_000fc63e) and TX packer (FUN_000fc218/2f6); a
concrete HS-0x0C0-signal → MS-CAN gateway cluster (7 shared signal-RAM addrs, frameObj
0x400001C0→0x400004FC); the HS 0x0C0 signal-RAM set.

**Open (c):** which MS frame the 7 shared signals pack into is 0x020 specifically (0x020 records not
yet isolated); the HS 0x060 record set (not yet isolated); full spec2 → start-bit/length/scaling
decode; authoritative frameObj→CAN-ID (frameObj is many-to-many with ID, so per-record spec1 is the
ID of record — but 0x060/0x020 spec1 not yet located). No fabricated bit-level 0x020 rows are
included; they await the NEXT STEPS above.
