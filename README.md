# Ford BCM (C1MCA) right-to-repair firmware project

Onboarding and technical-status document for anyone continuing this work. Read this first, then
the four docs in `docs/`. Everything here is backed by real extraction; claims are tagged
**(a)** decompiled-code proof · **(b)** validated-table-structure proof · **(c)** inferred/unproven.

---

## 0. Goal & current status

**Goal:** document, maintain, and repair the Ford BCM (Body Control Module) firmware from the aging
C1MCA platform, for which manufacturer support and replacement firmware are no longer available.
The technical work focuses on its role as a **CAN gateway** between HS-CAN (500k) and MS-CAN
(125k), and on how CAN frames/signals are routed or translated between buses.

**Original concrete task:** find the translation of RX HS-CAN `0x0C0` and `0x060` → TX MS-CAN `0x020`.

**Status (high-level):**
- ✅ VBF files parsed & verified; raw binaries extracted; merged flash image built.
- ✅ **Owner full-flash dump analysed layer-by-layer** — `ghidra_proj_fullflash`, **1,161 verified symbols**
  across 16 layers, incl. the 48 KB PBL that no OEM VBF contains. This is the **primary** project.
  See **`docs/owner_flash_layers.md`** (analysis) and **`docs/owner_artifacts.md`** (outputs).
- ✅ **Full code sweep done** — 2,403 → **13,588 functions** (483k code units) by linear-sweeping the
  unreferenced code the recursive disassembler could not reach, with a per-range quality gate that
  rejected 91 data regions. See `owner_flash_layers.md` §23.
- ✅ Gateway architecture understood: **table-driven Volcano network database**, not hand-coded.
  Complete per-bus CAN-ID inventory extracted from FlexCAN acceptance filters and **cross-validated
  against the vehicle databases** (58 MS directions agree, 0 mismatches). See **`docs/gateway_map.md`**.
- ✅ **`frameObj → CAN-ID` binding RESOLVED** (long the key open item). RX and TX record layouts were
  decoded from the consuming code, yielding **279 RX frames, 15 HS TX, 43 MS TX** with per-byte
  addresses. All four addresses the shipped mods rely on (`0x40000707`, `0x40000705`, `0xFFFC0080`,
  `0xFFFC4090`) are reproduced independently by the tables.
- ✅ Application diagnostics mapped: 492-entry DID table, **476 per-identifier readers named**,
  validated against a real scan-tool session (146/147 supported, 29/29 security-gated).
- ✅ One cross-bus signal link **proven**: HS `0x0C0` → MS `0x020` (shared signal-RAM).
- ✅ **Shipped modification `acc-fix`** (on-vehicle proven): remaps the new SWM steering-wheel
  cruise buttons in TX HS-CAN `0x030` so the old PCM understands them. **§5.4**, `docs/acc-fix.md`,
  porting guide `AGENTS.md`.
- ✅ **Shipped modification `rke-lock`** (on-vehicle proven): lets the remote key **lock the car with
  the ignition ON** (stock BCM blocks it), gated on **key-outside**. TX-mailbox injection on MS-CAN
  `0x3A`, layered into the same caves as acc-fix → **one combined VBF**. **§5.5**, `docs/rke-lock.md`.
- ⚠️ **Module identity lives in the BOOTLOADER block** — `F111`/`F113`/`F180`/`F18C` are served by app
  readers from literals at `0x006B10..0x006BA8`, and the **VIN** sits at `0x008000`. No OEM VBF
  contains any of it, so it is **restorable only from the owner backup**. This module also reports
  different `F111`/`F113` than the vehicle's as-built data (replacement unit).
  See `docs/owner_flash_layers.md` §21.
- ⚠️ **Key open item:** the **unpack stage** (packed RX frame images → the app signal planes) is not
  located. Measured: zero app functions touch image bytes by absolute address, so static analysis
  cannot find it — needs bench instrumentation (`owner_flash_layers.md` §20.2).
- ❗ **12 retracted assumptions — read §7 before building on anything.**

---

## 1. Target hardware

- **MCU:** SPC560B64L7 (STMicro), MPC5607B family, PowerPC **e200z0h** core, **big-endian**,
  **VLE** instruction set only. Flash base `0x0`, SRAM base `0x40000000` (96 KB).
- **CAN transceiver:** NXP **UJA1078A** (system basis chip; datasheet `DS_UJA1078A.pdf`).
- **On-chip CAN:** three **FlexCAN** modules — CAN_0 `0xFFFC0000`, CAN_1 `0xFFFC4000`,
  CAN_2 `0xFFFC8000`. Standard 11-bit IDs stored in MB as `id << 18`.
- Reference PDFs in repo root: `DS_spc560b64l7.pdf`, `spc560b64x-refmanual.pdf`, `DS_UJA1078A.pdf`.

### Secondary bootloader / owner recovery and firmware preservation

This part of the project is owner-directed right-to-repair work on an old, unsupported vehicle BCM.
Its purpose is to make a verifiable backup of firmware from the owner's module so that the module
can be studied, preserved, and recovered. It is not a vulnerability assessment, remote-access
project, or investigation of third-party vehicles. All live work is performed on an owned bench
module over its wired diagnostic connector.

- [`docs/sbl-DV6T-14C097-AB.md`](docs/sbl-DV6T-14C097-AB.md) — static analysis and bench results for
  the `DV6T-14C097-AB` RAM SBL: stock erase/program/verify support, but no general flash-backup service.
- [`docs/sbl-upload-patch.md`](docs/sbl-upload-patch.md) — reproduced the normal SBL download/call
  protocol, documented the missing stock backup service, and validated a temporary SRAM addressed-
  frame reader. The complete CFlash, shadow-flash, and DFlash backup workflow is bench proven.
- [`backups/owner-backup-20260911T090300Z/`](backups/owner-backup-20260911T090300Z/) — the resulting
  owner backup (CFlash, shadow flash, DFlash) with hashes and a manifest. Each region was captured
  twice byte-identically and cross-checked against the OEM VBFs and the firmware's internal `sum8`.
- `BCM_CAN_Pins` — pinout notes (repo root).

### Buses (a)+(b)
| FlexCAN | Base | Baud | Role |
|---------|------|------|------|
| CAN_0 | 0xFFFC0000 | **500 kbps** | **HS-CAN** (main high-speed) |
| CAN_1 | 0xFFFC4000 | **125 kbps** | **MS-CAN** (mid-speed body) |
| CAN_2 | 0xFFFC8000 | **125 kbps** | **MSX-CAN** (left/right side obstacle / parking-assist modules) |

Baud from FlexCAN CTRL reg (ctrlDesc+0x30) at **f_can = 30 MHz**:
`0x05492004`→500k, `0x17DB2000`→125k.

---

## 2. Input files (VBF) & extraction

Three Volvo/Ford **VBF** (Versatile Binary Format) files in repo root:

| File | Part type | Loads at | Contents |
|------|-----------|----------|----------|
| `JV6T-14C094-AD.VBF` | Application (EXE) | 0x10000 | Main firmware + generic CAN driver/codec |
| `JV6T-14C403-AB.VBF` | Cal Config **F10A** | 0x140000 | **Volcano CAN network database** (the gateway map) |
| `JV6T-14C095-AB.VBF` | Cal Data **F124** | 0x0C000 | Signal defaults / local configuration |

**VBF format** (validated against `github.com/smartgauges/qvbf`): ASCII `header { … }` then binary
blocks `[addr:4 BE][len:4 BE][data][crc16:2 BE]`. Per-block **CRC-16/CCITT-FALSE**; whole-file
**CRC-32** (reflected, poly 0xEDB88320). No `data_format_identifier` ⇒ **no LZSS** (raw blocks).
All CRCs verified byte-perfect. Diagnostic identity from headers: `ecu_address = 0x726`.

### ⚠️ 2.1 THREE integrity layers — repair ALL on any app-block edit

Editing the application (EXE) block invalidates **three independent** integrity checks. The two
VBF container CRCs are **not** sufficient — there is also an **internal on-image checksum the BCM
verifies at boot**. Miss it and the BCM boots into **safe mode with a software-integrity fault**
(observed on a real vehicle after flashing an app edit that repaired only the container CRCs).

| # | Layer | Where | Algorithm |
|---|-------|-------|-----------|
| 1 | VBF per-block checksum | 2 bytes after each block's `[start][len][data]` | CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect) |
| 2 | VBF file checksum | header text `file_checksum = 0x…;` | CRC-32 (`zlib.crc32`, reflected 0xEDB88320) over first block's start-addr field → EOF |
| 3 | **INTERNAL app checksum** | **`0x13FFFE`** (low 16 bits; word at `0x13FFFC` keeps high half `0xFFFF`) | **`sum8 = (Σ bytes 0x10000 … 0x13FFFE) & 0xFFFF`**, big-endian halfword |

Layer 3 covers the whole app block from the RCHW/reset block (`0x10000`) up to — but **not
including** — the 2-byte checksum word itself. Proven byte-exact on **two** OEM part versions:
`JV6T-14C094-AB` → `0x6288`, `JV6T-14C094-AD` → `0x7572` (stored == computed in both).

**How it was found:** diff two OEM versions of the *same* part (`-AB` vs `-AD`, size-identical).
Most of the app block differs by a global `+4` code-pointer relocation (noise); the legit
integrity fields are the few differing aligned words that are **not** `+4` shifts. The block tail
is the giveaway — `0x13FFE0` holds the ASCII part number, `0x13FFFC/E` the checksum. Confirm by
finding the `(algo, range)` whose result equals the stored value in **both** versions
(cross-version validation eliminates false positives). Winning combo: `sum8(0x10000..0x13FFFE)`.

**Rebuild order (mandatory):** apply data edits → recompute internal `sum8` @`0x13FFFE` →
recompute each block CRC-16 → recompute file CRC-32 into the header. Also note a single logical
change can span **two VBF files** (e.g. a descriptor-pointer edit in the APP block + a routing
record in the F10A cal block = two container checksum domains); repair and flash both.

Helper scripts (in `work/`): `cmp_ab_ad.py` (OEM version diff), `hunt_cksum.py` / `hunt_const.py` /
`find_algo.py` (integrity-word hunt), `check_internal.py` (validate layer 3),
`vbf_crc_validate.py` (container CRC check). The per-mod builders under `work/acc-fix/` and
`work/rke-lock/` repair all three layers automatically (§5.4/§5.5). Whatever flashing/repack step is
used must deliver the app block **byte-exact** (no re-alignment/re-padding) or the `sum8` drifts
again.

**Extraction pipeline** (all in `work/`):
```
python3 work/vbf_extract.py <file.VBF> work/bins   # parse + dump blocks (verifies structure)
python3 work/crc_check.py                          # per-block CRC-16 check (all OK)
python3 work/crc32_check.py                        # whole-file CRC-32 check (all OK)
python3 work/build_image.py                        # assemble work/flash_merged.bin
```
`work/flash_merged.bin` = one flat big-endian image (base 0x0, 0xFF-filled gaps) with F124@0xC000,
app@0x10000, F10A@0x140000. **This is the file to struct-scan and to load in Ghidra.**

---

## 3. Ghidra project

Two projects exist. **Use the right one for the question:**

| Project | Program | Covers | Use for |
|---|---|---|---|
| `ghidra_proj/` · `BCM_C1MCA` | `flash_merged.bin` | app + both cals, re-assembled from OEM VBFs | the historical `acc-fix` / `rke-lock` builds (their addresses are quoted against this image) |
| **`ghidra_proj_fullflash/` · `BCM_OwnerFlash`** | `cflash.bin` | the module's **real** nonvolatile memory — **incl. the 48 KB PBL**, shadow array and DFlash | **everything else — now the primary project** |
| `ghidra_proj_accfix_rkelock/` | patched image | the modified app block as built by the mod pipeline | inspecting a built mod |
| `ghidra_proj_sbl/` · `SBL` | `work/sbl_merged.bin` | the secondary bootloader | `docs/sbl-*.md` |

The owner project is built straight from `backups/owner-backup-20260911T090300Z/` and carries
**938 verified user-defined symbols** across 16 analysed layers. Because no OEM VBF ships the primary
bootloader, **everything below `0xC000` is invisible in `ghidra_proj/`**.

See [`docs/owner_flash_layers.md`](docs/owner_flash_layers.md) for the full layer-by-layer analysis and
`work/owner/` for the scripts (each layer is reproducible — §27 of that doc lists the commands).

What the owner project now maps, beyond the bootloader:

| Area | Detail |
|---|---|
| **CAN codec** | TX/RX record layouts decoded from consumer code; **279 RX + 15 HS TX + 43 MS TX frames** enumerated with per-byte addresses |
| **Bus map** | CAN_0 HS 500k / CAN_1 MS 125k / CAN_2 MSX 125k — derived from the FlexCAN `CTRL` registers, not assumed |
| **Diagnostics** | 492-entry DID table, **476 per-identifier reader functions** individually named |
| **Memory** | retained RAM / `.data` / `.bss` boundaries read from the reset path |
| **Validation** | all three addresses the shipped on-vehicle mods use (`0x40000707`, `0x40000705`, `0xFFFC0080`, `0xFFFC4090`) fall out of the decoded tables independently |

- **Ghidra:** 12.1.2 at `/opt/ghidra`. Language **`PowerPC:BE:64:VLE-32addr`**.
- **Critical setup already applied:** `vle` context register = 1 on the code region (0x10000–0x13FFFF)
  — without it nothing disassembles. Entry point 0x0010F4A0 (from RCHW `005A005A` @0x10000). SRAM
  (0x40000000) and peripheral blocks added. Full auto-analysis done and saved.

### Driving Ghidra headless via pyghidra (preferred)
A venv with pyghidra 3.1.0 is at `.venv/`:
```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate
python3 work/gw_dec.py 0xfc63e 0xfc218 0xfc2f6   # decompile function(s) by entry addr
```
In any pyghidra script: `os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"; pyghidra.start()`, then
`GhidraProject.openProject("…/ghidra_proj","BCM_C1MCA",False)` and
`project.openProgram("/","flash_merged.bin",False)`. **Always `project.close()` in `finally`;
open read-only; only ONE process may hold the project at a time.** Reference scripts: `pg_*.py`
(setup/analyze/decompile helpers), `gw_dec.py`, `gw_mkfunc*.py`, `gw_refs*.py`.

---

## 4. How the Volcano gateway works (mental model)

The BCM is a **table-driven Volcano gateway**. Application code is generic; **all** CAN behavior is
data in the calibration blocks, walked at runtime (`FUN_0004471a → FUN_000fbc48(&PTR_00140000)`).
**Proof (a):** no CAN-ID and no FlexCAN base appears as a code immediate anywhere.

```
[1] Master net table 0x0178AC/0x017A78/0x017AD4   +0x08 → controller descriptor  (stride NOT uniform)
[2] Controller desc  0x1464E0/0x146900/0x146C50   FlexCAN base (+0x10), CTRL/baud (+0x30)
[3] MB filter list   0x146530/0x146950/0x146CA0   12B: [id<<18][dir 0x04=RX/0x08=TX][mask]
                                                  list position == hardware mailbox index
[4] RX/TX descriptor arrays — anchored at RUNTIME (S+0x44 → T), no flash pointer exists
[5] Signal-routing records 0x140000–0x15BF00      28B, marker-anchored
[6] Signal descriptors 0x15A920 (24B) + defaults in F124@0xC000
```

**Codec code (a):** RX copier `FUN_000fc63e` (MB→frame-image, **compacting** byte copy), TX packers
`FUN_000fc218` (single) / `FUN_000fc2f6` (walker) (frame-image→MB), net bring-up `FUN_000fbc48`,
hardware init `FUN_000fceb8`. Signals live in RAM `0x40000600–0x40000D2F`.

**Gateway translation = shared signal-RAM:** a cell written while unpacking an RX frame and read
while packing a TX frame. That is the ONLY reliable evidence of cross-bus content flow.
**Same CAN-ID number on both buses is NOT evidence of forwarding** (§7).

Full layouts, per-bus ID inventory, frame maps and routing evidence: **`docs/gateway_map.md`**.

---

## 5. Established results

### 5.1 Per-bus CAN-ID inventory (authoritative, from MB filters) (b)
`python3 work/gw_mbfull.py`. **HS-CAN** 46 RX / 17 TX · **MS-CAN** 14 RX / 49 TX · **MSX-CAN**
obstacle IDs only. Cross-validated against the vehicle CAN databases: **58 MS directions agree, 0
mismatches**. Full lists: `docs/gateway_map.md` §2.1.

### 5.2 Frame maps — every RX/TX frame byte has an address (a)
RX and TX record layouts decoded from the consuming code: **279 RX frames, 15 HS TX, 43 MS TX**
with per-byte absolute addresses (`work/owner/rx_frame_map.json` / `tx_frame_map.json`). All four
addresses the shipped mods rely on fall out of the tables independently. `docs/gateway_map.md` §3.

### 5.3 Proven cross-bus signal link (b)
**HS-CAN 0x0C0 → MS-CAN 0x020**, via 7 shared signal-RAM cells
`0x40000751/774/77B/78A/78D/79F/7A1` — the answer to the original 0x0C0 half of the task. The
**0x060 path is not mapped** (§8). `docs/gateway_map.md` §6.

### 5.4 ACC-FIX — SWM cruise-button remap in TX HS-CAN 0x030 (a) — ON-VEHICLE PROVEN
**Purpose:** adapt a **new SWM** (steering-wheel module) to the **old PCM**. The BCM reads the SWM
buttons over LIN and composes them into TX HS-CAN **`0x030`**. The new SWM's combo
buttons land on bits the old PCM does not act on; ACC-FIX rewrites the assembled `0x030` payload so
the old PCM sees the correct cruise signals. **Build artifact:** `work/acc-fix/JV6T-14C094-AD_acc-fix.VBF`
(APP/EXE VBF only; sha256 `f5fb75e33398f860d17b1b21496fdc9c8ca525bc55a446ef82f3278a1b02c9eb`).

**Bit mapping applied** (0x030 byte indices d0..d7):
| Source (SWM as composed) | → Target (old PCM understands) | Rule |
|---|---|---|
| `ACC_Res_Plus` d1 bit6 (0x40) | `CC_Res` d5 bit5 (0x20) **or** `CC_Set_Plus` d5 bit7 (0x80) | context-gated (below) |
| `ACC_Lim` d1 bit5 (0x20) | `CC_Lim` field d6[5:6] = `0b10` (pressed) | set field to 0x40; released `0b01` is the native d6=0xB3 baseline |

**RES+ context gate (reads two PCM frames back):** RES+ is a combo button — it must act as **Resume**
only when cruise/limiter is *cancelled with a stored set-speed*, else as **Set+**. It combines
**`0x0C0` d0** (status) and **`0x060` d6** (stored set-speed). The status byte alone is ambiguous: a
fresh cancel decays after ~2 s to the same value as engaged-but-no-speed-yet —

| mode | engaged-not-set | active | cancel (fresh) | cancel (~2 s later) |
|---|---|---|---|---|
| cruise | `0x18` | `0x10` | `0x40` | → `0x18` |
| limiter | `0x38` | `0x30` | `0x48` | → `0x38` |

so `0x18`/`0x38` are indistinguishable by d0. The set-speed **`0x060` d6** (0 until a speed is ever
set) breaks the tie.

Gate = **`(d0 & 0x48) != 0` AND `(0x060 d6 != 0)`** → Resume, else Set+. (`d0 & 0x48` = StandBy bit3
| cancel bit6, covering both fresh and decayed cancels; `d6 != 0` excludes engaged-not-set and off.)

Reads (both plain decoded RAM frame-images, verbatim RX-copier writes): `0x0C0` d0 at
**`0x40000707`** (MB30, mask `0x13`); `0x060` d6 at **`0x40000705`** (MB22, base `0x40000700`, mask
`0xFE` — **compacted** copy, so d6 lands at base+5, not base+6).

> ⚠ **Gate history (each corrected on-vehicle):** (1) bit3-alone mis-fires on limiter no-speed
> standby `0x38`; (2) interim `(d0&0x28)==0x08` misread cruise-started `0x18`/active `0x10` as paused;
> (3) bit6-alone `0x40` broke once the status byte **decayed** — cancelled cruise/limiter fall to
> `0x18`/`0x38` after ~2 s, indistinguishable from engaged-not-set. The two-frame rule
> `(d0 & 0x48) && (0x060 d6 != 0)` is the robust fix (`candump-2026-09-09_191816.log`).

**Implementation = TX-time injection hook (no data-table edit).** d1 and d5/d6 live in *different*
composition PDUs, so the bits cannot be moved during signal packing; the only place all 8 bytes of
0x030 are contiguous is the final FlexCAN mailbox. Two TX packers are hooked, each gated on
**CAN0 MB0** (=0x030, MB CS addr `0xFFFC0080`):
| Packer | Hook site | Displaced instruction(s) | Code cave |
|---|---|---|---|
| `FUN_000fc218` single-frame | `0xFC2C2` (`e_sth r7,0x0(r10)`) | `e_sth r7,0x0(r10)` | `accfix_cave_single_packer` @ `0x117100` |
| `FUN_000fc2f6` periodic walker | `0xFC440` (`se_extzh r7; se_sth r7,0x0(r29)`) | both | `accfix_cave_walker_packer` @ `0x117300` |

Each cave: save scratch → `cmplw mbreg,0xFFFC0080` gate → apply RES+ (edge-latched) and LIM
transforms on the MB data bytes (`d1=+0x89, d5=+0x8D, d6=+0x8E` off the CS addr) → restore →
replay displaced store(s) → branch back. Caves live in the in-block `0xFF` padding (covered by the
internal sum8). Both are labeled/plate-commented in the Ghidra DB (bookmarks type `Note`, category
`ACC-FIX`). All three integrity layers (§2.1) are repaired by the build.

**RES+ edge-latch (why it isn't stateless):** a single physical press is **held ~240 ms** (0x030 goes
out every ~10 ms while held). Resume flips the PCM `paused → active` *mid-press*, so a per-frame
gate would emit Resume for a few frames and then **Set+** for the rest — bumping the set-speed
(observed `candump-2026-09-09_214156.log`: brief `d5.5` then `d5.7`, speed `0x50→0x55`). Fix: decide
**once at the rising edge** and hold it for the whole press, via a 1-byte latch **`L` @`0x40011000`**
(0=idle, 1=Res, 2=Plus):
```
if (d1 & 0x40) {                                   // ResPlus held
    if (L == 0) L = ((0x0C0 d0 & 0x48) && 0x060 d6 != 0) ? 1 : 2;  // decide on rising edge
    d5 |= (L == 1) ? 0x20 : 0x80;                  // apply latched decision every held frame
    d1 &= ~0x40;
} else L = 0;                                       // released -> reset
```
`0x40011000` is **proven-unused SRAM** (`docs/scratch_ram.md`): inside the startup ECC/zero-init
range `[0x400039A0..0x40014000]` (so it powers up 0), above the stack top (SP=`0x4000CAC8`), below
the SDA base (`0x40017920`), with **zero references anywhere in flash** — written/read only by the
two caves. No stock code is modified (deliberately not reusing SWM button state bytes, which the LIN
handlers still drive every frame).

**Reproduce / rebuild:**
```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate
python3 work/acc-fix/build_caves.py      # assemble caves+hooks (Ghidra VLE asm) -> patch_blobs.json
python3 work/acc-fix/build_vbf.py        # patch APP VBF + repair all 3 integrity layers
python3 work/acc-fix/verify.py           # re-parse CRCs, sum8, re-disasm caves, behavior sim, diff
python3 work/acc-fix/annotate_ghidra.py  # (re)apply labels/comments/bookmarks to the Ghidra project
```
Full method + porting guide for **other OEM BCM versions**: **`AGENTS.md`** and **`docs/acc-fix.md`**.

---

### 5.5 RKE-LOCK — remote-key lock with ignition ON (a) — ON-VEHICLE PROVEN
**Purpose:** the stock BCM ignores an RKE (remote key) lock press while the ignition is ON; this mod
lets it lock, **only when the passive key is outside the cabin** (never lock the key in a running car).
**Build artifact:** `work/rke-lock/JV6T-14C094-AD_accfix-rkelock.VBF` — the **combined** APP VBF
carrying BOTH acc-fix and rke-lock (sha256 `ca4ccb170ec1dd6352e9ed7b0764bc4de5382310f42b3296b445db6b24892343`).

**Gate + action** (all reads proven from captures; full detail in `docs/rke-lock.md`):
| Input | Where | Test |
|---|---|---|
| RKE LOCK button | MS `0x100` RX image d7 `0x4000091F` | bit0 |
| key outside | `0x100` d1 `0x40000919` | bit7 |
| ignition = Run | `0x3A0` raw d0 `0xFFFC42C8` | hi-nibble == 4 |

(_UB_ = `0x100` d6 bit2 was tried as a gate but **dropped** — the RFA asserts it only after validating
the rolling code, lagging the first few presses; our own rising-edge latch handles per-press detection.)

When all true on the **rising edge** of the lock press, inject one **execute strobe** onto the TX
MS-CAN `0x3A` mailbox (CAN1 MB1, CS `0xFFFC4090`): `d3 (lock-command)=0x01` + `d1 |= 0x42`
(bit6 execute strobe + bit1 UB). This reproduces the BCM's **own** native lock-with-ignition-on
sequence (learned from the interior-lock-button capture: one `82 C3 00 01…` strobe, then steady
native stream). `d1 bit6` is a **one-shot strobe**, not a level — asserting it every frame re-actuates
the motor (the "rapid clicking" failure v1/v2 hit). After our strobe, a ~1 s window clears `d1 bit6`
on outgoing lock frames to neutralise the BCM's **own follow-up re-strobe** (~0.45 s later, emitted
because it learns of the external lock via DDM — this caused the v3 double-click; proven single-strobe
on the physical-key-turn capture). A genuine unlock during the window passes through. See
`docs/rke-lock.md` §4/§7. One press → one clean lock.

**Implementation:** no new hook — the RKE block is appended to **both** acc-fix caves
(`0x117100` single packer, `0x117400` periodic walker) after the acc-fix CAN0-MB0 gate, gated on
`cmplw mbreg,0xFFFC4090`. The walker (`FUN_000fc2f6`) is the active path for `0x3A`. Two scratch bytes
`L2 @0x40011001` (press latch, re-armed on button release) + `L3 @0x40011002` (time-based re-strobe
suppress countdown) — kept independent so the BCM's native d3=02 stream can't re-trigger our strobe
(the v4 5-click bug; see `docs/rke-lock.md` §7). Proven-unused SRAM adjacent to
acc-fix's `0x40011000`. acc-fix logic is byte-preserved (only branch offsets shift). All three
integrity layers repaired over the combined image.

**Reproduce:**
```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate
python3 work/rke-lock/build_caves.py     # both caves (acc-fix + RKE) -> patch_blobs.json
python3 work/rke-lock/build_vbf.py       # patch combined APP VBF + repair all 3 integrity layers
python3 work/rke-lock/verify.py          # CRCs + sum8 + cave byte-exactness + diff-vs-OEM + one-shot sim
```
Full method: **`docs/rke-lock.md`**.

---

## 6. Document map (`docs/`)

| Document | What it is |
|---|---|
| **`central_locking_chain.md`** | **Consolidated findings (layers 29–35): the two lock-request paths.** Path A (periodic, feature unknown) and Path B (RKE) end to end, every address, what is proven vs open, and the method traps that produced two retractions. Start here for locking. |
| **`owner_flash_layers.md`** | **Primary RE reference.** Layer-by-layer analysis of the real full-flash dump (35 layers, PBL boot path → CAN codec → TX pack stage → request bus → the RKE→lock join), plus the derivation of every correction. Start here for how the module works. |
| **`gateway_map.md`** | **Condensed CAN reference.** Table stack, per-bus ID inventory, RX/TX frame maps, routing model, retracted readings, open items. |
| **`tx_pack_stage.md`** | **Layers 29–30.** The transmit half of the codec (`VOL_sig_set8`, `APP_tx_compose`, 384 source→image pairs), the two-phase periodic task (a correction to §32), the central-lock command chain, and the body-control request/event bus that drives it. |
| `owner_artifacts.md` | Index of the machine-readable outputs (`work/owner/*.json`) and their validation status. |
| `owner_backup_analysis.md` | Backup verification + memory-map recon (how the dump was proven genuine). |

**Shipped modifications**

| Document | What it is |
|---|---|
| **`acc-fix.md`** | SWM cruise-button remap (§5.4): bit map, RES+ context gate, verified cave disassembly, integrity, rebuild steps. Porting guide: **`../AGENTS.md`**. |
| **`rke-lock.md`** | RKE lock-with-ignition-on (§5.5): signals, one-shot strobe, combined VBF, on-vehicle design history. |

**Evidence notes** (each feeds one of the above; none is a standalone conclusion)

| Document | Backs |
|---|---|
| `030_composition_trace.md` | acc-fix — `0x030` LIN→button composition, and why a TX-time hook was required |
| `0c0_standby_read.md` | acc-fix — how the `0x40000707` / `0x40000705` read addresses were proven |
| `scratch_ram.md` | acc-fix + rke-lock — proof that `0x40011000..02` is unused SRAM |
| `rke_0x100_lock.md` | rke-lock — RKE button decode on MS `0x100` |
| `key_outside_gate.md` | rke-lock — key-outside gate + full v1→v5 capture-driven debug history |
| `clockcmd_0x3a.md` | rke-lock — `0x3A` d3 lock command + RKE→lock chain |
| `ign_powermode_0x80.md` | rke-lock — ignition/power state (`0x80` d2; the shipped gate uses `0x3A0`). ⚠ Its §2 "signal-accessor route" is now partly answered: the intersection is `APP_lock_request_dispatch` `0x87A0E` (`tx_pack_stage.md` §7.5), but **whether a gate exists at all** is open — see `owner_flash_layers.md` open item 30. |

**Hardware / recovery**

| Document | What it is |
|---|---|
| `sbl-DV6T-14C097-AB.md` | Static analysis + bench results for the RAM SBL (no stock backup service). |
| `sbl-upload-patch.md` | The SRAM addressed-frame reader and the bench-proven full-backup workflow. |
| `interior_button_gpio_trace.md` | Interior lock/unlock button pin investigation (PI15/PF12) — negative result, exhaustively enumerated. |

---

## 7. ⚠️ Retracted assumptions — DO NOT REPEAT

Gateway-model retractions (1–6) are restated with evidence in `docs/gateway_map.md` §7; the full
derivation of all of them is in `docs/owner_flash_layers.md` §26.

1. **"Same CAN-ID RX-on-one-bus + TX-on-other = forwarding" — FALSE.** Acceptance-filter
   coincidence. No shared signal-RAM exists between the HS-receive and MS-transmit paths for those
   IDs; the BCM independently consumes the incoming frame and independently builds its own
   same-numbered frame (user-confirmed for `0x040`). Prove a forward only via **shared signal-RAM**.
2. **"`spec1` = `CAN_id << 18`" — FALSE.** `(spec1>>18)` matches the bus ID list 23.8 % of the time
   = chance (`work/gw_test_spec1.py`). CAN IDs come from the filter list / descriptor chain only.
3. **"frameObj numeric range = bus" — FALSE.** Ranges are not bus-exclusive. `0x400004FC..FF`, once
   mislabelled "MS frameObj", is the **MS-CAN RX arrival-flag page** — an address, not a frame
   object. The arrival-flag page *is* the reliable per-net discriminator (§19.1).
4. **"`ctrlDesc+0x44` points at the descriptor table" — FALSE.** The controller descriptor hangs off
   net record `+0x08`, not `+0x04`; `+0x44` is a field of the per-net **RAM** state block, and the
   array anchor is built at bring-up, so no flash pointer to it exists (§15.1).
5. **"MS-CAN is TX-only" — FALSE.** 63 configured mailboxes, 14 RX / 49 TX (§19).
6. **Routing records are 28 bytes, not 20.** The inherited 20-byte parse is misaligned — two
   permanently-zero columns and a flat column profile (§16.2). All field semantics derived from it
   (`sigA`/`sigB`/`spec1`/`spec2` positions) are reading shifted data.
7. **"`0x40006400–0x400064FF` is a CAN TX change-flag bus" — FALSE.** It is the per-signal
   **validity / error-substitution** layer; no CAN code reads it (§13.1).
8. **"The `0x28xx` as-built DIDs are patchable calibration values" — FALSE.** All 85 cells are in
   **retained RAM**, accumulated at runtime (§12.2); five of them are one rolling event buffer, not
   five config items (§12.3).
9. **"`FUN_0010DAB8` is the shared signal-access API" — FALSE.** It is `memset()`; 79 of 83 modules
   call it to zero their state blocks. **No signal-access API exists** (§14.6).
10. **"The mailbox is the only place a frame's 8 bytes are contiguous" — TOO STRONG.** The assembled
    TX frame image holds d0–d7 adjacently one stage earlier (§18.3). Does not affect the shipped
    acc-fix, which hooks the mailbox and is on-vehicle proven.
11. **`0x030` remap by editing F10A routing records + EXE image pointers — DOESN'T WORK.** The
    `0x40007Axx` pool that edit targeted is the RX/gateway path, not the transmitted `0x030`; the
    flashed edit was a confirmed no-op. Composition-side remap is impossible anyway — d1 and d5/d6
    live in different PDUs (`docs/030_composition_trace.md` §5).
12. **Single-byte `0x0C0` d0 tests for "cruise paused" — ALL FAILED on the vehicle.** bit3-alone,
    `(d0&0x28)==0x08`, and bit6-alone each broke in a different state; the status byte **decays**
    ~2 s after a cancel. The working gate needs a second frame (`acc-fix.md` §3).

---

## 8. Recommended next steps (resume here)

> **Both ends of the CAN codec are now closed.** RX: `APP_rx_unpack_main` `0x048C6C` (§33). TX:
> `VOL_sig_set8` `0x0FBDD4` / `APP_tx_compose` `0x04B7AA` (`docs/tx_pack_stage.md`), with
> `tx_signal_dict.json` giving 384 injective `(signal cell → frame-image byte, mask, shift)` pairs.
> The `frameObj → CAN-ID` binding is resolved (`docs/gateway_map.md` §3). Items 1 and 2 of the old
> list are **done**; what follows is the current list.

1. **Settle the ignition-lock question with a capture** (`owner_flash_layers.md` open item 30).
   The intersection is `APP_lock_request_dispatch` `0x087A0E`, but every arm *emits* a command and
   the `0x3A` d1 bit6 execute strobe has **no pack descriptor in the image**. At the refusal
   condition, does `APP_lock_command` change at all (⇒ a gate to patch) or does d3 reach `0x01`
   while d1 bit6 never strobes (⇒ the path does not exist, and injection is *necessary*)?
2. **Re-audit "unreachable / no callers" findings** (open item 26) with the forwards fallthrough
   walk (`tx_pack_stage.md` §3.1). `getCalledFunctions()` truncates at sweep block boundaries, so
   every reachability measurement taken before layer 29 is a lower bound.
3. **Determine which paired control block is live** per bus (§19.4) — still **required before any
   record-level patch**; frame-image addresses are shared and safe.
4. **Decode the remaining request words** (open item 32) — `APP_req_word_68`/`6C`/`74` are mapped
   per bit but unnamed; `68`'s value bits 5/7/8 are the most contended in the image and are the
   natural handle on the body-feature layer.
5. **Decode the pack-spec** into `(start_bit, length, byte_order, scaling)` — ⚠ read §16.1 first:
   three models have been refuted and the inherited 20-byte parse is misaligned (§7.6).
6. **Locate MSX's control block** (§20.3) — its 23 RX records are scattered, not arrayed.
7. **Optional:** frame periods / TX cycle times (0x90-stride records near `0x146060`); signal
   defaults and timeout values (F124 @`0xC000`).

---

## 9. Script index (`work/`)

**Pipeline (no Ghidra; operate on `work/flash_merged.bin`, big-endian):**
`vbf_extract.py`, `crc_check.py`, `crc32_check.py`, `build_image.py`.

**Gateway struct scanners:** `gw_mbfull.py` / `gw_mblist.py` (ID filter lists — authoritative),
`gw_nettbl.py` (master net table), `gw_rxdesc.py` (reception descriptors), `gw_shared.py` (shared
signal-RAM), `gw_membership.py` (frameObj groups — **counts only**, §7.3), `decode_baud.py` /
`decode_ctrl.py` (baud), `gw_sig*.py` (signal descriptors), `gw_targets.py` (records by would-be ID).

⚠ Superseded, kept only for historical comparison: `gw_aligned.py` / `gw_route20.py` (the misaligned
**20-byte** routing-record parse, §7.6 — output `aligned_records.txt`), `gw_forward.py` (same-ID
pairs, §7.1), `gw_test_spec1.py` (the script that *disproved* `spec1 = id<<18`, §7.2).

**pyghidra (need `.venv`):** `gw_dec.py` (decompile), `gw_mkfunc*.py` (create functions),
`gw_refs*.py` (xrefs), `pg_*.py` (setup/analyze/state helpers), `gw_findcan.py` (proved no FlexCAN
immediates).

**ACC-FIX build (`work/acc-fix/`):** `build_caves.py` → `build_vbf.py` → `verify.py` →
`annotate_ghidra.py`, plus `patch_blobs.json` and the artifact `JV6T-14C094-AD_acc-fix.VBF`. Integrity
helpers used by the build live in `work/`: `find_algo.py`, `check_internal.py`, `vbf_crc_validate.py`,
`cmp_ab_ad.py`. See §5.4 / `docs/acc-fix.md` / `AGENTS.md`.

**RKE-LOCK build (`work/rke-lock/`):** `build_caves.py` → `build_vbf.py` → `verify.py`, plus
`patch_blobs.json` and the **combined** artifact `JV6T-14C094-AD_accfix-rkelock.VBF` (acc-fix +
rke-lock in one VBF). RE helper scripts used while deriving the mod (all read-only, operate on
`flash_merged.bin` / candump logs): `rke_field.py`, `rke_rxdesc.py`, `rke_coderefs.py`,
`rke_bandrefs.py`, `rke_txwalk.py`, `rke_3a.py`, `rke_cavespace.py`. See §5.5 / `docs/rke-lock.md`.

**Owner full-flash analysis (`work/owner/`, ~120 numbered scripts + helpers):** operate on
`backups/owner-backup-20260911T090300Z/cflash.bin` and the `ghidra_proj_fullflash` project. Numbered in
execution order — `00`–`07` project setup and analysis, `09`–`24` signal planes, `25`–`27` CAN/DB
cross-reference, `28`–`40` dispatch tables and the diagnostic layer, `41`–`46` memory architecture,
`47`–`53` the validity layer, `54`–`61` the CAN codec, `62`–`72` the descriptor chain, `73`–`79`
routing records, `80`–`88` the RX/TX frame maps, `89`–`98` per-net binding and MSX,
`110`–`171` coverage sweep / pads / discrete inputs / signal dictionaries,
**`241`–`245`, `177`–`187` the TX pack stage and the body-control request bus** (layers 29–30, see
`docs/tx_pack_stage.md`).

Key reusable helpers, not tied to one pass:

| Script | Purpose |
|---|---|
| `gq.py` | read-only query helper — `dec` / `dis` / `xref` / `funcs` / `stats` |
| `dump.py` | hex dump by address range |
| `36_force_functions.py` | force-create functions Ghidra never discovered (see §11.1/§14.1 of the doc — this exposed two whole subsystems) |
| `verify_pass.sh` | annotation read-back + proprietary-identifier leak check |
| `leak_check.py` | greps 2,294 vehicle-DB identifiers against `work/owner/` and `docs/` |
| `99_project_audit.py` | full project audit: analysed flag, symbol counts, bookmarks, key-address check |

Full index of outputs: `docs/owner_artifacts.md`. Reproduce sequence: `docs/owner_flash_layers.md` §27.

---

## 10. Environment quick-reference
- Repo: `/home/gl/Projects/ford/BCM/Research`
- Ghidra: `/opt/ghidra` (12.1.2); pyghidra venv: `./.venv` (`. .venv/bin/activate`)
- Owner project (**primary**): `ghidra_proj_fullflash/BCM_OwnerFlash` on `cflash.bin`
- Mod-build project: `ghidra_proj/BCM_C1MCA` on `work/flash_merged.bin`
- Never mix the two: the owner image contains everything below `0xC000` (incl. the PBL); the merged
  VBF image does not.
- Always verify against real tool output; keep the (a)/(b)/(c) evidence discipline; cite addresses.
