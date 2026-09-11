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
- ✅ Ghidra project created, VLE-disassembled, auto-analyzed (~129k instr, ~2229 funcs).
- ✅ Gateway architecture understood: **table-driven Volcano network database**, not hand-coded.
- ✅ Complete per-bus CAN-ID inventory (RX/TX) extracted from FlexCAN acceptance filters.
- ✅ One cross-bus signal link **proven**: HS `0x0C0` → MS `0x020` (shared signal-RAM).
- ⚠️ **Key open item:** the `frameObj → CAN-ID` binding is NOT yet resolved. Without it, per-ID
  routing/forwarding and per-ID signal membership cannot be stated exhaustively.
- ✅ **Shipped modification `acc-fix`** (on-vehicle proven): remaps the new SWM steering-wheel
  cruise buttons in TX HS-CAN `0x030` so the old PCM understands them. See **§5.4** and
  **`docs/acc-fix.md`** + **`AGENTS.md`** (porting guide for other OEM BCM versions).
- ✅ **Shipped modification `rke-lock`** (on-vehicle proven): lets the remote key **lock the car with
  the ignition ON** (stock BCM blocks it), gated on **key-outside**. TX-mailbox injection on MS-CAN
  `0x3A` (lock-command byte), layered into the same caves as acc-fix → **one combined VBF**. See **§5.5** and
  **`docs/rke-lock.md`**.
- ❗ **Retracted mistakes** (do not repeat — see §7): "same-ID on both buses = forwarding" is FALSE;
  "spec1 = id<<18" is FALSE; "frameObj numeric range = bus" is FALSE.

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

Helper scripts (in `work/`): `cmp_ab_ad.py` / `diff_ab_ad.py` (OEM version diff), `hunt_cksum.py`
/ `hunt_const.py` / `find_algo.py` (integrity-word hunt), `check_internal.py` (validate layer 3),
`build_resplus.py` (patch + repair all three layers), `verify_resplus.py` / `diff_resplus.py`
(re-parse, decode, differential audit). Whatever flashing/repack step is used must deliver the app
block **byte-exact** (no re-alignment/re-padding) or the `sum8` drifts again.

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

- **Location:** `ghidra_proj/` — project `BCM_C1MCA`, program `flash_merged.bin`.
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
data in the F10A block, walked at runtime (`FUN_0004471a → FUN_000fbc48(&PTR_00140000)`). **Proof:**
no CAN-ID and no FlexCAN base appears as a code immediate anywhere (a).

Table stack (details + byte layouts in `docs/gateway_map_format.md`):
```
[1] Master net table 0x178B0  (0x5C/rec)  → +0x04 controller descriptor
[2] Controller desc 0x1464E0/0x146900/0x146C50  FlexCAN base, CTRL/baud, +0x44 → RX desc table
[3] MB acceptance/ID filter list 0x146530/0x146950/0x146CA0  (12B: [id<<18][dir 0x04=RX/0x08=TX][mask])
[4] Reception descriptors 0x18000  (32B: …[handler→routing rec @+0x0C]…[frame-image RAM @+0x18])
[5] Signal-routing records 0x140000–0x15BF00  (20B: [sigA][sigB][frameObj][spec1][spec2])
[6] Signal descriptors 0x15A920 (24B) + defaults in F124@0xC000
```

**Signal-routing record (20 B, the core map):** `[sigA src signal-RAM][sigB dst signal-RAM][frameObj]
[spec1 pack-spec][spec2 pack-spec]`. (Note field order: the reception-descriptor handler pointer
lands on `sigA`; `frameObj` is the 3rd word = handler+8.) Signals live in RAM `0x40000600–0x40000D2F`.

**Codec code (a):** RX copier `FUN_000fc63e` (MB→frame-image), TX packer `FUN_000fc218`/`FUN_000fc2f6`
(frame-image→MB), net bring-up `FUN_000fbc48`.

**Gateway translation = shared signal-RAM:** a cell written while unpacking an RX frame and read
while packing a TX frame. That is the ONLY reliable evidence of cross-bus content flow.
**Same CAN-ID number on both buses is NOT evidence of forwarding** (see §7).

---

## 5. Established results

### 5.1 Full per-bus CAN-ID inventory (authoritative, from MB filters) (b)
Run `python3 work/gw_mbfull.py`. Summary: **HS-CAN** 46 RX / 17 TX; **MS-CAN** 14 RX / 49 TX;
**MSX-CAN** obstacle IDs only (0x1xx/0x3xx/0x5xx/0x7xx). Full lists in
`docs/volcano_calibration_documentation.md` §3. Diag IDs seen: 0x72E, 0x7CC, 0x7CE.

### 5.2 Proven cross-bus signal link (b)
**HS-CAN 0x0C0 → MS-CAN 0x020**, via 7 shared signal-RAM cells
`0x40000751/774/77B/78A/78D/79F/7A1`. This is the answer to the original 0x0C0 half of the task.
The **0x060 path is not yet mapped** (its records were not isolated because the `spec1=id<<18`
assumption was wrong — see §7).

### 5.3 frameObj membership (record counts) (b)
`python3 work/gw_membership.py` groups all 1229 routing records by frameObj with signal counts.
⚠ The bus label in that table is a disproven heuristic (§7) — trust only the counts/spans.

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

## 6. Deliverable docs (in `docs/`)
- **`acc-fix.md`** — the shipped SWM cruise-button remap (§5.4): exact bit map, RES+ context gate,
  verified cave disassembly, integrity, reproduce steps. Porting guide: **`../AGENTS.md`**.
- **`rke-lock.md`** — the shipped RKE lock-with-ignition-on mod (§5.5): signals, one-shot strobe
  mechanism, combined-VBF build, on-vehicle design history. Evidence notes below.
- **`rke_0x100_lock.md`** — RKE button decode on MS `0x100` (lock/unlock bits, key-outside bit).
- **`ign_powermode_0x80.md`** — ignition/power state (`0x80` d2 field, `0x3A0` ignition-status frame), from captures.
- **`clockcmd_0x3a.md`** — central-lock command (`0x3A` d3) + full RKE→lock chain evidence, from captures.
- **`key_outside_gate.md`** — key-outside gate derivation + complete v1→v2→v3 design/debug history.
- **`0c0_standby_read.md`** — how the `0x0C0` cruise-status read address (`0x40000707`) was proven.
- **`030_composition_trace.md`** — `0x030` composition + LIN→button chain (why injection was needed).
- **`volcano_calibration_documentation.md`** — master reference: file layout, table architecture,
  full CAN-ID inventory, routing, signal↔frame membership, proven-vs-open. **Start here.**
- **`gateway_map_format.md`** — exact byte layouts of every table (for re-parsing/extending).
- **`gateway_id_interaction_map.md`** — HS↔MS ID interaction, with the forwarding caveat.
- **`gateway_map_current.md`** — signal-level notes on the 0x0C0→0x020 link.
- `work/gateway_translation_report.md` — earlier detailed checkpoint (some claims since corrected;
  cross-check against the docs above).

---

## 7. ⚠️ Retracted assumptions — DO NOT REPEAT

1. **"Same CAN-ID appearing RX-on-one-bus and TX-on-other = forwarding" — FALSE.** It is
   acceptance-filter coincidence. Verified: no shared signal-RAM between the HS-receive and
   MS-transmit paths for these IDs. The BCM **independently consumes** the incoming frame and
   **independently builds its own same-numbered frame** on the other bus (user-confirmed for `0x040`).
   Only prove a forward via **shared signal-RAM** through the descriptor chain.
2. **"spec1 (routing record +0x0C… word) = CAN_id << 18" — FALSE.** Measured `(spec1>>18)` matches
   the bus ID list only 23.8 % (chance level; `work/gw_test_spec1.py`). `spec1` is a pack/conversion
   spec. CAN IDs come from tables [3]/[4], never from routing records.
3. **"frameObj numeric range = bus" — FALSE.** Ranges are not bus-exclusive; e.g. `0x400004FC`
   (once mislabeled "MS") appears on the **HS receive path** in the reception descriptors.

---

## 8. Recommended next steps (resume here)

1. **Resolve `frameObj → CAN-ID` binding** (the master key). Parse the reception-descriptor tables at
   `ctrlDesc+0x44` (HS @0x18000; find MS/MSX equivalents) — each 32-byte record ties an MB (hence
   CAN ID, in filter-list order) → frame-image RAM (`0x40007Axx`) → routing-record handler → frameObj.
   Once bound, every routing record gets a real (bus, CAN-ID); then:
2. **Rebuild the true forwarding map** by intersecting shared signal-RAM between RX-path and TX-path
   frameObjs per ID (extend `work/gw_shared.py`). Confirm/deny each same-ID pair as real vs independent.
3. **Map the 0x060 path** the same way as 0x0C0.
4. **Decode `spec1`/`spec2`** fully into (start_bit, length, byte_order, scaling) — use the 24-byte
   descriptor table at `0x15A920` (proven bitmask=high byte of spec2) and the codec bit-loops in
   `FUN_000fc63e` / `FUN_000fc218` as ground truth.
5. **Optional extras:** frame periods/TX cycle times (0x90-stride records near 0x146060); signal
   defaults/timeout values (F124@0xC000). End goal: a full **signal map** export
   for both buses, reconstructed from the firmware's own embedded routing tables.

---

## 9. Script index (`work/`, 51 scripts)
Struct scanners (no Ghidra; operate on `flash_merged.bin`, big-endian):
`vbf_extract, crc_check, crc32_check, build_image` (pipeline);
`gw_mbfull`/`gw_mblist` (ID filter lists), `gw_nettbl` (master net table), `gw_aligned`
(routing records → `aligned_records.txt`), `gw_membership` (frameObj groups), `gw_shared`
(shared sigRAM), `gw_forward` (same-ID pairs — see §7 caveat), `gw_rxdesc` (reception descriptors),
`gw_test_spec1` (disproves spec1=id<<18), `decode_baud`/`decode_ctrl` (baud), `gw_sig*` (24/28-byte
signal descriptors), `gw_targets` (records by would-be ID).
pyghidra (need `.venv`): `gw_dec` (decompile), `gw_mkfunc*` (create funcs), `gw_refs*` (xrefs),
`pg_*` (setup/analyze/state helpers), `gw_findcan` (proved no FlexCAN immediates).
Data outputs: `aligned_records.txt`, `routing_records.txt`, `sig24.txt`, `sig_desc*.txt`, `allframes.txt`.

**ACC-FIX build (`work/acc-fix/`):** `build_caves.py` → `build_vbf.py` → `verify.py` →
`annotate_ghidra.py`, plus `patch_blobs.json` and the artifact `JV6T-14C094-AD_acc-fix.VBF`. Integrity
helpers used by the build live in `work/`: `find_algo.py`, `check_internal.py`, `vbf_crc_validate.py`,
`cmp_ab_ad.py`. See §5.4 / `docs/acc-fix.md` / `AGENTS.md`.

**RKE-LOCK build (`work/rke-lock/`):** `build_caves.py` → `build_vbf.py` → `verify.py`, plus
`patch_blobs.json` and the **combined** artifact `JV6T-14C094-AD_accfix-rkelock.VBF` (acc-fix +
rke-lock in one VBF). RE helper scripts used while deriving the mod (all read-only, operate on
`flash_merged.bin` / candump logs): `rke_field.py`, `rke_rxdesc.py`, `rke_coderefs.py`,
`rke_bandrefs.py`, `rke_txwalk.py`, `rke_3a.py`, `rke_cavespace.py`. See §5.5 / `docs/rke-lock.md`.

---

## 10. Environment quick-reference
- Repo: `/home/gl/Projects/ford/BCM/Research`
- Ghidra: `/opt/ghidra` (12.1.2); pyghidra venv: `./.venv` (`. .venv/bin/activate`)
- Merged image: `work/flash_merged.bin` · Ghidra project: `ghidra_proj/BCM_C1MCA`
- Always verify against real tool output; keep the (a)/(b)/(c) evidence discipline; cite addresses.
