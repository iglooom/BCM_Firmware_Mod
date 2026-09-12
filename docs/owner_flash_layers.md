# Owner full-flash Ghidra project — layer-by-layer analysis

Analysis of `backups/owner-backup-20260911T090300Z/` in a **new** Ghidra project built from the
module's *real* nonvolatile memory rather than from merged OEM VBF blocks.

| | |
|---|---|
| Project | `ghidra_proj_fullflash/` · `BCM_OwnerFlash` · program `cflash.bin` |
| Language | `PowerPC:BE:64:VLE-32addr` (e200z0h, big-endian, VLE-only) |
| Build script | `work/owner/00_create_project.py` |
| Analysis | `work/owner/01_analyze.py` → **116 073 instructions / 2 398 functions** |
| Annotations | `work/owner/03_annotate_l0_l1.py`, verified by `04_verify_annotations.py` |

**Why a new project.** `ghidra_proj/` was built from `work/flash_merged.bin`, which is the *OEM VBF
set* re-assembled. It therefore contains **nothing below `0xC000`** — the 48 KB primary bootloader
simply did not exist in it, because no OEM VBF ships the PBL. It also lacks the shadow array, the
DFlash, and the owner module's four differing configuration bytes. Everything in §2 below is
invisible in the old project.

Evidence tags follow the project convention: **(a)** decompiled-code proof · **(b)** validated table
structure · **(c)** inference.

---

## 0. Memory map as actually captured

`work/owner/recon_layout.py`. Blocks created in the project:

| Block | Range | Source | Notes |
|---|---|---|---|
| `CFLASH` | `0x00000000–0x0017FFFF` | `cflash.bin` | RX, executable |
| `SHADOW` | `0x00200000–0x00203FFF` | `shadow.bin` | NV option/censorship words |
| `DFLASH` | `0x00800000–0x0080FFFF` | `dflash.bin` | EEPROM emulation |
| `SRAM` | `0x40000000–0x40017FFF` | uninitialised | 96 KB on-chip |
| `PBRIDGE_A` | `0xC3F00000–0xC3FFFFFF` | uninitialised | SIUL, MC_*, flash cfg, eMIOS |
| `PBRIDGE_B` | `0xFFE00000–0xFFFFFFFF` | uninitialised | FlexCAN, LINFlex, DSPI, ADC |

Both peripheral bridges are marked *volatile* so the decompiler does not fold repeated reads.

### 0.1 Content map of CFlash

```
0x000000–0x00BFFF   PRIMARY BOOTLOADER   FORD-PBL-V013 / DV6T-14C245-FF   <- new in this project
0x00C000–0x00FFFF   Cal F124             JV6T-14C095-AB  (byte-identical to the OEM VBF)
0x010000–0x13FFFF   Application          JV6T-14C094-AD  (+4 owner config bytes)
0x140000–0x15BF4B   Cal F10A             JV6T-14C403-AB  (Volcano CAN database)
0x15BF4C–0x17FFFF   erased (0xFF)        beyond every VBF
```

Fill statistics show the app region `0x120000–0x13FFDF` is **100 % `0xFF`** — that is the padding
the `acc-fix`/`rke-lock` code caves live in, and it is inside the `sum8` domain.

### 0.2 Two boot headers, and only two

A brute scan of every boot-sector start finds exactly two valid RCHWs:

| Address | Halfword | Entry | Meaning |
|---|---|---|---|
| `0x000000` | `0x005A` | `0x00000160` | **PBL** — the BAM finds this first, so the PBL owns reset |
| `0x010000` | `0x005A` | `0x0010F4A0` | **Application** |

Note the two differ in their second halfword: the PBL's word is `005A0000`, the application's is
`005A005A`. That is not cosmetic — the PBL's own validity test reads the application word and
compares it against `0x005A005A` (§2.5). **(a)**

### 0.3 Integrity, recomputed from the capture

```
sum8(0x10000 .. 0x13FFFE) = 0x75A5   stored @0x13FFFE = 0x75A5   guard @0x13FFFC = 0xFFFF   ✅
```
Labelled `APP_internal_checksum`. OEM `-AD` stores `0x7572`; the owner's four configuration bytes
sum to +51 and `0x75A5 − 0x7572 = 51`, so the image satisfies the firmware's own algorithm. This is
the layer that boots the BCM into a software-integrity fault if left stale. **(a)**

---

## 1. What the old project could not see

The PBL contributes **110 functions** and ~6 550 instructions that were entirely absent before.
Section 2 is all new ground.

---

## 2. Layer 1 — the primary bootloader

### 2.1 Reset path

```
PBL_reset_entry            0x000160   (from PBL_RCHW+4)
 ├─ PBL_hw_init            0x0008D8   watchdog off, mode/clock, conditional SRAM wipe
 ├─ PBL_check_warm_reentry 0x00086C   honours an app-requested warm handoff
 ├─ copy 8 bytes 0x43E0 → 0x4000F800  (boot-status signature)
 └─ PBL_main_loop          0x0023C8   never returns
```

**`PBL_hw_init` decoded register-by-register (a):**

| Write | Register | Effect |
|---|---|---|
| `0xFFF38010 ← 0xC520, 0xD928` then `SWT_CR &= ~1` | SWT | **software watchdog disabled for the whole PBL** |
| `0xC3FE8008/800C ← 0x5FF` | MC_PCU | power-domain config |
| `0xC3FDC000/004/00C` `0x5AF0`/`0xA50F` | MC_ME | DRUN mode transition key sequence |
| `0xC3FE00A0 ← 0x9240012` or `0x8240012` | MC_CGM | 16 MHz vs 8 MHz, selected by hook `PBL7` |
| `0xC3FE4002` read | **MC_RGM RGM_DES** | reset-cause discrimination — see below |

The test `(RGM_DES & 0x800B) == 0` is exactly the reference manual's *"was this a power-on?"*
question: those bits are `F_POR | F_LVD27_VREG | F_LVD27 | F_LVD12_PD0`. RM0037 §9.3.1.2 even
instructs software to treat any of them as power-on. Consequences:

- **Cold reset** → SRAM `0x40002000–0x40013FFF` is wiped with `0xFFFFFFFF`, and both warm-entry
  magics are cleared. A stale RAM pattern can therefore never fake a warm re-entry.
- **Warm reset** → SRAM is trusted and the handoff protocol below runs.

Either way `0x400117F0–0x40012ADF` is zeroed. *(Adjacent to `0x40011000`/`0x40011001`, the scratch
latch bytes used by `acc-fix`/`rke-lock` — see §5.)*

### 2.2 The application→bootloader handoff protocol (a)

`PBL_boot_mode_arbitration` @ `0x000750`:

```c
0x4000F800 = 2;                        // boot-status mailbox
if (*(u32*)0x40013FFC == 0x5555AAAA) { // the app's "reprogram me" request
    *(u32*)0x40013FFC = 0;
    PBL_enter_programming();           // STAY IN THE LOADER
} else if (PBL_try_custom_reentry(&0x40013FFC)) {
    ctx[0x13] = 1; ctx[0x3AB] = word; ctx[0x14] = 1;
}
```

`PBL_try_custom_reentry` @ `0x3D20` defers to the `PBLG` hook @ `0x773C`, which is a **three-value
whitelist**:

```c
if (w == 0xAAE01751 || w == 0xAAE01741 || w == 0xAADA0100) { pulse_transceiver(0x2F50); return 1; }
return 0;
```

A second, independent magic (`0x40000028 == 0x78945612`) gates the `PBLC` warm-entry handler in
`PBL_check_warm_reentry`. Labelled `PBL_reentry_request_magic` and `PBL_warm_entry_magic`.

**Practical meaning for this project:** the documented "flash the SBL, then call it" route is not the
only door into the loader. A running application can request the loader via a single SRAM word plus
a warm reset — and the magic values are now known. Both magics are wiped on power-on, so this is a
deliberate handoff channel, not an accident.

### 2.3 The download address-permission table (b, cross-validated a)

`PBL_region_permission_table` @ `0x0001C0` — 12-byte records `[start][end][flag]`:

| start | end | flag | region |
|---|---|---|---|
| `0x00000000` | `0x00007FFF` | **0** | the PBL itself — **refused** |
| `0x00008000` | `0x0017FFFF` | 4 | calibration + application — programmable |
| `0x00800000` | `0x0080FFFF` | 4 | DFlash — programmable |
| `0x40000000` | `0x40001FFF` | 0 | SRAM low — loader's own state |
| `0x40002000` | `0x4000F7FF` | **1** | **SRAM download window** |
| `0x4000F800` | `0x40013FFF` | 0 | SRAM high — loader's own state |

The flag semantics are proven, not guessed: the OEM SBL `DV6T-14C097-AB.vbf` header declares
`call = 0x40002000`, which is *exactly* the start of the single `flag=1` region. So `1` = "RAM, may
receive a downloaded loader and be executed", `4` = "flash, may be erased/programmed", `0` = refused.

This table is the structural reason the PBL cannot be overwritten through the normal download path,
and it independently explains why the custom SRAM backup reader had to be placed at `0x40006000`
(inside the window) rather than anywhere convenient.

### 2.4 The tagged extension table (b)

`PBL_extension_hook_table` @ `0x006C00` — 8-byte entries `[4-char tag][u32 value]`. Every consumer
guards with `if (tag == 'PBLn')` **before** dereferencing, so an absent tag silently disables that
feature. It is a forward-compatible plug-in table, which is why one PBL binary serves several
vehicle programs.

| Tag | Value | Role |
|---|---|---|
| `PBL1` | `0x006E00` | pads/boot-mode entry callback |
| `PBL2` | `0x007132` | protocol callback |
| `PBL3` | `0x0072A8` | early init: pads + CAN + input shadow |
| `PBL4` | `0x0074E8` | periodic: input rising edge → force reset |
| `PBL5` | `0x00320000` | scalar → `ctx[0x1D8]` timer |
| `PBL6` | `0x0074CE` | "is the application image valid?" |
| `PBL7` | `0x10000000` | high byte `0x10` = 16 MHz (`0x08` would select 8 MHz) |
| `PBL8` | `0x01000000` | scalar |
| `PBL9` / `PBLA` | `0x0075BA` / `0x0076EC` | — |
| `PBLB` | `0x0FA00000` | scalar → `ctx[0xEA8]` |
| `PBLC` | `0x00010008` | warm-entry handler slot → `ctx[0xEA4]` |
| `PBLD`/`PBLE`/`PBLF` | `0x006F98`/`0x007288`/`0x007298` | PD14 low / PD14 high |
| `PBLG` | `0x00773C` | re-entry magic whitelist |

### 2.5 Application validity gate (a)

```c
bool PBL_app_image_is_valid(void) { return *(u32*)0x00010000 == 0x005A005A; }
```
A blank or erased application keeps the PBL resident — the module stays recoverable.

### 2.6 Other PBL structures

- `PBL_flexcan_base_table` @ `0x000224` — CAN_0…CAN_5 bases; only the first three are bonded out.
- `PBL_crc16_ccitt_table` @ `0x00023C` — 256 × u16 BE, poly `0x1021`, verified byte-exact against a
  generated table. **Same algorithm as the VBF per-block checksum**, so the loader validates each
  downloaded block with the container's own CRC. A second identical copy sits in the application at
  `0x016360`.
- `PBL_diag_config_record` @ `0x006B00` — the `0x726` diagnostic address seen in every VBF header is
  read from *here*, not hardcoded.
- `VEHICLE_VIN_record` @ `0x008000` — CRLF-delimited ASCII inside the PBL's own sector. Not part of
  any VBF, i.e. written at end of line.

---

## 3. ⚠ Correction: the PBL *does* configure SIUL pads

`docs/owner_backup_analysis.md` §2 states **"SIUL (any pad register): 0 refs"** and concludes the PBL
configures no pins. That document itself flagged the caveat — it was *"a literal scan, the same
method that previously missed the WKPU and the PWM driver."* The caveat was right.

`work/owner/02_periph_scan.py` asks Ghidra for the **resolved reference target of every
instruction**, so addresses built with `e_lis` + `e_add16i` are caught. Result for the PBL:

```
  48  SIUL        31  MC_ME       15  DSPI_1      10  MC_CGM       7  STM
   4  SWT          3  FLASH cfg    3  MC_RGM       3  DSPI_0       3  INTC       2  MC_PCU
```

**24 distinct pads** are configured. `PBL_pads_init` @ `0x0072FC` (a):

| Function | Pads |
|---|---|
| Outputs (OBE, `PCR←0x0200`) | PD14, PI5, PJ1, PG11, PC2, PH13, PH11 |
| Inputs (IBE, `PCR←0x0500`) | PB10, PD9, PD0, PB1, PC11, PE9 |
| Alternate function (`0x0600`) | PB0, PC10, PE8, PA14, PA13 |
| Other | PA12 `0x0100`, PB14 `0x0E00`, PH0 `0x0100`, PH1/2/3 `0x0A00` |

It also writes PSMI bytes at SIUL `0x500`/`0x501`/`0x508` (input-function pad select).

### 3.1 The PI15 / PF12 conclusion still holds — now for a better reason

Neither **PI15 (PCR143)** nor **PF12 (PCR92)** appears anywhere in the PBL's 48 SIUL accesses. The
same instruction-level scan across the **application** finds only three pads touched at all —
PA0, PB2, PB3. So the conclusion of `interior_button_gpio_trace.md` survives, but it now rests on a
scan that provably *can* see `e_lis`-built addresses, rather than on a null literal result. That is a
materially stronger negative.

### 3.2 New: three pads are a hardware programming interlock (a)

`PBL_hook4_input_watchdog` @ `0x0074E8`, wired in as hook `PBL4`:

```c
if (GPDI[26] /*PB10*/ == 1 && shadow_PB10 == 0) PBL_force_reset();
if (GPDI[57] /*PD9*/  == 1 && shadow_PD9  == 0) PBL_force_reset();
if (GPDI[48] /*PD0*/  == 1 && shadow_PD0  == 0) PBL_force_reset();
shadow_PB10 = GPDI[26]; shadow_PD9 = GPDI[57]; shadow_PD0 = GPDI[48];
```

`PBL_force_reset` @ `0x7788` writes `MC_ME_MCTL ← 0x5AF0, 0xA50F` with target mode 0 — an immediate
functional reset. So **PB10 / PD9 / PD0 are an abort interlock: a rising edge on any of them during
programming resets the module.** The shadows are labelled `PBL_input_shadow_PB10/PD9/PD0`.

This is operationally relevant to the SBL/backup workflow: an unexplained mid-transfer reset is not
necessarily a watchdog or a protocol fault — it can be one of these three pins twitching.

### 3.3 Transceiver control lines (c, structurally strong)

`PBL_pads_bootmode` @ `0x006E00` (hook `PBL1`) sequences PG11↑, PC2↑, 20 × SPI pulse,
`PBL_transceiver_config()`, PJ1↑, PI5↑, PC2↓, and `PBL_transceiver_config` @ `0x6FCC` pushes command
word `0x777377` over DSPI. Given the UJA1078A on this board, PG11/PC2/PJ1/PI5 are its
enable/inhibit/wake/standby lines. Marked inferred — no scope proof yet.

---

## 4. Shadow array and DFlash

- **`SHADOW_nv_config` @ `0x200000`** — 17 non-`0xFF` bytes in 16 KB, and they are **not** erased
  padding: they are the censorship control words, holding the **uncensored** values.

  | Shadow offset | Register | Value | Meaning |
  |---|---|---|---|
  | `0x203DD8` | `NVPWD0/1` | `FEEDFACE CAFEBEEF` | the documented **factory-default** password |
  | `0x203DE0` | `NVSCC0/1` | `55AA55AA 55AA55AA` | censorship **disabled** |
  | `0x203E18` | — | `DF` | single byte, unidentified |

  `NVHWOPT` and `NVBIU0/1` *are* erased. The MCU is therefore **not censored**: the JTAG/Nexus port is
  open and not password-locked, so an independent hardware readout is available as a cross-check on
  the CAN-based dump — **and as a recovery path if a bootloader-block write ever fails** (§21.4).

  > **Correction (was wrong here until §21 review):** an earlier version of this section said these
  > words were "all erased" and called the pattern a manufacturing artefact. That was backwards and
  > self-contradicting — on this part censorship is *disabled* by `NVSCC = 0x55AA55AA`, so an
  > **erased** `0xFFFFFFFF` would mean the device is **censored**. The values being present is
  > precisely what makes JTAG open. The conclusion was right; the evidence cited for it was wrong.
- **`DFLASH_wear_record_0` @ `0x800000`** — 32 of 65 536 bytes used, as four 8-byte records with a
  uniform `F1000100` header, an incrementing counter (05, 06, 07, 08) and a trailing checksum. This
  is EEPROM-emulation wear levelling. **There is no variant coding in DFlash.** Re-derived
  independently in §12.4, which additionally shows the trailer is **not** CRC-16/CCITT over any
  prefix (unlike the PBL's block checks) and confirms, from §12.2, that the module's persistent state
  lives in **retained RAM**, not NVM.

---

## 5. Owner-specific delta, in context

`OWNER_gateway_routing_record` @ `0x0015BE00` is labelled and commented. App record `0x017C90 +0x1C`
points here; the OEM points at `0x00141C74`, which in the OEM image is populated and in the owner's
is a relocated single-entry list with the mask changed `0x40 → 0x80`. `0x4000081C` / `0x400002E0`
are gateway signal-RAM cells. **Reflashing stock `-AD` would revert this routing variant** — worth
knowing before any future flash of this module.

---

## 6. Layer 2 — the PBL's UDS diagnostic stack

This was the top open item from the first pass. It is now fully resolved.

### 6.1 The dispatcher (a)

`PBL_uds_dispatch` @ `0x002288` reads the request SID from `ctx+0x238` and branches:

| SID | Handler | SID | Handler |
|---|---|---|---|
| `0x10` DiagnosticSessionControl | `0x1AE4` | `0x31` RoutineControl | `0x29AA` |
| `0x11` ECUReset | `0x2738` | `0x34` RequestDownload | **`0x2F3A`** |
| `0x19` ReadDTCInformation | `0x3C7E` | `0x35` RequestUpload | **`0x2F3A`** |
| `0x22` ReadDataByIdentifier | `0x2DD6` | `0x36` TransferData | `0x30C0` / `0x33BA` |
| `0x27` SecurityAccess | `0x35B8` | `0x37` RequestTransferExit | `0x38AA` |
| `0x3E` TesterPresent | `0x3A08` | | |

Reached from `PBL_main_loop` via a 19-entry task table at `0x000700` (`PBL_task_table`).

### 6.2 The service-permission table (b)

`PBL_service_permission_table` @ `0x00043C` — 12 records × `0x18` bytes, `sid==0` terminator.
Field meanings derived from `PBL_service_table_walk`'s own offsets:

| SID | Service | sup | subfunc | session | security | addressing |
|---|---|---|---|---|---|---|
| `0x10` | DiagnosticSessionControl | 0 | `0x02` | – | – | – |
| `0x11` | ECUReset | 0 | `0x02` | – | – | – |
| `0x27` | SecurityAccess | 0 | any | ✔ | – | – |
| `0x22` | ReadDataByIdentifier | 0 | any | – | – | – |
| `0x3E` | TesterPresent | 0 | `0x02` | – | – | – |
| `0x2E` | WriteDataByIdentifier | 2 | any | ✔ | ✔ | ✔ |
| `0x31` | RoutineControl | 2 | any | ✔ | – | – |
| `0x34` | **RequestDownload** | 1 | `0x0B` | ✔ | ✔ | – |
| `0x35` | **RequestUpload** | 1 | `0x0B` | ✔ | ✔ | ✔ |
| `0x36` | TransferData | 2 | any | ✔ | – | – |
| `0x37` | RequestTransferExit | 0 | `0x01` | ✔ | ✔ | – |
| `0x19` | ReadDTCInformation | 0 | any | – | – | – |

**This is the complete service set.** `0x23 ReadMemoryByAddress` appears neither here nor in the
dispatcher — so the *primary* loader has no `0x23` either, exactly like the secondary loader
(`docs/sbl-DV6T-14C097-AB.md` §2).

### 6.3 `0x34` and `0x35` share one handler (a)

`PBL_svc_request_transfer` @ `0x2F3A` serves **both**. The dispatcher's `bVar1 < 0x36` arm falls
through to the same function, and direction is chosen *inside* by testing the literal request byte
against ASCII `'4'`:

```c
addr = be32(req[0x23B..0x23E]);  size = be32(req[0x23F..0x242]);
ok = PBL_check_address_permission(ctx, addr, size, ctx[0x38], /*isDownload=*/ reqByte=='4');
if (reqByte == 0x34) { ctx[8]=1;  /* DOWNLOAD */  maxBlock = 0x0C62; }
else                 { ctx[0xC]=1;/* UPLOAD   */  maxBlock = 0x0022; }
```

So — contrary to the secondary loader, where `0x35` only served a fixed sentinel — **the PBL's
RequestUpload is genuinely address-parameterised**, and `PBL_transfer_data_read` @ `0x33BA` is a real
read-out path delivering up to 32 bytes per TransferData with proper block-sequence handling.

### 6.4 …but a hook vetoes the addresses that matter (a)

`PBL_check_address_permission` @ `0x000D2C` is the gate for *every* memory operation:

1. overflow check on `addr+size-1`;
2. containment search of `PBL_region_permission_table`, yielding the region flag;
3. for downloads, alignment from `PBL_alignment_by_flag_table` @ `0x1B4` (flag 4 → 8-byte);
4. `ctx[0x38]==1` (flash ops) requires `flag != 1`, else requires `flag == 1` — i.e. a RAM-only
   session can touch **only** `0x40002000–0x4000F7FF`;
5. **upload-only final veto** — if the request byte is `'5'` and hook `PBLA` exists, the hook decides.

`PBL_upload_address_filter` @ `0x0076EC`, read from the **disassembly** (the decompiler renders the
`se_blt`/`se_bgt` pairs as strict inequalities; the bounds are actually *inclusive*):

```
ok = 0;  if (size == 0) return;
if (addr >= 0x008000 && addr <= 0x00BFFF && addr+size-1 <= 0x00BFFF) ok = 1;
if (addr >= 0x140000 && addr <= 0x17FFFF && addr+size-1 <= 0x17FFFF) ok = 1;
```

| Window | Contents | Uploadable? |
|---|---|---|
| `0x000000–0x007FFF` | PBL code | ❌ |
| `0x008000–0x00BFFF` | PBL sector tail + `VEHICLE_VIN_record` | ✅ |
| `0x00C000–0x00FFFF` | Cal F124 | ❌ |
| `0x010000–0x13FFFF` | **Application** | ❌ |
| `0x140000–0x17FFFF` | Cal F10A + erased tail | ✅ |

**Conclusion:** stock `0x35` cannot read out the application or the bootloader, which independently
justifies the custom SRAM reader used for the owner backup. It *can* legitimately read the **F10A
calibration block** and the VIN area — a supported, non-invasive route worth knowing.

### 6.5 Other services worth noting

- **`PBL_svc_routine_control` @ `0x29AA`** — routine `0x0301` validates a 4-byte address then stores
  it in `ctx[0x1E8]`; `PBL_response_pump` @ `0x2CB8` performs the deferred indirect **call**. That is
  the mechanism behind the SBL VBF's `call = 0x40002000`. Routine `0xFF01` is eraseMemory.
- **`PBL_svc_read_data_by_id_impl` @ `0x75BA`** (hook `PBL9`) — DIDs `0xD100`, `0xD12B`, `0xF111`
  (`DV6T-14C245-FF`), `0xF162`, `0xF180` (`FORD-PBL-V013`), **`0xF188` (`JV6T-14C094-AD`)**, `0xF18C`
  (`009640039386`). `0xF188` reads the *application's* part number out of the app block, so the PBL
  can report which app is installed while the app is not running.
- **`PBL_can_bringup` @ `0x7132`** (hook `PBL2`) — PIT enable, MC_ME RUN0 with a 10⁶-iteration
  timeout guard, INTC enable and clearing of 0xD9 priority slots.

---

## 7. Layer 3 — the application's top-level structure

Mapped top-down from the app's reset vector in this pass. Every step is decompile-verified.

### 7.1 Boot → main → scheduler (a)

```
APP_reset_entry            0x10F4A0   (from APP_RCHW+4)
 ├─ FUN_0010F570(&PTR_00021200)       early trampoline/table setup
 ├─ APP_clock_sram_init     0x2FDF2   MC_PCU, SWT, MC_ME/RUN0, MC_CGM, SRAM ECC paint
 ├─ FUN_0002FEC8                      (empty stub)
 ├─ .bss clear   0x4000549F..0x4000B06B
 ├─ .data copy   flash PTR_001156BC -> 0x40003A5C..0x40005492
 ├─ APP_stm_init            0x2FF70   STM channels 0..3 = the OS tick
 └─ APP_main                0x2F12E
```

`APP_reset_entry` wraps the whole thing in `do { ... } while(true)` — the "if main ever returns,
start over" idiom. The `.bss`/`.data`/SP/SDA values match `docs/scratch_ram.md` exactly, which
independently re-confirms that document's scratch-RAM reasoning.

**One notable contrast with the PBL:** `APP_clock_sram_init` writes `SWT_CR ← 0x8000011B` with
`TO = 64000` — the application **enables** the software watchdog, where the PBL disables it.

### 7.2 `APP_main` @ `0x2F12E` (a)

```c
APP_wake_init();          // 0x34D16  WKPU x6, MC_RGM x4, RTC/API
APP_mcu_driver_init();    // 0x32358  flash cfg, INTC, WKPU + 20 sub-inits
FUN_00050460(); FUN_0002E6F2(); APP_io_init(); FUN_00057A5E();
APP_can_gateway_init();   // 0x44A3E  <- Volcano/FlexCAN bring-up
APP_feature_init();       // 0x625FC  <- 83 body-feature modules
APP_os_activate_task(0..9);          // 10 OS tasks
APP_sched_lock_counter++;            // 0x400053E6
APP_os_start();           // 0xF7AE2  StartOS
APP_os_schedule();        // 0xF7504
```

### 7.3 The RTOS (a)/(b)

An OSEK/AUTOSAR-style kernel living in the `0xF7xxx–0xF9xxx` band:

| Item | Address | Notes |
|---|---|---|
| `APP_os_start` | `0xF7AE2` | walks a 12-entry NULL-terminated startup-hook table |
| `APP_os_startup_hooks` | `0x136D8` | `0xF76D2, 0xF848E, 0xF83BA, 0xF83F6, 0xF838C, 0xF852C, 0xF854C, 0xF8418, 0xF84D4, 0xF7AC2, 0xF8F8E, 0xF8FCC` |
| `APP_os_mode_hook_table` | `0x135E0` | 9 entries; `[0] = 0x2FBEE` is the app-mode hook |
| `APP_os_schedule` | `0xF7504` | ready-queue at `0x4000AB2C`/`0x4000AB28`, task-state byte `+0x1A`, context swap via `0x10F6C0`/`0x10F670` |
| `APP_os_activate_task` | `0x2F8C6` | TCB array `0x40004108`, **8-byte stride**, `+3` = state (3 → 2) |
| `APP_os_config_flags` | `0x13550` | `0x2DA`; bit5 pre-start, bit6 stack-guard, bit10 error hook |
| stack canary | `0x1356C → 0x4000B180` | sentinel `0xEBEBEBEB` |

### 7.4 The feature layer — 83 modules (b)

`APP_feature_init` @ `0x625FC` calls **83 distinct modules**, every one as `init(1)`. Profiling them
(`work/owner/16_feature_modules.py` → `feature_modules.json`) shows a rigid, generated structure:

- each module writes exactly **one 4-byte slot** in the dense array `0x40004D74..0x40004F14`
  (`APP_feature_handle_array`, ~104 slots);
- each module owns a state block in `0x40007F00..0x40009D40` (`APP_feature_state_region`);
- sizes span 59 → 1109 instructions (2-level deep count).

Largest modules, i.e. the richest features:

| Module | instrs (deep) | Module | instrs |
|---|---|---|---|
| `0x0C4DDE` | 1109 | `0x0A50FC` | 287 |
| `0x0AAC98` | 917 | `0x0B1D3E` | 242 |
| `0x0A5862` | 604 | `0x06A516` | 205 |
| `0x097A64` | 468 | `0x0AEFBC` | 143 |
| `0x0B4724` | 407 | `0x0C0AF0` | 132 |

### 7.5 ⚠ Negative result: features are fully decoupled from CAN

`work/owner/18_find_lock_module.py` walked all 83 modules to depth 3 looking for accesses to RX
signal cells, the RKE `0x100` frame image, the TX image pool, or LIN/DSPI/SIUL. Result: **none, for
every module.**

Three independent scans now agree that no application code addresses a CAN signal cell:

| Method | Result |
|---|---|
| per-cell xrefs over the whole signal band (earlier work) | 0 / 2048 |
| computed `e_lis`+offset targets (`10_resolve_lis_targets.py`) | 0 into signal bands |
| 83 feature modules, depth-3 walk (`18_find_lock_module.py`) | 0 |

This is a **structural fact about the architecture, not a dead end**: the Volcano layer moves wire
bytes into decoded signal cells, and features reach those cells through generated accessors keyed by
signal ID. It is also why the shipped `acc-fix`/`rke-lock` mods had to inject at the TX mailbox
rather than patch a feature's logic — and it means "find the central-lock `if`" cannot succeed as
posed. The productive route is the handle array (§7.4): it is the one place where module identity is
one-to-one with a memory slot.

## 8. Layer 4 — the signal plane (and a flag page that turned out to be something else)

§7.5 ended on a negative: features never touch CAN. This pass found **what they touch instead**, and
it turned out three earlier scans had been looking in the wrong SRAM band.

### 8.1 ⚠ Correction: the application signal plane is not where the gateway docs pointed

Scans 09/10/18 searched `0x40000600–0x40000E00` for "decoded signal cells", a band taken from the
older gateway notes. Decompiling a real periodic feature handler (`0x9F55A`) showed it reading and
writing entirely different addresses. A full SRAM usage map by 0x100 bucket
(`work/owner/21_sram_map.py`) then located the true layout:

| Region | Reads | Writes | Reader fns | Writer fns | Role |
|---|---|---|---|---|---|
| `0x40003C00–0x40003DFF` | 1203 | 639 | **265** | **127** | **main signal plane** |
| `0x40001E00` | 590 | 113 | 230 | 39 | shared signal plane |
| `0x40002800–0x40002CFF` | ~700 | ~560 | ~190 | ~170 | secondary plane |
| `0x40003E00` | 0 | 107 | 0 | 50 | write-only aggregates |
| `0x40002300` | 170 | 11 | 68 | 3 | broadcast inputs |
| `0x40006400–0x400064FF` | — | — | — | — | **change-flag bus** (§8.3) |

The Volcano cells at `0x4000_06xx` really do have zero static references — that finding stands. They
are simply not where feature logic lives.

### 8.2 The busiest signal in the firmware (a)

`APP_vehicle_mode_state` @ **`0x40001E38`** — **one producer, ~120 reader functions.** Nothing else
in the image comes close, which makes it a global vehicle mode/run-state and the natural precondition
for most body features.

Its producer, `APP_vehicle_mode_update` @ `0x2EDD0`, is gated on calibration byte `DAT_00008166`
(values 5/6), raises change flag `0x40006408 |= 8` **only on an actual transition**, then bulk-copies
one of two parameter sets into the `0x400057xx–0x400058xx` working area depending on
`DAT_4000246A` bit0 and `DAT_4000249A` bits[1:0]. *(The name is inferred from fan-out and producer
shape; not yet confirmed against a capture.)*

### 8.3 ⚠ SUPERSEDED — this section's conclusion was wrong (see §13 and §14)

This section originally claimed `0x40006400–0x400064FF` was a **CAN TX change-flag bus**: features set
a dirty bit and the Volcano TX side repacks the affected frame. **That reading does not survive
testing.** §13 shows the region is the per-signal **validity / error-substitution** layer; no CAN code
reads it.

What still stands: the write idiom is real, the region *is* a bit page, and the counts below are
correct. What was wrong: the claimed *consumer*. The text is kept for the record.

> The application-wide write idiom, appearing verbatim in dozens of functions:
>
> ```c
> if (cell != NEWVALUE) { *flagbyte |= BIT; }   // mark dirty
> cell = NEWVALUE;
> ```
>
> `work/owner/23_change_flags.py` counts **576 write sites across 94 distinct functions** into
> `0x40006400–0x400064FF`, with a separate reader set consuming them. Busiest bytes: `+0x09`
> (36 writers / 36 readers) and `+0x08` (8/8).
>
> ~~**This is the mechanism that was missing.** Features write plain RAM signal cells and set a change
> bit; the Volcano TX side notices the change and repacks the affected frame.~~
>
> ~~**It also explains a previously-diagnosed on-vehicle bug** — the `rke-lock` "sticky write".~~

**On the `rke-lock` sticky write:** the explanation given here is withdrawn, but the phenomenon is
now explained correctly in **§14.5** by the TX packer's post-transmit AND-mask loop. Cite §14.5, not
this section.

### 8.4 Where features meet CAN in code

`APP_can_tx_state_update` @ `0x45560`, called from `APP_can_gateway_init`, is the cleanest observed
junction: it reads the change-flag page (`0x40006404`), reads `APP_vehicle_mode_state`, and computes
an enable bit into `DAT_40003CAF`. A good entry point for following feature state into CAN output.

Also identified: `APP_periodic_handler_9F55A` @ `0x9F55A` — a caller-less periodic handler (reached
from an OS task, not from `APP_feature_init`) showing the canonical feature shape: read inputs from
the signal plane, compute, write own state block, set change flags. Note this means **`init(1)` is
only a constructor** — the real logic lives in separate periodic functions registered elsewhere.

## 9. Layer 5 — the BCM's CAN role, cross-validated against the vehicle databases

The firmware's acceptance-filter tables were cross-referenced against the owner's vehicle CAN
databases (`CAN-HS.dbc`, `CAN-MS.csv`). The MS-CAN CSV carries a **per-ECU send/receive column**,
which makes it ground truth rather than a guess.

> Per project convention (README §7 / the signal-DB pitfall note) **no proprietary frame or signal
> identifiers are reproduced here.** The databases were used only to classify and verify; everything
> below is our own wording, plus addresses derived from the firmware itself.

### 9.1 The firmware tables are correct — independently confirmed (b)

| Check | Result |
|---|---|
| MS-CAN mailbox direction vs database BCM role | **58 agree, 0 mismatch**, 2 IDs absent from the DB |
| HS-CAN mailboxes present in the DBC | 62 of 63 |

`work/owner/25_can_db_xref.py`. Three MS IDs are marked TX by the firmware while the DB leaves the
BCM column blank — those are the interesting outliers, not errors.

This is the first **external** validation of the acceptance-filter decoding that the whole gateway
model rests on. It also re-confirms the two addresses the shipped mods depend on:
`0x030` → CAN0 MB0 → CS `0xFFFC0080`, and `0x3A` → CAN1 MB1 → CS `0xFFFC4090`.

### 9.2 Bus roles

| Bus | Mailboxes | TX | RX | Character |
|---|---|---|---|---|
| CAN0 HS 500k | 63 | 17 | 46 | mostly **listening** to the powertrain/chassis world |
| CAN1 MS 125k | 63 | 47 | 16 | mostly **driving** the body/comfort world |
| CAN2 MSX 125k | 14 | — | — | side/parking-assist modules |

The asymmetry is the clearest statement of what this module *is*: on HS-CAN it is a consumer of
vehicle state; on MS-CAN it is the authority that body modules obey.

### 9.3 What the BCM drives vs consumes, by domain

`work/owner/26_can_domains.py` classifies every mailbox by keyword families.

**Transmits (BCM is the authority):** driver information & HMI (25 frames), chassis/drivetrain status
re-broadcast (23), exterior lighting (21), keys/ignition/power mode (17), electrical & energy (16),
climate (12), wipers & washers (8), parking aids (7), occupant & restraints (5), security/alarm (3),
steering & column (3), windows/mirrors/roof (2), doors & locks (1).

**Receives:** chassis & drivetrain status (32), driver information & HMI (23), climate (8),
keys/ignition/power (7), exterior lighting (7), electrical & energy (6), steering & column (4),
diagnostics & network mgmt (4), occupant & restraints (3), parking aids (3).

Two observations worth keeping:

- **Exterior lighting is the BCM's single biggest *actuation* domain** (21 TX frames) — it is the
  lighting master for the vehicle.
- **Doors/locks appear in only one TX frame.** That matches the on-vehicle work exactly: central
  locking is one command frame (MS `0x3A`), which is why the `rke-lock` mod is a single-byte
  injection rather than a state-machine patch.

### 9.4 Mailbox addresses are now labelled in the project

`work/owner/27_annotate_mailboxes.py` labels **all 140 mailboxes** across the three controllers with
their computed FlexCAN addresses:

```
CS word      = CAN_base + 0x80 + MBidx*0x10
data d0..d7  = CS + 0x8 .. CS + 0xF
```

Each carries a plate comment with bus, direction, functional domain, nominal cycle time and signal
count. Six high-value frames additionally carry role notes derived from this project's own
on-vehicle work (the lock-command frame, the power/ignition status frame, the RKE event frame, the
steering-wheel button frame, and the two powertrain frames behind the `acc-fix` gate).

These are the addresses you need when writing a cave or reading a capture, and they are now one
lookup away in the listing.

## 10. Layer 6 — the application's diagnostic interface

The app's own UDS layer (distinct from the PBL's, §6) is now mapped and **validated against a real
scan-tool session** (`BCM_read_DIDs` in the CAN capture folder).

### 10.1 ⚠ Method note: a wrong guess, caught by ground truth

The first attempt derived the DID table's array bases from decompiled indices in
`APP_did_read_dispatch`. It produced obvious nonsense — a DID count of 32,833,536 and a "sub-index"
column that merely counted 0,1,2,3… Rather than publish it, the bases were re-derived by **searching
flash for DIDs known to work from the capture**. That located the real array immediately.

Lesson worth keeping: when a capture of the actual behaviour exists, use it to *find* the structure,
not merely to check it afterwards.

### 10.2 The DID table (b, validated)

`APP_did_identifier_array` @ **`0x01FFCC..0x0203A2`** — 492 entries, u16 big-endian, **sorted
ascending** `0x0202 … 0xFDFF`. Sorted means the lookup is a **binary search**, which explains why no
per-DID compare exists anywhere in the code.

Parallel arrays, all indexed by the same position:

| Array | Address | Contents |
|---|---|---|
| identifiers | `0x01FFCC` | u16 DID, sorted |
| handler index | `0x0203AC` | byte → slot in the handler table |
| parameter | `0x0203AE` | u16 at stride 4, sub-index/source selector |
| length | `0x021318` | byte, default response length |
| read mode | `0x02150D` | 2 bits: 1 = fixed source, 2 = via handler |
| length mode | `0x02158B` | 2 bits: 2 = dynamic length |

**Validation against the live session:**

| Check | Result |
|---|---|
| DIDs answered positively that are present in the array | **146 / 147** |
| DIDs refused `0x33 securityAccessDenied` / `0x22` present | **29 / 29** (exist but gated) |
| DIDs refused `0x31 requestOutOfRange` | mostly absent, as expected |

The single miss is `0x0000`, which is not a real identifier (an artefact of parsing a multi-frame
response). The `0x33`-refused DIDs being *present* is the strongest signal: those identifiers exist
in the table but are blocked by security, exactly as the table-plus-gate design predicts.

### 10.3 What the module exposes

| Family | Count | Character |
|---|---|---|
| `0xEExx` | 129 | largest group |
| `0xFDxx` | 101 | manufacturer / routine |
| `0x40–42xx` | 117 | live status & measurements |
| `0xF1xx` | 29 | identification (part numbers, VIN, versions) |
| `0xC0/C1xx` | 27 | security-protected |
| `0x28xx` | 22 | configuration / as-built data |

The `0x28xx` group is the interesting one for repair work: as-built configuration is where variant
coding lives, and it is readable.

### 10.4 Dispatch is one generic reader, not 486 functions

`APP_did_handler_table` @ `0x20B80` has 486 slots — **all holding the same target**,
`APP_did_generic_reader` @ `0x0DBD34`. The classic "one default handler" pattern: dispatch happens
*inside* on the per-DID parameter. `APP_did_read_dispatch` @ `0x107C1A` is the entry point a scan
tool reaches for service `0x22`.

### 10.5 Generated jump tables

Three large tables of unique code addresses with no static xrefs (computed addressing), now labelled:
`0x01D3A8` (1036 entries), `0x01CDF0` (336), `0x01E710` (178). Their size and density indicate
generated switch dispatch for large state machines rather than interrupt vectors — the app's INTC
vectors were **not** found as a flat table, consistent with the OS installing them programmatically.

## 11. Layer 7 — every diagnostic identifier bound to its reader function

### 11.1 ⚠ Correction to §10.4

§10.4 claimed the 486 identical entries at `0x20B80` meant "one generic reader that dispatches
internally, not 486 functions". **Half right, and the important half was wrong.**

Ghidra had never created a function at `0x0DBD34` — nothing references it *statically*, since the
table is reached by computed addressing, so it appeared as raw bytes. Force-creating it
(`work/owner/36_force_functions.py`) reveals an **8418-byte switch** that calls **476 distinct
per-DID reader functions**.

The real design is: uniform table entry → one dispatcher → **one small dedicated function per
identifier**. Worth remembering as a method note: *a table target that "isn't a function" usually
means Ghidra never discovered it, not that it isn't code.*

### 11.2 The complete DID → reader map (a)

485 switch cases parsed; **476 bound to distinct readers**, covering **145 of the 147** DIDs the real
scan session answered. Every one is now individually named in the project, e.g.
`APP_did_cfg_280F_read`, `APP_did_status_4094_read`, `APP_did_ident_F188_read`.

Full map: `work/owner/did_readers.json`.

Where the readers get their data (reference counts across all 476):

| Region | Refs |
|---|---|
| SRAM (live state) | 1810 |
| `CAL_F124` calibration data | 58 |
| `CAL_F10A` network database | 3 |

So diagnostics are overwhelmingly a **live-state** interface, with a small calibration-backed group —
the latter being the as-built configuration values.

### 11.3 `APP_vehicle_mode_state` — now proven, not inferred

§8.2 identified `0x40001E38` as the most-read cell (~120 readers) and called its meaning *inferred
from fan-out shape*. The diagnostic layer settles it. Readers have the shape:

```c
if (APP_vehicle_mode_state == 1) { produce the value; }
else { APP_diag_nrc_slot = 0x22; }     // conditionsNotCorrect
```

Tested against the live session (`work/owner/39_prove_mode_gate.py`):

| Observation | Count |
|---|---|
| Guarded DIDs requiring `mode == 1` that answered positively | **31** |
| DIDs refused with exactly NRC `0x22` — the failure branch | **4** |
| Guarded DIDs requiring any *other* constant | **0** |

**Mode 1 is the normal operating state** in which the module serves diagnostics and runs body
features. The model is confirmed end-to-end: firmware branch → NRC constant → observed bus response.
This is level-5 evidence (confirmed through to an external output), the strongest class in the
project's own hierarchy.

Also identified: `APP_diag_nrc_slot` @ `0x40009DF8`, the negative-response-code output, referenced by
120 of the 476 readers.

### 11.4 What this unlocks

Any diagnostic identifier can now be traced from the wire to its data source in two lookups: DID →
reader function (`did_readers.json`) → the SRAM cell or calibration address it reads. The `0x28xx`
as-built group (22 identifiers) is fully named, which is the natural starting point for variant-coding
work.

## 12. Layer 8 — memory architecture, and what the `0x28xx` group really is

### 12.1 Three distinct RAM regions, read from the reset path

Disassembling the reset path (`0x10F4A0`, `0x2FECA`, `0x2FEE8`) rather than pattern-matching gives the
authoritative map (a):

| Region | Range | Size | Init |
|---|---|---|---|
| **Retained RAM** | `0x40000020..0x400039A0` | 14720 B | zero-filled **only on destructive reset** |
| `.data` | `0x40003A60..0x40005492` | 6706 B | copied from flash `0x1156C0..0x1170F2` |
| `.bss` | `0x400054A0..0x4001B06B` | 89035 B | zeroed every reset |

`APP_reset_cause_check` @ `0x2FEE8` decides whether retained RAM survives:

```c
if ((*(u16*)0xC3FE4002 & 0x801B) != 0) clear;   // RGM_FES
if (*(u16*)0xC3FE4000 & bit)           clear;   // RGM_DES
p = retained_ptr();
if (p <= 0x40000020 || p >= 0x400039A0) clear;  // sanity-check the pointer
else                                    PRESERVE;
```

**Independent cross-check:** `AGENTS.md` Step F2 records the ECC/zero-init range as *starting* at
`0x400039A0` — exactly where this region *ends*. Two unrelated derivations agree on the boundary,
which also retroactively validates the `acc-fix` scratch-byte choice at `0x40011000` (in `.bss`, well
clear of retained RAM).

### 12.2 ⚠ Correction: the `0x28xx` values are not flash constants

§11.4 suggested the `0x28xx` group was the natural starting point for variant coding, on the
assumption those values are calibration-backed. **They are not.** All **85** cells behind the 22
identifiers fall in **retained RAM** — zero in `.data`, zero in `.bss`:

| Backing | Cells |
|---|---|
| Retained RAM | **85** |
| `.data` (flash-backed) | 0 |
| `.bss` | 0 |

So these values are *accumulated at runtime and survive warm resets*. They cannot be changed by
patching the image, and re-reading them after a battery disconnect will show them reset. Useful
negative result: it removes a whole class of intended edits.

### 12.3 Five "configuration" DIDs are actually one rolling event buffer (a)

`0x281C/1E/1F/20/21` looked like five independent config items. Sorting each one's private cells and
reading across rows shows perfectly consecutive columns:

```
        0x2820      0x2821      0x281C      0x281E      0x281F
 [0] 0x40002740  0x40002741  0x40002742  0x40002743  0x40002744
 [1] 0x40002745  0x40002746  0x40002747  0x40002748  0x40002749
 [2] 0x4000274A  0x4000274B  0x4000274C  0x4000274E  0x40002750
 ...
```

That is a **struct-of-arrays with five slots** — one record type stored five times. Nine parallel
fields, plus three cells shared by all five (buffer-level bookkeeping: `APP_event_buffer_flags`,
`APP_event_buffer_timebase`, `APP_event_buffer_index`).

The reader's arithmetic confirms event semantics:

```c
elapsed = clamp(APP_event_buffer_timebase - slot.timestamp, 0, 0xFF);
count   = slot.counter - 1;
```

A duration and an occurrence count — a **rolling history buffer**, renamed `APP_event_slot_0..4_read`.
Reading all five in one session yields a consistent snapshot only because they share one timebase.

### 12.4 Data flash is an EEPROM-emulation store, and nearly empty

`dflash.bin`: 65536 bytes, **32 non-`0xFF`** — four 8-byte records at 4 KiB spacing:

```
0x00000: f1 00 01 00 05 01 d6 4d
0x01000: f1 00 01 00 06 01 d6 bd
0x02000: f1 00 01 00 07 01 d7 2d
0x03000: f1 00 01 00 08 01 d2 dd
```

Identical shape, one field incrementing 5→8, one record per sector: classic **rotating-record EEPROM
emulation** (newest counter wins). The trailer is *not* CRC-16/CCITT over any prefix (tested all
lengths, both init values), so the integrity scheme differs from the PBL's — open question. The
payload is ≤6 bytes, so this is a small persistent counter, **not** a configuration store. The BCM's
persistent state therefore lives almost entirely in retained RAM, not in NVM.

## 13. Layer 9 — the signal validity / error-substitution layer

### 13.1 ⚠ Major correction: `0x40006400–0x400064FF` is not a CAN TX flag page

§8.3 called this region a **change-flag bus** driving CAN transmission. Testing the claim properly
refutes it. Four independent observations, none of which the flag-bus model predicts:

| Test | Result | Implication |
|---|---|---|
| Stores classified as read-modify-write | **407 / 575** are bit set/clear | it *is* a bit page ✓ |
| Functions clearing bits that reach any FlexCAN register (depth 3) | **0 of 19** | no CAN consumer ✗ |
| Pure consumers (load, never store) among the 44 hot-cell functions | **0** | no producer/consumer split ✗ |
| The two hottest cells (`+0x08`, `+0x09`) | set 46×, **never cleared** | a dirty flag must be cleared ✗ |

A dirty flag nobody clears would latch permanently after the first change, so it cannot drive periodic
TX.

### 13.2 What it actually is (a)

`APP_signal_substitution_run` @ `0x0F5084` applies one template ~34 times, verbatim:

```c
out.bit   &= ~m;                  // drop the published bit
if (status.bit) out.bit &= ~m;    // idempotent guard
status.bit |= m;                  // latch "substituted"
out.bit    = valid.bit ? m : 0;   // republish from the validity bit
```

with e.g. `valid = 0x40006444.b1`, `status = 0x40006413.b1`, `out = 0x40003D0F.b1`.

Matched mechanically across all 97 functions touching the region:

| Measure | Count |
|---|---|
| Republish-template instances | **80** |
| …sourced from `0x4000_64xx` | **68** |
| …landing in the signal plane `0x40003C00–0x40003DFF` (§8.1) | **42** |

So this is the AUTOSAR-style **signal validity / error-substitution** layer: it records whether each
signal is valid or has been replaced by a default, and republishes the result into the signal plane.
The gateway walker reads *the signal plane* — which is why no CAN register is ever touched here, and
why there are no pure consumers (each handler owns its own bits).

Two sticky latches never cleared anywhere in the image:

- `APP_signal_error_latch_0` @ `0x40006408` — 10 setters, bits 1,2,3,5,7
- `APP_signal_error_latch_1` @ `0x40006409` — 36 setters / 218 writes, bits 2,4,6,7

Three diagnostic identifiers read this region directly (`0x4028`, `0x4029`, `0xFD81`), consistent with
validity/quality being reportable over UDS.

### 13.3 A second stale claim in the same area

The plate comment on `APP_can_tx_state_update` @ `0x45560` said it "reads the change-flag page at
`0x40006404`". It does not: `0x40006404` is a **32-bit pointer slot** (`se_stw`/`e_lwz`, written by
`FUN_0002E730`) selecting one of six calibration records at `0xC469`, `0xCB1C`, `0xD1CF`, `0xD882`,
`0xDF35`, `0xE5E8`. The function compares the pointer to pick a variant, then computes an enable bit
into `0x40003CAF.b4`. Corrected in the project.

### 13.4 Method note

The first version of this test asked *"does any OR instruction reference the region?"* and got **none**
— which looked like strong refutation but was a worthless test: PowerPC is load/store, so `*p |= bit`
compiles to `e_lbz` / `e_ori` / `e_stb`, and the OR operates on a **register**, never referencing
memory. The valid test is to classify each **store** by inspecting the instructions before it. Worth
remembering on any RISC target.

## 14. Layer 10 — the CAN codec, and why no feature→CAN reference exists

### 14.0 The bus↔controller map, proven from the CTRL registers (a)

Every doc in the repo asserts this mapping; it had never been *derived*. It is now, from the FlexCAN
bit-timing registers at `ctrlDesc+0x30` (`work/owner/62_prove_bus_map.py`):

| Module | Base | CTRL | PRESDIV | Tq/bit | `(PRESDIV+1)·Tq` | Rate | Bus |
|---|---|---|---|---|---|---|---|
| **CAN_0** | `0xFFFC0000` | `0x05492004` | 5 | 10 | **60** | 500 kbit/s | **HS-CAN** |
| **CAN_1** | `0xFFFC4000` | `0x17DB2000` | 23 | 10 | **240** | 125 kbit/s | **MS-CAN** |
| **CAN_2** | `0xFFFC8000` | `0x17DB2000` | 23 | 10 | **240** | 125 kbit/s | **MSX-CAN** |

The ratio **60 : 240 = 4 : 1** is clock-independent, so "CAN_1 and CAN_2 run at a quarter of CAN_0"
holds without knowing `f_CAN`. Solving with the 500 kbit/s HS assumption gives `f_CAN` = **30 MHz**,
which then yields exactly 125 kbit/s for the other two — a consistent, self-checking result.

Mailbox counts reinforce it: CAN_0 and CAN_1 have **63** configured mailboxes each, CAN_2 only **15**
— a small dedicated bus, matching the side/parking-assist role. MS-CAN (CAN_1) is the body bus, home
of the `0x3A` lock frame at MB1 (`CS 0xFFFC4090`), consistent with `docs/rke-lock.md`.

### 14.1 The codec functions were invisible (again)

None of `0x0FC218` / `0x0FC2F6` / `0x0FC63E` — the TX packers and RX copier documented in
`gateway_map.md` — existed as functions in this project. They have **no static xref**: each is
reached only through a **net-table function pointer**, one slot per network:

| Function | Role | Pointer slots |
|---|---|---|
| `VOL_tx_pack_single` `0x0FC218` | single-frame TX | `0x0178B8`, `0x017A84`, `0x017AE0` |
| `VOL_tx_pack_walker` `0x0FC2F6` | periodic walker | `0x0178BC`, `0x017A88`, `0x017AE4` |
| `VOL_rx_copy_to_image` `0x0FC63E` | RX → image | `0x0178C4`, `0x017A90`, `0x017AEC` |

Exactly three slots each, at the offsets `gateway_map.md` §1 predicts — an independent
confirmation of the net-table layout. Force-creating them (§11.1's lesson, third application) made all
three decompile cleanly.

### 14.2 The TX packer, in full (a)

```c
cs = canbase + 0x80 + desc[0x1A]*0x10;
if ((*cs & 0xE00) == 0x400 || (*cs & 0xE00) == 0x800) {   // mailbox free
    image[0] += desc[0x1D];                  // alive-counter bump
    *cs = 0x800;                             // lock
    for (k=0; k<8; k++)                      // desc[0x1E] = byte-present mask
        data[k] = (desc[0x1E]>>k & 1) ? *img++ : 0;
    *cs = ctrlword | 0xC40;                  // ARM TRANSMIT
    for each present byte: *img &= desc[k];  // post-TX AND-mask
}
```

**The final AND-mask loop is the mechanism behind one-shot command bits**: a payload byte is masked in
the image immediately after being transmitted.

### 14.3 The descriptor array is per signal *bit* (b)

`VOL_tx_descriptor_array` @ `0x017B80` — **361 uniform records × 32 bytes**, spanning
`0x017B80..0x01A8A0`.

| Offset | Meaning |
|---|---|
| `+0x08` | bit mask — only 8 values, `0x01..0x80 << 24`, cycling |
| `+0x0C` | → routing record in the F10A block |
| `+0x10`/`+0x14` | → `0x146FA0` / `0x146FA4`, shared by 232 records each |
| `+0x18` | → **frame-image byte** in SRAM (`0x40007AF8..0x40007B25`) |

The mask cycles through 8 values while the image pointer advances one byte per group: **each record
describes one bit of one frame byte**. This independently re-derives §8's finding that `+0x08` is a
bit mask, not a mailbox IFLAG.

> **⚠ Correction (same pass).** An earlier draft of this section said *"`ctrlDesc+0x44` points into
> this array"*. That is **not established**, and the evidence is against it:
>
> - CAN_0's `+0x44` = `0x018000` lands at **record 36 of 361** — pointers don't address an array's middle;
> - CAN_2's `+0x44` = `0x0033E0` is inside **PBL code space**, impossible for a descriptor table;
> - CAN_1's `+0x44` = `0`, yet MS-CAN demonstrably transmits (the `rke-lock` frame `0x3A` is on it);
> - **nothing** in the image points at the array start `0x017B80`.
>
> Root cause of the misreading: I assumed the packer's `param_1+4` was the controller descriptor. It
> isn't — `VOL_tx_pack_single` derives the FlexCAN base from `*(param_1+8)+0x10`, so the ctrlDesc is
> at `param_1+8` and `param_1+4` is a different structure. **How the array is reached at runtime is
> open.** The layout above is unaffected: it came from the uniform record structure, independently of
> the `+0x44` question.

### 14.4 Why the feature→CAN reference does not exist — resolved (a)

The answer to the question §8.3 got wrong, and it is a **negative result proven four ways**:

| Population | Functions |
|---|---|
| Referencing frame images `0x40007Axx` absolutely | **1** — `VOL_network_bringup`, and only to *zero* them |
| Referencing the Volcano signal RAM | **1** — the same function |
| Referencing FlexCAN registers | **0** |
| Referencing the app signal planes | 772 |

**Every runtime CAN access is pointer-based**, through the descriptor's `+0x18` field. The packer
never names an address: it dereferences `*(param_2 + 8)`. That is why no scan for direct references —
and there have now been five — can ever connect feature code to CAN. The decoupling is structural,
not an artefact of looking in the wrong place.

### 14.5 The `rke-lock` sticky write — explanation restored, with the right mechanism

§13 withdrew the "delta-driven packer" story. The real mechanism is now visible and is **stronger**:
the packer's post-TX `*img &= desc[k]` loop means the firmware clears command bits in the image after
transmitting. A code cave that forces a mailbox byte writes *downstream* of that loop, so nothing ever
clears it — the value persists until the next packer pass overwrites the whole payload. The shipped
fix (drive the byte in both directions) remains correct, and now rests on the packer's own code rather
than on an inferred flag bus.

### 14.6 ⚠ Correction: `FUN_0010DAB8` is `memset`

§8.4 flagged it as the shared signal-accessor lead because **79 of 83 feature modules call it**. It is
`memset()` — word-fill with alignment head/tail handling. The high call count simply reflects every
module zeroing its state block at init. **There is no signal-access API**; features do not reach CAN
through a call at all.

## 15. Layer 11 — the runtime descriptor chain (anchor resolved, scope limited)

### 15.1 The anchor is built in RAM, not stored in flash

§14.3 left open *how the descriptor array is reached*. The TX walker's own code answers it:

```c
count = *(u8*)( *(int*)(param_1 + 4) + 0x44 + 0x10 );
for (d = *(u8**)( *(int*)(param_1 + 4) + 0x44 + 4 );
     *(int*)(d + 8) != 0; d += 0x20) { ... }
```

So `+0x44` **is** a real pointer field — just not on the controller descriptor. My last-pass test
failed because `param_1+4` is a *different* structure (`S`), while the ctrlDesc sits at `param_1+8`.

Locating the net-table records by that corrected offset gives:

| Net record | `+0x00` config (flash) | `+0x04` = `S` (RAM) | `+0x08` ctrlDesc |
|---|---|---|---|
| `0x0178AC` | `0x00144B90` | **`0x400001A0`** | `0x1464E0` CAN_0 HS |
| `0x017A78` | `0x00146060` | **`0x400004FC`** | `0x146900` CAN_1 MS |
| `0x017AD4` | `0x00146330` | **`0x40000588`** | `0x146C50` CAN_2 MSX |

`S` is **SRAM**. `S+0x44` → `T`, and `T+4` → array base, `T+0x10` → count. `VOL_network_bringup` is
the only function touching `0x400001E4` (= `S+0x44`), so it installs the anchor at bring-up.

**That is why every flash-pointer search failed** — the anchor never exists in flash. Also note the
net-table stride is **not uniform** (`0x1CC` then `0x5C`), so the table cannot be indexed blindly.

### 15.2 The descriptor's `+0x10` is a signal pointer, and 193 slots are unbound (b)

`0x146FA0` holds **`0x40000614`** — the NULL-signal placeholder already documented in
`gateway_map.md` §4. So `+0x10` points at a routing record whose word0 is the signal-RAM
address, and the "shared constant" seen on 193 descriptors simply means **unbound slot**.

| Descriptors | Meaning |
|---|---|
| 193 of 361 | point at the NULL signal — unbound |
| **168** | carry real signals, covering **118 distinct signal cells** |

The `+0x14 − +0x10` delta is a clean binary split: **`+4` for all 193 unbound, `+0x10` for all 168
bound** — an independent confirmation of the split.

Each bound descriptor yields **signal cell → frame-image byte → bit index**, e.g.
`0x40000C2F → 0x40007B08 bit 3`. Full map: `work/owner/signal_bit_map.json` (168 entries). Signal
cells landing exclusively in the Volcano band `0x400006xx–0x40000Cxx`, as expected.

### 15.3 ⚠ Scope limit — this is not the main gateway path

Measuring coverage before drawing conclusions (`71_coverage_check.py`):

- the array names only **46 image bytes** (~6 frames), against **141 configured mailboxes**;
- it is the **only** descriptor array in the image (a full scan for the same record shape found one run);
- **no F10A routing record names the `0x40007Axx` pool at all** — routing `frameObj` values live at
  `0x400001xx` (250), `0x400005xx` (132), `0x40000Exx` (49).

So this structure is narrow and self-contained, and **its role is not established**. It is *not* the
path by which most frames are composed. Recorded as a limit rather than extrapolated — the honest
reading is "one decoded mechanism, unknown share of the whole".

## 16. Layer 12 — the 28-byte routing records: geometry solved, binding not

### 16.1 Three refuted models (recorded so nobody retries them)

Each was tested against one falsifiable prediction: **within a frame object, the bits claimed by
different signals must be mutually disjoint** — a bit of a payload byte can belong to only one signal.

| Model | Result |
|---|---|
| `frameObj` = destination byte, `spec2` high byte = mask | **refuted** — 29 of 49 frame objects overlap; one carries 94 records (>8 bits) |
| 20-byte records at 4-byte alignment (the inherited parse) | **refuted** — `spec2` bytes 2–3 are zero in all 447 records, and column profiles are flat = misaligned |
| 28-byte records, `attr` byte2 as mask | **refuted** — all 14 frame objects overlap; 24 signals cannot fit in 8 bits |

### 16.2 What *is* established: record geometry (b)

The breakthrough was abandoning statistics for a **self-evident marker**: a word of the form
`0x08_mmmm_00` recurs throughout the block. Anchoring on it gives stride **28 (`0x1C`)** and, crucially,
**columns that specialise** — the signature of correct alignment, where every earlier attempt produced
a flat profile:

| Offset from marker | Content |
|---|---|
| `−4` | attribute word; byte2 single-bit in **291 of 298** |
| `0` | marker `0x08_mmmm_00` (147 distinct middles, *not* sequential) |
| `+4` | **signal cell** — SRAM pointer in **298/298** |
| `+8` | optional second signal (pointer in 111/298) |
| `+12` | **frame object** — SRAM pointer in **298/298**, only 14 distinct |
| `+16` | optional (pointer in 113/298) |
| `+20` | zero in 283/298 |

94 distinct signal cells across 14 frame objects, and they group cleanly by net:

| Frame objects | Net | Signals each |
|---|---|---|
| `0x400001A0..A7` | CAN_0 HS | 24, 24, 24, 24, 24, 24, 24, 6 |
| `0x400004FC..500` | CAN_1 MS | 32, 32, 26, 25, 3 |
| `0x40000588` | CAN_2 MSX | 6 |

### 16.3 ⚠ Resolved in §17 — the premise was wrong

The models failed because **"frame object" is not a payload byte at all**. §17 shows it is an
**RX-arrival flag byte**, and the masks index *frames*, not bits within a CAN data byte. The
disjointness test was therefore testing a property the data was never supposed to have.

What stands from this pass: the 28-byte stride and the marker-anchoring technique — both confirmed
independently by the consumer code in §17. What was wrong: trying to derive field *semantics* from
value-shape statistics instead of reading the code that consumes the table. Recorded because the
sequence "three refutations → read the consumer → immediate answer" is the reusable lesson.

## 17. Layer 13 — the RX frame map, decoded from the consumer (a)

### 17.1 Method: let the consuming loop define the fields

`VOL_rx_copy_to_image` walks the records with stride **`0x1C`** — confirming §16's marker-derived
stride — and every field is named by how the code uses it:

| Offset | Meaning |
|---|---|
| `+0x00` | destination frame-image base (packed) |
| `+0x04` | second buffer (previous value, for the change compare) |
| `+0x08` | **RX-arrival flag byte** |
| `+0x0C` | gate byte pointer (software-triggered mode) |
| `+0x14` | mode: 0 = hardware mailbox |
| `+0x15` | compare-before-copy enable |
| `+0x16` | **this frame's bit** in the arrival flag byte |
| `+0x18` | expected DLC (checked against `CS & 0xF`) |
| `+0x19` | **mailbox index** → CAN ID via the filter list |
| `+0x1A` | **byte-present copymask** |

Anchor: `S+0x44 → T`; `T+0x04` = TX descriptor array, **`T+0x08` = RX record array**, `T+0x10`/`T+0x11`
the two counts. One control block, two arrays — which also explains §15's loose end.

### 17.2 The compacting-copy rule, now general

```c
for (m = copymask; m; m >>= 1) { if (m & 1) *dst++ = *src; src++; }
```

**CAN byte `k` lives at `image_base + popcount(copymask & ((1<<k)−1))`, and only if bit `k` is set.**

This is exactly the rule `AGENTS.md` Step D2 warns about — previously derived by hand, one frame at a
time. It is now enumerated for **279 RX frames** across all nets in `work/owner/rx_frame_map.json`,
with every present byte's absolute address precomputed.

### 17.3 Validation against the shipped firmware (level 5)

Both addresses the **on-vehicle-proven acc-fix** depends on fall straight out of the formula:

| Signal | MB | copymask | base | offset | computed | expected |
|---|---|---|---|---|---|---|
| `0x0C0` d0 (PCM cruise status) | 30 | `0x13` | `0x40000707` | 0 | `0x40000707` | `0x40000707` ✓ |
| `0x060` d6 (stored set-speed) | 22 | `0xFE` | `0x40000700` | 5 | `0x40000705` | `0x40000705` ✓ |

Derived here from consumer code → record layout → filter list; derived originally by hand-tracing
descriptors. Two independent paths, same answers — and the firmware built on them runs on the car.

### 17.4 The `0x400001A0..A7` puzzle, solved

After a successful copy the consumer does `*(u8*)rec[0x08] |= rec[0x16]`. So those bytes are
**RX-arrival flags**: each holds "frame received" bits for up to **eight** frames.

Verified: **7 of 8 bytes carry exactly 8 frames, and every frame owns a distinct single bit** — e.g.
`0x400001A2` = `0x060`:b0, `0x070`:b1, `0x080`:b2, `0x090`:b3, `0x0A0`:b4, `0x0C0`:b5, `0x120`:b6,
`0x130`:b7.

These are the bytes application code polls to learn a frame arrived — a concrete, checkable hook for
any future "react to frame X" work.

## 18. Layer 14 — the TX frame map, and both ends of the codec closed (a)

### 18.1 A shape-scan that failed, and the fix

The first attempt scanned flash for 32-byte records matching the TX field shape. It produced 48
"records" that were obviously wrong, and said so itself: every image base came out `0x40000614` (the
NULL placeholder), the "post-TX masks" read `40 00 0C C3` (i.e. **SRAM pointers split across byte
columns**), and MS `0x3A` was missing although `rke-lock` proves it transmits. Discarded.

The fix was to use the anchor instead: search for the pointer to the **already-proven** RX array
(§17), which lands on the net control block `T`:

| `T` @ `0x144C20` | Value | Meaning |
|---|---|---|
| `+0x04` | `0x0014AA0C` | **TX record array** (32-byte records) |
| `+0x08` | `0x0014AC4C` | RX record array (28-byte, §17) |
| `+0x10` | `0xFFFF0000` | counts read as `0xFF`/`0xFF` = "no limit" → the sentinel terminates |

Useful general lesson: **anchor new structures on ones you have already validated**, rather than
re-deriving from scratch.

### 18.2 The TX record (from `VOL_tx_pack_walker`'s disassembly)

| Offset | Meaning |
|---|---|
| `+0x00..07` | post-TX AND masks (one per payload byte) |
| `+0x08` | **frame image base** — the assembled payload |
| `+0x0C` | request-bitfield byte pointer |
| `+0x14` | optional `u16*` inhibit (skip while `*p != 0`) |
| `+0x1A` | **mailbox index** |
| `+0x1B` | this frame's **request bit** |
| `+0x1D` | alive-counter increment |
| `+0x1E` | byte-present mask (same compacting rule as RX) |

**15 records, mailbox indices 0–14 in order**, every request mask a single bit, and **zero overlap**
between frame image windows. Full map in `work/owner/tx_frame_map.json`.

Validation: `0x030` → MB0 → CS **`0xFFFC0080`**, image `0x40000760`, present `0xFF` — the CS address
the shipped acc-fix hooks.

### 18.3 What this adds to `030_composition_trace.md`

That doc established (level b/c, analysis only) that `0x030` d1 comes from a 4-byte contributor PDU at
`0x40005AE0`, while **d5 lives in a different contributor** — hence "you cannot reach d5 by editing
this button PDU", which is *why* acc-fix injects at the mailbox.

The TX map shows the other end of the pipeline: in the **final** frame image, `0x030` occupies eight
contiguous bytes, so **d1 = `0x40000761`, d5 = `0x40000765`, d6 = `0x40000766`**.

Both are correct at different stages — upstream contributors are separate; the TX image is where they
merge. Concretely this means the TX frame image is the **earliest point where d1, d5 and d6 coexist**,
i.e. a candidate hook site one stage before the mailbox. Not a change to the shipped mod, but a
cheaper option if acc-fix is ever reworked.

### 18.4 The three unexplained MS TX IDs, explained

§9 flagged `0x400`, `0x405`, `0x435` as transmitted by the BCM but unattributed in the vehicle DB.
They appear here as ordinary HS TX records — MB10, MB11, MB14 — with normal images and request bits.
They are simply **HS-CAN frames the database doesn't attribute**, not anomalies.

### 18.5 Codec status

| Direction | Records | Frames | Validated against |
|---|---|---|---|
| RX | 28-byte, `T+0x08` | 279 across nets | acc-fix `0x40000707`, `0x40000705` |
| TX | 32-byte, `T+0x04` | 15 on CAN0_HS | acc-fix CS `0xFFFC0080` |

Both directions are now decoded from consumer code and cross-checked against firmware that runs on the
car.

## 19. Layer 15 — MS-CAN mapped, and the `0x3A` lock frame located (a)

### 19.1 Two failed identification routes, and the one that worked

**Failed — mailbox indices:** CAN0 and CAN1 both configure 63 mailboxes with overlapping indices, so
"does this MB exist in that filter list" scored 15/15 for *both* nets. The same degenerate-ground-truth
trap as the earlier mailbox-bitmask test; discarded without reporting a number.

**Failed — referrer chasing:** only CAN0's `T` has a locatable binding record, and the `−8` offset that
worked there turned out to be coincidence. MS/MSX net-record pointers live in a different structure
(`0x0177DC`) with no `T` nearby.

**Worked — the arrival-flag page.** Each net's RX records point their flag byte into that net's own
block, and §16 had already established the groups independently:

| `T` block | RX flag bytes | Net |
|---|---|---|
| `0x144C20`, `0x144CB0` | `0x400001A0..A7` | CAN_0 HS |
| `0x146180`, `0x146210` | `0x400004FC..FF` | **CAN_1 MS** |

Confirmed by the TX request bitfields: `0x400001C0..C1` for HS, `0x4000051C..21` for MS — disjoint,
so no coincidence.

### 19.2 MS-CAN, the body bus

| | |
|---|---|
| `T` | `0x146180` |
| TX array | `0x00151A68` — **43 records** |
| RX array | `0x00152088` — **30 records** |

### 19.3 The `0x3A` central-lock frame (level 5 validation)

```
MB1   CS 0xFFFC4090   image 0x40000A0F   present 0xFF
  d0 0x40000A0F    d1 0x40000A10  <- execute strobe, bit6
  d2 0x40000A11    d3 0x40000A12  <- 0x01 = LOCK, 0x02 = UNLOCK
  d4 0x40000A13    d5 0x40000A14
  d6 0x40000A15    d7 0x40000A16
```

**`0xFFFC4090` is exactly the CS address the shipped `rke-lock` mod hooks** — reproduced here from an
independent path (RX flag pages → net binding → TX record → filter list). Combined with §17's and
§18's checks, all three addresses the two on-vehicle-proven mods depend on now fall out of the decoded
tables.

As with HS `0x030` (§18.3), the assembled frame image already holds all eight bytes contiguously, one
stage **before** the mailbox — a candidate cheaper hook site. The shipped mod is unaffected.

### 19.4 ⚠ Two MS configurations, selection unknown

`0x146180` (43 TX) and `0x146210` (44 TX) share the same flag page, the same request bitfield, and the
same `0x3A` image `0x40000A0F`. So MS-CAN has **two near-identical configurations** — variant- or
mode-dependent. Which one is live is **not established**: the selection happens at bring-up, in RAM
(`S+0x44`). The same pairing exists for HS (`0x144C20` / `0x144CB0`).

This is worth flagging for any future mod: patching a frame image address is safe (both configs share
them), but patching a *record* means picking the right array.

## 20. Layer 16 — MSX-CAN, and a self-caught false discovery

### 20.1 ⚠ A "breakthrough" I had to withdraw

An intermediate scan reported **279 records pairing an RX image byte with a signal cell** — apparently
the long-sought unpack step. It was wrong, and the output said so on inspection:

- record `0x14AC48` sits inside `VOL_rx_frame_records` (`0x14AC4C`) — **the array already decoded in
  §17**, re-read at a 4-byte offset;
- the "signal cells" were `0x400001A6`-type addresses — **arrival flag bytes** (§17.4), not signal storage;
- the count was exactly **279**, i.e. the same 279 RX records;
- the disjointness test failed **87/87**, precisely as §16.3 predicts for frame-indexed bits.

So it re-derived a known structure and mislabelled its columns. Rejected before it reached the
project. The general trap: *a new parse that reproduces the count of something you already decoded is
probably that same thing, shifted.*

### 20.2 The unpack step: a clean negative result

Testing the alternative — that features read packed images directly — gives a sharp answer:

| Measurement | Result |
|---|---|
| App functions **reading** RX image bytes by absolute address | **0** |
| App functions **writing** them | **0** |
| Overlap between RX image pages and the app signal planes | **none** |

RX images occupy `0x40000600/700/800/900/C00` (414 bytes); the app signal planes are at
`0x40001E00`/`0x40002800`/`0x40003C00`. **Decoded CAN data and feature state live in disjoint memory**,
and nothing reaches the images by literal address — consistent with §14.4's finding that all runtime
CAN access is pointer-based.

**The unpack stage therefore exists and is still unlocated.** That is now a measured claim rather than
an assumption.

> **Strengthened in §23 (do not re-litigate).** At the time of writing, this measurement covered only
> the ~2,400 functions Ghidra had discovered, so "0 readers" was open to the objection that the unpack
> code was simply *not disassembled*. A full linear sweep has since raised the project from 2,403 to
> **13,588 functions**, disassembling essentially all remaining code — and the counts above are
> **unchanged** (1 function touches frame images, 1 touches FlexCAN registers). The conclusion no
> longer depends on coverage.

### 20.3 MSX-CAN: records found, no control block

MSX (CAN_2) uses a **single** arrival-flag byte at `0x40000588` — versus 8 for HS and 4 for MS —
matching its 15 configured mailboxes (`0x120`, `0x370`, `0x380`, `0x400`, `0x405`, `0x501`, `0x581`,
`0x7C4`, `0x7C6`, `0x7DF`, `0x090`, `0x200`, `0x7CC`, `0x7CE`, `0x500`).

**23 RX records** point their flag byte there and are now labelled — but they are **scattered**
(`0x1448C0`, `0x1478C4`, `0x147904`, `0x147F64`, …), not one contiguous array, and none sits at a
`T+0x08` target. **No MSX control block has been identified.** Whether MSX uses a different
arrangement, or these are fragments of several small arrays, is open — the HS/MS layout should not be
assumed to apply.

## 21. Module identity — a cross-block dependency (a)

Triggered by the question "where do `F1DT-14F119-EC` and `F1DT-14A073-EF` live?". They are **not in
this firmware at all** — but answering it exposed a dependency worth recording.

### 21.1 The PBL identity block (`0x006B00..0x006BC0`)

Four fixed identity strings live inside the **primary bootloader block**, NUL-padded and separated by
erased `0xFF` runs:

| Address | Value | Meaning | Served as DID |
|---|---|---|---|
| `0x006B10` | `009640039386` | ECU serial number | `0xF18C` |
| `0x006B20` | `FORD-PBL-V013` | Bootloader version | `0xF180` |
| `0x006B68` | `DV6T-14C245-FF` | ECU Core Assembly Number | `0xF111` |
| `0x006BA8` | `DV6T-14A073-FK` | ECU Delivery Assembly Number | `0xF113` |

A fifth record at `0x008000` holds the **VIN**, CRLF-delimited and likewise below `0xC000`:

```
008000  57 00 31 82 73 71 30 30 35 0d 0a 57 46 30 41 58  |W.1.sq005..WF0AX|
008010  58 57 50 4d 41 45 4c 33 32 36 30 30 0d 0a 00 00  |XWPMAEL32600....|
```

→ VIN **`WF0AXXWPMAEL32600`**, preceded by a short `sq005` tag record. This matches the owner vehicle
and the `.uuw` as-built file name, confirming the backup came from this car.

### 21.2 Application readers reach into the bootloader block

The readers are **application** code (`0x0E3xxx`), but the data is **bootloader** content:

```
000e321e  e_add16i r7,r5,0x6b68     ; literal base + index
000e3222  e_add2is r7,0x0           ; high half 0  -> absolute 0x00006B68
000e3226  se_lbz   r7,0x0(r7)
```

All four share one clamped byte-copy shape — zero-padded to the requested length, capped at 24 bytes:

```c
for (i = 0; i < want_len; i++)
    dst[i] = (offset < 0x18) ? literal[offset] : '\0';
```

**Measured scope:** exactly **4 of 476** app DID readers reference an ASCII string below `0xC000`
(`100_pbl_identity_refs.py`, resolving both Ghidra xrefs and `e_add16i`-synthesised addresses). Every
other identity DID reads app or calibration data: `0xF10A` → `0x15BC5A`, `0xF110` → `0x0134F6`,
`0xF124` → `0x00C000`, `0xF188` → `0x13FFE0`.

Consequences:

- **Reflashing or erasing the PBL block changes what the application reports** for
  `F111`/`F113`/`F180`/`F18C`. These are not app-block values and the app does not cache them.
- **No OEM VBF contains this data** (nothing ships the PBL), so these values cannot be restored from a
  vendor file — **only from this owner backup**. Same for the VIN record.
- Confirmed on hardware: a bench `22 F111` returned `DV6T-14C245-FF` (`docs/sbl-upload-patch.md` §2),
  matching the literal exactly.

### 21.3 The module's identity disagrees with the vehicle as-built data (b)

The vehicle's as-built/configuration records list, under the BCM node:

| DID | As-built record | This module reports |
|---|---|---|
| `F111` ECU Core Assembly | `F1DT-14F119-EC` | **`DV6T-14C245-FF`** |
| `F113` ECU Delivery Assembly | `F1DT-14A073-EF` | **`DV6T-14A073-FK`** |

Neither `F1DT` string appears anywhere in `cflash.bin`, `dflash.bin` or `shadow.bin`. Since part
numbers are stored as plain ASCII in this image, a byte scan finding nothing is conclusive here.

`F111`/`F113` are **hardware** assembly numbers, so the disagreement is consistent with the fitted
module being a **replacement/donor unit** rather than the factory-fitted one. Note the as-built data
is not wrong across the board — its `F110` (`DS-JV6T-14A073-BB`) matches flash at `0x0134F6` exactly;
only the two hardware numbers differ.

### 21.4 Can these values be changed? (a)

Asked directly. The answer **splits by flash block**, and the split is decided by
`PBL_region_permission_table` (§2.3) — the same gate every memory operation passes through.

| Value | Address | Erase block | Permission region | Verdict |
|---|---|---|---|---|
| serial `F18C` | `0x006B10` | **L1** `0x4000–0x7FFF` | `0x0–0x7FFF` **flag 0** | ❌ refused |
| PBL ver `F180` | `0x006B20` | **L1** | flag 0 | ❌ refused |
| core asm `F111` | `0x006B68` | **L1** | flag 0 | ❌ refused |
| delivery `F113` | `0x006BA8` | **L1** | flag 0 | ❌ refused |
| **VIN** | `0x008000` | **L2** `0x8000–0xBFFF` | `0x8000–0x17FFFF` **flag 4** | ✅ **programmable** |

The boundary at `0x8000` is not incidental — it is the *exact* first address of the `flag=4`
programmable region. Ford drew the line so the VIN is writable and the identity strings are not.

**The four identity strings: not writable by any supported path.**

1. No UDS `0x2E` WriteDataByIdentifier service exists for them. (A scan for functions testing service
   byte `0x2E` returned 5 candidates, **all false positives** — `0x2e50`, `0x2e0` and similar
   unrelated constants. The PBL's service-permission table §6.2 lists no `0x2E` at all.)
2. `0x34` RequestDownload against any address `< 0x8000` is refused by
   `PBL_check_address_permission` — region flag 0.
3. They sit in erase block **L1**, which also contains **~3.9 KB of live PBL code and tables**
   (46 populated runs, incl. the service-permission table at `0x43C`). Flash erases per block, so
   changing one string means erasing working bootloader code and rewriting all of it.
4. Nothing in the app caches them, so there is no RAM shortcut — the readers fetch from flash on every
   request (§21.2).

**What *would* work, and its cost.** The MCU is **not censored** (§4: `NVSCC = 0x55AA55AA`, `NVPWD` at
the factory default), so the **JTAG/Nexus port is open**. A hardware debugger can erase and rewrite
block L1 directly, bypassing the permission table entirely — it is a PBL-level gate, not silicon.
That is genuinely available here, but note what it costs:

- The module is **unrecoverable-by-CAN** while L1 is blank — the reset vector is in L0, but the PBL
  code L1 holds is what answers diagnostics. Recovery then *requires* the debugger.
- It only makes sense with `cflash.bin` from this backup as the restore source, since **no OEM VBF
  contains the PBL**.
- It changes what the module reports about **hardware it is not** — see §21.3.

**Recommendation.** Don't. The mismatch in §21.3 is *diagnostic information*, not a fault: it records
that this is a replacement module. Making `F111`/`F113` report `F1DT-…` would not change any behaviour
— nothing in this firmware reads those strings except the DID readers — and would destroy the only
evidence of the module's true provenance. If some tool insists on matching part numbers, the correct
fix is to update the **vehicle's as-built record** to match the installed hardware, which is a
data-side change with no brick risk.

The VIN at `0x008000` is a different matter: it *is* in a programmable region, which is consistent
with the VIN being a normal service operation after module replacement.

> Practical note: **as-built part numbers cannot be used to identify which firmware a module is
> running.** Read `F188`/`F124`/`F10A` from the module itself (they reflect flash content), and treat
> `F111`/`F113` as describing the *hardware the DB expected*, not the hardware present.

---

## 22. The AES S-Box at `0x016760` — an orphan library table (a)

Raised by a binwalk hit. The table is **genuine** but does **not** mean this module does AES.

### 22.1 It is a real AES S-Box, and it is deliberate

Exact 256-byte match against a computed AES forward S-Box, and a verified permutation of `0..255`
(so not a coincidental byte run). It sits inside `0x010000..0x13FFFE`, i.e. **covered by the app's
internal `sum8`** — it was deliberately flashed as part of the application, not leftover debris.

### 22.2 …but it belongs to a lookup-table bank, not a cipher

The neighbourhood is not crypto code — it is a **contiguous bank of algorithm tables with zero
padding between them**:

| Address | Size | Table |
|---|---|---|
| `0x015F60` | 512 B | CRC-16, poly `0xA001` (reflected `0x8005`, IBM/Modbus) |
| `0x016160` | 512 B | CRC-16, poly `0x8005` non-reflected |
| `0x016360` | 512 B | CRC-16, poly `0x1021` (CCITT-FALSE) |
| `0x016560` | 512 B | CRC-16, poly `0x8408` (reflected `0x1021`) |
| `0x016760` | 256 B | **AES forward S-Box** |

A fifth CRC-16 table (`0x8408`) sits at `0x01C854`; the PBL keeps its own CCITT table at `0x00023C`.
The perfect back-to-back packing is the signature of **one library's constant pool** linked in
wholesale. The high entropy (7.2–7.8) that made the region look like key material is just what
densely-packed CRC tables look like.

### 22.3 There is no AES implementation in this image (a)

Five independent checks, all negative:

| Test | Result |
|---|---|
| Inverse S-Box (needed to decrypt) | **absent** |
| Round constants (Rcon `01 02 04 08 … 1b 36`) | **absent** |
| T-tables (all four rotations, computed from this S-Box) | **absent** |
| References to the table, across all **116,073** instructions (incl. `e_lis`/`e_add16i` split halves) | **0** |
| Functions with the AES round shape (≥4 indexed byte loads **and** ≥4 xors) | **0 candidates** |

Also: **0** functions mention both service `0x27` and NRC `0x33`, so there is no seed/key routine
consuming it either.

**Conclusion:** the linker kept the table (it is one object with the CRC tables) while the AES code
was never called — garbage-collected or never included. It is dead data.

> **Do not** infer from this table that the BCM does AES seed/key, secure boot, encrypted
> diagnostics, or rolling-code crypto. Nothing in this image implements any of them.

### 22.4 A false lead worth recording

A raw 4-byte-aligned pointer scan found `0x00016760` stored in the `.data` image
(flash `0x115DE8` → RAM `0x40004188`), which looked like the missing indirection — the same shape as
the Volcano descriptor anchor (§15.1), where exactly this pattern explained an unreferenced table.

It is a **false positive**: `0x00016760` is **92000 decimal**, a round number sitting in a run of
zeros, and **nothing references `0x40004188`** (checked across the whole `0x40004140..0x400041C0`
neighbourhood — 29 functions touch that area, none touch `+0x188`). A round decimal constant is a far
better explanation than a pointer nothing dereferences.

Method note: "value looks like an address" is the weakest form of evidence. Require a **consumer**
before believing a pointer — the same discipline that resolved §17/§18.

---

## 23. Full code sweep — closing the disassembly gap (a)

Prompted by the observation that the listing had large undecoded stretches. The app block was
**59.8 % undefined** (744 510 of 1 245 184 bytes). This section records why a linear sweep was
justified, how it was made safe, and what it did — and did not — change.

### 23.1 Why the normal routes were exhausted

Before sweeping anything, two cheaper and safer mechanisms were measured to exhaustion:

| Route | Result |
|---|---|
| Call/branch targets not yet disassembled | **2** (`0x0373AA`, `0x108040`) |
| Pointer-table targets (208 tables, 3 093 distinct targets) | **2 968 already code**; of the 125 left, only 2 had a valid prologue |
| Functions with an undisassembled tail | **0** |

Recursive descent was finished. Yet the undefined bytes begin with the *exact* prologues of this
compiler — so the gaps are **unreferenced code**, reachable by no static path. A linear sweep was the
only remaining route.

### 23.2 The prologue vocabulary (derived, not guessed)

Guessing entry-point signatures is how data gets disassembled as code. Instead the vocabulary was read
off the **2 402 functions Ghidra had already found**:

| First instruction | Share | First 2 bytes |
|---|---|---|
| `e_lis` | 34.5 % | `70 e8`, `70 68`, `70 c8` |
| `se_mflr` | 31.4 % | `00 80` |
| `e_stwu` | 8.3 % | `18 21`, `02 13` |

The top 12 two-byte signatures cover **86.7 %** of known functions.

> A pure signature scan was **rejected**: it yielded **16 728** candidates, because bytes like `00 04`
> and `48 00` occur constantly in data. Signatures were used only to place function entry points
> *inside ranges that had already passed the sweep quality gate*, never to decide what is code.

### 23.3 The safety model

Each undefined run (≥32 B, not padding) was disassembled, then **measured**, and kept only if
**coverage ≥ 98 % and zero bad instructions**; failing runs were reverted with `clearCodeUnits`.

| | Runs | Bytes |
|---|---|---|
| Committed | **646** | 650 896 |
| Rejected | **91** | 78 644 |

No rejected run contained a bad instruction — all were rejected on coverage, i.e. the gate fired on
*partial* decode, exactly the signature of data being read as code.

**The gate validated itself blindly.** It had no knowledge of any earlier layer, yet **7 of the 10
largest rejects** are structures previous sections independently proved are data:

| Rejected run | Coverage | Known to be |
|---|---|---|
| `0x017C10` | 68.3 % | TX descriptor array (§15) |
| `0x021318` | 92.5 % | DID handler table (§10) |
| `0x015F64` | 85.7 % | CRC-16 table bank + AES S-Box (§22) |
| `0x01FFCE` | 59.8 % | DID identifier array (§10) |
| `0x1161C4`, `0x116B78` | 95.7 / 93.2 % | `.data` init image (§12) |
| `0x0001B8` | 82.9 % | PBL permission + service tables (§2.3, §6.2) |

### 23.4 Result

| Metric | Before | After |
|---|---|---|
| Functions | 2 403 | **13 588** |
| Code units | 240 708 | 483 199 |
| User-defined symbols | 930 | 930 (intact — the sweep destroyed none) |
| Project size | 17 MB | 36 MB |

Quality: **40 of 40** randomly sampled functions decompiled without error. Median body size 22 bytes —
most of the new functions are small accessors, consistent with the signal-plane counts below.

### 23.5 What it changed — and what it did not

The sweep **did not** change any structural conclusion. Most importantly, with essentially the whole
image now disassembled:

| Band | Functions referencing it |
|---|---|
| RX/TX frame images (`0x40000600..0x40000D00`) | **1** |
| HS arrival flags | 2 |
| MS arrival flags | 0 |
| FlexCAN registers | **1** |
| Signal plane `0x40003C00` | 2 732 |
| Signal plane `0x40001E00` | 488 |
| Signal plane `0x40002800` | 238 |

This **upgrades §20.2 from an inference to a measurement over the complete image**: the unpack stage
is not missing because code was undisassembled. All runtime CAN access really is pointer-based, so no
amount of static reference scanning will find it — the remaining route is dynamic (§24).

The 11 185 new functions are overwhelmingly **feature/state-plane code**, which is where the module's
remaining unexplored logic lives.

### 23.6 Three pyghidra traps, all of which "succeeded" silently

The sweep hit three bulk-write traps — `os._exit(0)` truncating a large save, `getDomainFile().save()`
deadlocking against `GhidraProject`'s open transaction, and a nested `endTransaction(tx, False)`
rolling back **all 646 good runs** with the 91 bad ones. Each reported success on stdout while disk
kept the old counts.

They are general to any Ghidra write script in this repo, so they are documented once in
**`AGENTS.md` §2.1 (trap 3)** with the fixes. The rule that came out of it: **after any bulk write,
reopen the project read-only and re-read the counts.**

---

## 24. Peripheral census on the fully-swept image (a)

Re-asking "what hardware does this module actually drive?" now that the whole image is disassembled
(§23). The earlier peripheral scans saw ~2,400 functions; this one sees 13,588, and it changes the
answer substantially — **the LIN master driver and most of the PWM code were previously invisible**.

Method per the negative-evidence hierarchy: iterate every instruction and read resolved reference
targets, so `e_lis`/`e_add16i`-synthesised addresses are caught. Output: `work/owner/peripheral_census.json`.

### 24.1 The census

| Peripheral | Functions | Distinct registers | |
|---|---|---|---|
| eMIOS_1 | 53 | 38 | PWM + channel status |
| WKPU (wakeup) | 51 | 8 | |
| SIUL (pads/GPIO) | 39 | 71 | |
| ME (mode entry) | 31 | 72 | low-power/run modes |
| CGM (clocks) | 23 | 17 | |
| PIT / STM / INTC | 18 / 17 / 18 | 6 / 14 / 10 | timers, interrupts |
| ADC_0 / ADC_1 | 16 / 6 | 61 / 15 | |
| RGM / ECSM / SWT | 13 / 10 / 9 | 8 / 6 / 5 | reset, ECC, watchdog |
| **LINFlex_0** | **11** | **14** | **full LIN master** |
| CTU | 7 | 17 | ADC trigger unit |
| PCU / DSPI_1 | 6 / 5 | 3 / 6 | |
| FlexCAN_0/1/2 | 1 each | 1 each | pointer-based (§14.4) |
| LINFlex_1/2/3 | 1 each | 1–2 each | |

**Referenced nowhere at all:** eMIOS_0, SSCM, DSPI_2/3/4, **FlexCAN_3/4/5**. The unused FlexCAN
instances confirm the three-bus conclusion of §14.3 from the opposite direction — the silicon has six
controllers and this firmware drives exactly three.

### 24.2 The LIN master driver — the SWM bus (a)

`PTR_LIN0_base` @ `0x0001AE74` = **`0xFFE40000` = LINFlex_0**, verified from the image.

LINFlex_0 is the only instance used as a real bus master: it is the sole one where header and data
registers (`BIDR` +0x34, `BDRL` +0x38, `BDRM` +0x3C) plus status/error (`LINSR` +0x08, `LINESR` +0x0C)
are all driven. LINFlex_1/2/3 are touched by exactly **one** function (`LIN_read_bdrm_by_index`
@ `0x00033B2E`) and only at +0x16 and +0x3C.

Driver state is a small RAM block, `LIN0_driver_state` @ **`0x40007B40`**, touched by **67 functions**:

| Offset | Role |
|---|---|
| `+0x00` | state machine (values 0, 4, 9, 10 observed) |
| `+0x01` | last received byte (`LIN0_rx_byte`) |
| `+0x02` | transfer-valid flag (`LIN0_xfer_valid`) |
| `+0x03..05`, `+0x08`, `+0x0C..0E` | per-transfer state |

Two functions named from their behaviour:

- **`LIN0_read_response` @ `0x000FA876`** — writes `BDRL`/`BDRM`, sets state = 9, waits, then returns
  `LIN0_rx_byte` **only if** `LIN0_xfer_valid == 1`.
- **`LIN0_isr_or_poll` @ `0x000FAC3E`** — reads `UARTCR`/`LINSR`/`LINESR`; on error state = 10, else
  state = 4; writes `LINCR1` = `0x311` then `0x310` and clears status.

**Why this matters:** this is the bus the **steering-wheel module** sits on — the origin of the cruise
buttons the shipped `acc-fix` remaps. Before the sweep, **none of these 67 functions existed in the
project**, which is why `docs/030_composition_trace.md` could only trace the CAN side.

It also **re-confirms the acc-fix design decision**: **0 of the 67** LIN functions reference the
`0x030` TX image at `0x40000760`. The driver publishes into signal state and the Volcano packer
composes the frame later — exactly why the remap had to be done at the TX mailbox rather than
upstream.

### 24.3 eMIOS_1 — four PWM outputs (b)

eMIOS_1 is used; **eMIOS_0 is referenced nowhere**.

| Channels | Registers touched | Reading |
|---|---|---|
| **ch0, ch8, ch16, ch23** | `CADR` + `CBDR` + `CCR` | driven as **PWM** |
| ch1, 4, 5, 7, 10, 18, 20, 21, 22 | `CSR` only | status polled (inputs/flags) |

ch0 additionally exposes `CCNTR` and `+0x14` (read back as well as driven) — the shape of a
timebase/reference channel.

On a body controller the PWM channels are the dimmable loads (interior/instrument illumination and
similar). ⚠ **Physical pin assignment is not established here** — that needs the SIUL pad
configuration; see `docs/interior_button_gpio_trace.md` for the method. Stated at level (b).

**Attempted and failed: linking PWM channels to pads.** The obvious cross-reference — do the eMIOS
PWM functions also configure SIUL pads? — returns **0 shared functions for all four channels**. Pad
setup and channel programming live in different code, so the binding cannot be made this way. Level
(b) stands; resolving it needs the PCR *values* (see §24.5).

### 24.4 Other observations

- **I2C_0**: exactly one register (`IBAD` +0x00) referenced, from code in **no function**. Almost
  certainly dead init or a false positive, not a working I²C bus.
- **DSPI_1** is the live SPI (6 registers incl. `PUSHR`/`POPR` — actual data movement, 5 functions);
  **DSPI_0** has only `MCR`/`SR`/`RSER` and no data registers. DSPI_2/3/4 unused.
- **WKPU** with 51 functions and `WIFEER`/`WIFER`/`WIPUER` configured is consistent with the module's
  wake-on-input role (§12's retained-RAM/reset-cause logic).
- **ADC_0** touches 61 distinct registers vs ADC_1's 15 — ADC_0 is the primary measurement path.

### 24.5 SIUL pad usage — what is solid, and one failed method (a)/(b)

**Solid (a)** — these come from resolved references, not inference:

| | Count | Pads |
|---|---|---|
| Pads with a PCR (config) write | 35 | 0, 4, 12–19, 26, 30, 34, 40–43, 48, 57, 62, 63, 72, 73, 77, 93, 105–115, 123, 125, 133, 145 |
| Pads written via **GPDO** (outputs) | 11 | 0, 18, 34, 62, 77, 107, 109, 123, 125, 133, 145 |
| Pads read via **GPDI** (inputs) | 9 | 0, 4, 26, 41, 43, 48, 57, 73, 103 |

**Independent cross-validation:** the input list contains **26, 48, 57**, which §5 identified — from
entirely separate PBL code — as **PB10, PD9, PD0**, the programming-abort interlock inputs. Two
unrelated derivations agreeing on the same three pad numbers is strong evidence the decoding is right.
Pad 0 appears in *both* the output and input lists (bidirectional, or reconfigured at runtime).

**Failed method, recorded so it is not repeated:** an attempt to recover each PCR's *written value* by
scraping hex immediates from the preceding instructions produced results that looked plausible but
were **entirely wrong** — checked mechanically, **29 of 29** reported "values" were exactly
`0x40 + pad*2`, i.e. the scraper was reading the **PCR address being computed**, not the data written.
Recovering PCR values requires real dataflow (decompiler high-level output or a p-code walk), not text
matching on disassembly. The broken code was removed from `122_siul_pwm_pins.py` rather than left to
mislead.

### 24.6 PCR values recovered properly, and what they rule out (a)

Redone with the decompiler (`123_pcr_values.py`), which resolves the register dataflow: **33 pads**
with recovered constant PCR values, written by **14 functions**.

**The bitfield was derived empirically, not read off a datasheet.** An initial guess
(OBE = bit 10, IBE = bit 9) scored **0 consistent / 18 contradictory** against the pads independently
observed being driven via GPDO and read via GPDI. Testing the alternative gave:

| Assignment | Consistent | Contradictory |
|---|---|---|
| OBE = bit 10, IBE = bit 9 | 0 | 18 |
| **OBE = bit 9, IBE = bit 8** | **17** | **1** |

The single exception is pad 0, which appears in *both* the GPDO and GPDI lists (reconfigured at
runtime). Independent anchor: pads **26/48/57 = PB10/PD9/PD0**, documented in §5 as inputs with PCR
`0x0500` — and `0x0500` decodes as IBE under the winning assignment.

Recovered configuration:

| PCR value | Decodes as | Pads |
|---|---|---|
| `0x0200` | OBE (output) | 34, 62, 77, 107, 109, 123, 125, 133, 145 |
| `0x0600` | OBE (output) | 13, 14, 16, 40, 42, 63, 72 |
| `0x0A00` | OBE (output) | 113, 114, 115 |
| `0x0E00` | OBE (output) | 30 |
| `0x0100` | IBE (input) | 0, 4, 12, 41, 93, 105, 112 |
| `0x0500` | IBE (input) | 17, 26, 43, 48, 57, 73 |

Every recovered `0x0200` pad is in the observed-GPDO list and every `0x0500` pad is in the
observed-GPDI list — the values and the runtime usage agree.

> ~~**The finding that matters: `PA = 0` on all 33 pads.**~~ **⚠ RETRACTED — see §28.**
> The `PA = 0` result was an artifact of reading the wrong bits. This section's OBE/IBE positions are
> correct; its `PA` position is not. Every recovered PCR value has a zero low byte, so the field this
> pass read (`(v >> 5) & 7`) is *necessarily* zero on all of them — "PA = 0 everywhere" was a
> tautology, not a measurement. The real field is **bits 11:10**, and 15 of these 33 pads carry
> `PA != 0`. §28 has the corrected map.

### 24.7 ⚠ SUPERSEDED — "the mux path does not exist" was a decode bug (see §28)

Follow-up attempt to find whatever *does* set `PA != 0`. It reported a sharper negative than §24.6 —
**48 recovered values, `PA = 0` on every single one** across app and PBL — and concluded the mux path
was "genuinely not in any code that writes a SIUL PCR", leaving three untested candidates
(reset defaults, a non-PCR register block such as `PSMI`, BAM/censorship word).

**All of that is withdrawn.** The pass inherited §24.6's wrong `PA` bit position, so it re-measured
the same tautology 48 times instead of once. There was never a missing init path: `0x0072FC` muxes
the CAN pads exactly where this section said it didn't. §28 resolves it.

The section's own honesty check is what should have caught it, and is worth preserving as a lesson:

> *"pads 16 and 17 are configured here (`0x0600` / `0x0500`) and would be the natural CAN0 TX/RX
> candidates on this package — but they carry `PA = 0`. Either the pad numbering differs, or those
> pins are not CAN."*

Both offered explanations were wrong, and a third — *the decode is wrong* — was not on the list.
Pad 16 **is** `CAN0TX` and pad 17 **is** `CAN0RX`, confirmed against `BCM_CAN_Pins`. When a
cross-check contradicts a result on the one case you understand best, suspect the measuring
instrument before rationalising the data.

#### Two false positives discarded along the way

- **Flash `(pad, value)` table scan** reported "1,282 candidate tables". Worthless: the offsets
  advanced in **4-byte steps** — a sliding window recounting one region 128×, 127×, 126× — and the
  data at the top hit (`0x01C3A0`) is a plain `u16` sequence (`00A0 008D 00A3 0001 006D…`), not
  pad/value pairs. The filter accepted nearly any small value as "PA≠0".
- **A regex that found nothing.** The first version of `125_pa_field_test.py` reported "0 lines
  touching a PCR" across functions that provably write PCRs — because it matched only `0x…` literals,
  while the decompiler renders these as **`DAT_c3f90040`**. Fixed to match both forms, after which 53
  lines appeared. *A scan returning exactly zero on a target you know is non-empty is a bug in the
  scan, not a finding.*

---

## 25. Annotation state in the project

Audited by `work/owner/99_project_audit.py`, which **reads the database back** — these are not
self-reported script outputs:

| Check | Result |
|---|---|
| `Analyzed` flag | **True** |
| User-defined symbols | **1,092** (prefix families: `APP_did_`, `MB_CAN`, `PBL_`, `RX_img_`, `TX_img_`, `APP_`, `VOL_`, `SIUL_`, `RXsig_`) |
| `Note` bookmarks | **629** across 17 `OwnerFlash-*` categories |
| Key addresses spanning all 16 layers **without** a symbol | **0 of 20** |
| Functions after the full sweep (§23) | **13,588** — but see §29.2: ~8,200 are block-starts, not functions |

Annotation was applied by the `*_annotate_*.py` passes listed in §27, one per layer, each verified by
`04_verify_annotations.py`. Per-pass symbol counts are not reproduced here — they are a build log, and
the audit above is the load-bearing check.

The program entry point `0x0010F4A0` carries a **project orientation note**: layer map, the four
addresses the shipped mods use, bookmark categories, and the caveats that must be read before building
on this work. It is the first thing visible when the program opens in the GUI.

Bookmark categories (type `Note`): `OwnerFlash`, `OwnerFlash-UDS`, `OwnerFlash-APP`,
`OwnerFlash-SIGNAL`, `OwnerFlash-CAN`, `OwnerFlash-DIAG`, `OwnerFlash-PADS`.

The layer-17 pad annotations (§28) were applied by `132_annotate_l17_pads.py` and **verified by a
separate read-only read-back** (`133_verify_l17.py`): 6/6 pad-init functions renamed with plate
comments, 4/4 ground-truth-anchored pads carrying the right `PCR`/`PA`/function EOL comment and
`SIUL_PCR_*` label, and **75 `OwnerFlash-PADS` bookmarks** present on disk.

Machine-readable outputs are indexed in [`owner_artifacts.md`](owner_artifacts.md).

---

## 26. Open items / next layers

~~**Next: the unpack step (§20.2), by dynamic means.**~~ **RESOLVED in §33** —
`APP_rx_unpack_main` @ `0x048C6C`, reached from `APP_main` via the periodic spine (§32), with 332/332
descriptors sourcing RX frame-image bytes. No bench instrumentation was needed. The claim that static
analysis was "conclusively ruled out" was true only of **reference scanning**; the **call graph** had
never been walked. The arrival-flag lead in §17.4 was right: `VOL_frame_arrived` gates every unpack
group.

**CAN / gateway** — these are the same five items as **README §8 1–5**; that is the canonical list.
Kept here only as the pointers into this document's evidence:

| # | Item | Evidence here |
|---|---|---|
| 1 | ~~Find the **unpack stage**~~ **DONE** (§33) | §33.1–33.3 |
| 2 | Decode the **pack-spec** into `(start_bit, length, byte_order, scaling)` | §16.1 — read the three refuted models first |
| 3 | Determine **which paired `T` block is live** per bus | §19.4 — required before any record-level patch |
| 4 | Locate **MSX's control block** | §20.3 — its 23 RX records are scattered, not arrayed |
| 5 | Establish what the **361-record per-signal-bit array** is for | §15.3 — separate from both record arrays, covers ~6 frames |

**Application** (unique to this document — not in README §8)

6. ~~**Find the periodic-handler registry**~~ — **RESOLVED in §32.3.** There is no registry: the
   runtime bodies are the **46 callees of `APP_feature_periodic` `0x062848`**, reached from
   `APP_periodic_dispatch` `0x02F20A` ← an OS task. §8.4's "caller-less" reading was the §29.2
   sweep artifact; the backwards-walk of §32.1 recovers the real entries.
7. **Find who writes the event-history slots** (§12.3) — identifies the subsystem behind the 5 slots.
8. **Identify features by signal-plane footprint** using the corrected bands — now tractable: the 46
   callees of `APP_feature_periodic` (§32.3) are the features, each with its own signal-plane set.

**Bootloader / misc** (unique to this document)

9. **`PBL_verify_key` @ `0x36EC`** — the SecurityAccess seed/key algorithm. The app has its own gate
   too: 25 DIDs refuse with `0x33`.
10. **`PBL_init_context` timing constants** — confirm against a programming-session capture.
11. **Transceiver command word `0x777377`** — decode against the UJA1078A datasheet in the repo.
12. **Live confirmation of §6.4** — bench `0x35` against `0x140000` vs `0x010000`.
13. **`0x3C9EA`-region SIUL ISR/IRER/IFEER writes** — the app's external-interrupt config path.
14. **Where the app installs its INTC vectors** — not a flat table; likely programmed at runtime.
15. **The DFLASH record trailer algorithm** (§12.4) — not CCITT; try other CRC-16 variants or an
    additive checksum.
16. ~~**The SIUL pad-mux path** (§24.7)~~ — **RESOLVED in §28.** There was no missing path; the `PA`
    field was being read at the wrong bit position. All 35 configured pads are now mapped, with the
    three CAN bus pin-pairs matching `BCM_CAN_Pins` ground truth.
17. **Identify the 9 plain-GPIO outputs and 6 GPIO inputs** (§28.4) — **partly answered in §31.5**: all
    9 outputs (34/62/77/107/109/123/125/133/145) are driven only by the **PBL or MCU driver layer**,
    and none by feature code, so they are *not* vehicle loads. What they actually are (transceiver
    enables, boot-mode strapping, watchdog kick) is still open.
18. **The 720 `ISOLATED` blocks** (§29.1) — the genuine remaining code gap, down from an apparent
    11,185. Not reachable by reference scanning (§29.3).
19. ~~**Resolve the remaining 46 discrete-input bits**~~ — **largely DONE in §37**: 37 of the 60
    polled pads now have an unambiguous `(state cell, bit)`, both capture-verified pairs reproduce,
    and 31 of 33 agree with the independent text-walk. **23 remain unresolved** (§37.4) — multi-bit
    fields or commits outside the search window; deliberately absent rather than guessed.
20. **Identify the 5-input combination gate** (§31.3) — **structurally DONE in §38**: all five
    inputs resolved to pads 59/110/99/**92**/102 (`PD11`, `PG14`, `PG3`, `PF12`, `PG6`). What the
    combination *is* remains open (c) — four of the five pins have no established vehicle function;
    needs a capture with them exercised.
21. **The 101 unmodelled RX image bytes** (§33.5/§34.2) — narrowed: 48 of the original 149 are a
    join-key gap (record with empty `can_id_by_bus`), but 101 bytes in `0x400007D4..0x40000CA1` are
    read by the unpack stage and lie outside every frame span in the §17 map. `rx_frame_map.json`
    is a **lower bound** until this region is modelled.
23. **`tx_frame_map.json` is partial** (§36.2) — it models one controller's 15 mailboxes and does
    not include the record set owning the MS `0x3A` image at `0x40000A0F` that `rke-lock` drives.
    Find and decode that second TX record set. **Partly mooted by §39.2**: `tx_signal_dict.json` now
    covers 249 destination bytes across `0x40000748..0x40000C97` including the `0x3A` image, derived
    from the pack descriptors rather than the record set. The record set itself is still unlocated.
22. ~~**Build the full RX signal dictionary**~~ — **DONE in §34**: 346 descriptors decoded, 102 bound
    to 29 frames, 184 with signal-plane destinations (`rx_signal_dict.json`/`.md`). Still a lower
    bound — see §34.4 for what remains unbound.

**Raised by §39 (layer 29)**

24. ~~**Find the TX pack stage**~~ — **DONE in §39.1/39.2**: `VOL_sig_set8` `0x0FBDD4` and
    `APP_tx_compose` `0x04B7AA`, 384 injective source→destination pairs.
25. ~~**Close the central-lock module's ingress**~~ — **DONE in §40.3.** The entries are not reached
    by calls at all: the module is driven by a **request/event bus** (`0x40008E68..74`), and
    `APP_lock_request_dispatch` `0x87A0E` consumes bits 2/3/4/10 of `APP_req_word_70`. "0 callers"
    was the wrong question.
26. **Re-audit every "unreachable / no references" conclusion with the forwards fallthrough walk**
    (§39.3). `getCalledFunctions()` truncates at swept block boundaries, so *every* reachability
    measurement taken before layer 29 is a lower bound — including those that concluded static
    analysis was exhausted. This is the same error class as §33.3, one level up.
27. ~~**Read `FUN_00087A0E`'s branch conditions**~~ — **DONE in §40.1/40.3.** The blocker was a
    decompiler artifact, not a missing fact: the *disassembly* already carries resolved references
    (base `0x40008DE8`). It branches on bits 2/3/4/10 of `APP_req_word_70`. Now named
    `APP_lock_request_dispatch` and confirmed as **the** ignition intersection — though *which*
    branch (if any) is the RKE refusal is still open, see item 30.
28. **Explain the wide lock-command codes** (§39.4) — sharpened in §40.3: the enumeration is
    `0x02`, **`0x06`**, `0x1F`, `0x3F`, `(x<<1)|1`; the wire has only ever shown `0x01`/`0x02`, so
    d3 is a multi-code command byte of which captures have exercised two states.
29. **Correlate `APP_power_mode` `0x40001D85` (codes `0..4`) with the wire power state**
    (`ign_powermode_0x80.md`, MS `0x80` d2, codes `0..7`) from a capture — or demote the name.
30. **Test whether the ignition-on lock refusal is a missing code path rather than a gate**
    (§39.5, §40.5) — neither the execute strobe nor HS `0x030` d5 has any pack descriptor in this
    build, and §40.3 found every dispatcher arm *emits* a command rather than suppressing one.
    The decisive experiment is a **capture**, not more static work: at the refusal condition, does
    `APP_lock_command` change at all (a gate) or does d3 go to `0x01` with d1 bit 6 never strobing
    (a missing path)? The latter would make bus injection *necessary*, not merely convenient.
31. **Name the conditioned automatic-lock gate `APP_lock_condition_gate` `0x08A096`** (§40.4) —
    shape established (gear-lever + threshold + status), identity not; 3 of 4 inputs unknown.
32. **Decode the other three request words** (§40.2) — `APP_req_word_68`/`6C`/`74` are mapped per
    bit but unnamed. `req_word_68`'s value bits 5/7/8 are the most contended in the image
    (15/15/13 consumers) and are the natural next handle on the body-feature layer.

**Raised by §41 (layer 31 — the RKE receive chain)**

33. ~~**Close the last hop of the RKE→lock chain**~~ — **CLOSED in §43.** The writer of
    `APP_lock_request_input` is `0x9749A` (unswept block, found via p-code); its source
    `APP_lock_src_level` `0x40008EF7` is written by `APP_lock_src_producer` `0x978D2`. §42's "inert"
    conclusion is retracted. ~~One unknown remains: what sets `r6`~~ — **resolved in §44**:
    `r6` ← `APP_lock_src_origin` `0x40008D6B`, written by the state machine
    `APP_lock_src_state_machine` `0x95770`. The chain is **live end to end**. Two narrower unknowns
    replace it (both now open items 36 & 37): how that state machine is *scheduled*, and whether its
    input is the RKE path at all.

    <details><summary>Superseded text (kept for the record — its conclusion is <b>retracted</b>)</summary>

    > ~~**BOUNDED TO ONE BYTE in §42**~~
    > (`docs/tx_pack_stage.md` §9). Downstream is now fully proven from
    > `APP_lock_request_input` `0x40008D2C` → edge detector → `req_word_74` bit 10 → gate → producer →
    > `req_word_70` bit 3 → dispatch → `0x3A` d3 → DDM/PDM. **But that byte has no writer**, by four
    > controlled methods, and sits in `.bss` (zeroed every reset) → the path is *inert in this build*
    > (level b). Remaining static hypothesis: a write through a pointer held in a struct field, which
    > needs p-code dataflow. Cheaper: the on-vehicle correlation in §42.5.

    </details>
34. **Explore `0x099000..0x09C000` as its own layer** — the subsystem holding ~116 consumers of the
    RKE one-hot bits, with exactly **one** user symbol in the whole `0x095000..0x0B0000` span. It is
    on the runtime spine (`0x0992B2` ← `0x99A60` ← `0x9B41C` ← `0x9BA92` ← `APP_feature_periodic`),
    so it is reachable and unread. §42 narrowed what to look for: **which request bit this build
    actually uses for an RKE lock**. ⚠ That framing assumed §42's "inert" conclusion, now
    **retracted in §43** — the path IS live, so the real question is narrower: **what sets `r6` in
    `APP_lock_src_producer` `0x978D2`**, which is the last unknown in the chain. Also note `0x096E5E`/
    `0x097382` (a per-field latch-copy stage) sit just above it and are likewise unexplored.
35. **Identify the `0x0AC000..0x0AF000` RKE-code readers** — five functions decode
    `(code & 0xF) == {1,8,...}` but their true entries have no incoming edge of any kind
    (`196`), i.e. they sit in §29.1's ISOLATED class. Determine whether they are a dispatch-table
    target set or genuinely dead code from a different vehicle variant.

**Raised by §44 (layer 34 — the lock-request origin)**

36. ~~**How is `APP_lock_src_state_machine` scheduled?**~~ — **CLOSED in §45.1.** It *is* periodic:
    `APP_feature_periodic` `0x62848` → `0x96B9C` → … → `APP_lock_periodic_chain` `0x97382` →
    `0x95716` → the state machine (one routine split into 15 zero-caller blocks). The premise
    "0 callers" was **my own script's bug** — `getCallingFunctions()` skips call sites in unswept
    blocks; the reference manager had the caller (`0x97540`) all along.
37. ~~**Is `APP_lock_src_state_machine` actually the RKE path?**~~ — **ANSWERED: NO, in §45.2.**
    Two agreeing instruments (reference manager + flow-edge reachability), both controls passing,
    show the RKE demux outputs and the layer-33/34 lock-request input live in **disjoint code**. That
    chain is a *different* lock actuator. The real RKE join is **`APP_rke_to_body_cmd` `0x8D522`**,
    which reads `APP_rke_command_code` and writes a 3-bit command enum into `APP_body_cmd_bus`
    `0x40008E58` value bits 11..13 (§45.3).

**Raised by §45 (layer 35)**

38. **Decode `APP_body_cmd_bus` `0x40008E58` field consumers with a CORRECT rlwinm decoder.**
    Script `235`'s decoder ignored the **rotate amount** — which is what separates an `rlwinm`
    extract from an `rlwimi` insert — and emitted impossible ranges ("bits 17..13") plus a
    write-only verdict for bits 11..13. Per rule 8 that is a decoder bug, not a finding. Implement
    `value = (x >> (32-sh)) & mask(mb,me)` and re-run; this is the last hop between the RKE command
    enum and `APP_lock_command`.
39. **Identify which feature owns the layer-33/34 lock-request chain.** Now known *not* to be RKE.
    Candidates: door-ajar/door-switch lock, interior lock button, autolock-on-drive-away. Its input
    struct is `APP_lock_sm_input_struct` `0x40008CEC` (132 writer blocks); start there.
40. **Schedule of `APP_rke_to_body_cmd` `0x8D522`.** The flow-edge climb reached `0x93890` /
    `0x8F8F2` and stopped without touching a spine symbol — unresolved, not "unscheduled".

---

## 27. Reproducing

Scripts in `work/owner/` are **numbered in execution order** — run a phase's range in sequence. Each
script's docstring states what it proves; the layer it belongs to is the `§` column below.

```bash
cd BCM/Research && . .venv/bin/activate
```

| Phase | Scripts | Produces | § |
|---|---|---|---|
| Pre-project recon (no Ghidra) | `recon_layout`, `recon_pbl*` (6) | region fill map, RCHWs, PBL sections/tables/UDS/permissions | 0, 2, 6 |
| Project setup | `00_create_project` (destructive), `01_analyze`, `02_periph_scan PBL\|APP` | the project + auto-analysis | 0–1 |
| Layers 0–2 | `03`–`08` | PBL + UDS stack labelled, read back, analysed-flag + decompile-gap audits | 2–6 |
| Signal planes | `09`–`24` (16) | SRAM buckets, per-cell producers/consumers, signal plane | 7–8 |
| CAN role / DB cross-ref | `25`–`27` (3) | filter lists vs vehicle DBs, domains, 140 mailboxes labelled | 9 |
| Dispatch + diagnostics | `28`–`40` (13) | pointer tables, DID array, 476 reader bindings | 10–11 |
| Memory architecture | `41`–`46` (6) | as-built trace, retained RAM, event buffer | 12 |
| Validity layer | `47`–`53` (7) | RMW classification, republish template | 13 |
| CAN codec | `54`–`61` (8) | descriptor array, image writers, packer wiring | 14 |
| Descriptor chain | `62`–`72` (11) | bus map from CTRL regs, the `+0x44` retest, runtime anchor | 15 |
| Routing records | `73`–`79` (7) | marker alignment, 28-byte record columns | 16 |
| RX / TX frame maps | `80`–`88` (9) | `rx_frame_map.json`, `tx_frame_map.json`, acc-fix cross-check | 17–18 |
| Per-net binding + MSX | `89`–`98` (10) | MS/MSX blocks, `0x3A`, the unpack-gap measurement | 19–20 |
| Identity, tables, sweep, peripherals | `100`–`125` (26) | PBL identity, CRC/AES tables, full sweep, peripheral census, PCR values | 21–24 |
| Pad/mux map + connectivity | `126`–`135` (10) | corrected PCR bitfield, datasheet AF table, PSMI input map, pad-init functions, `pad_map.md`, orphan classification | 28–29 |
| Table-driven pad HAL | `136`–`145` (10) | the 149-record pad table, APC correction, generic pad reader, PI15/PF12 read sites + debounce | 30 |
| Discrete-input plane | `146`–`151` (6) | the 60-pad poll routine, switch state word, lock chain, GPIO-output negative | 31 |
| Runtime spine | `152`–`157` (6) | true entries behind swept blocks, climb to APP_main, periodic dispatcher + 3 layers, combo state machine | 32 |
| RX unpack stage | `158`–`161` (4) | unpack descriptors, coverage vs rx_frame_map, layer-22 annotation + read-back | 33 |
| RX signal dictionary | `162` (1) | all 346 unpack descriptors joined to CAN ids + signal cells | 34 |
| DBC join + annotation | `163`–`165` (3) | vehicle-DB signal join (runtime, /tmp), layer-24 annotation, read-back | 35 |
| TX signal annotation | `166`–`167` (2) | TX image bytes bound to DB signals, validated vs acc-fix bits | 36 |
| Mod-critical images | `168`–`170` (3) | 0x3A/0x100 images annotated, db-vs-vehicle comparison, precedence notes | 36.5 |
| Discrete-input bit map | `171`–`173` (3) | 37 pads resolved to state bits by disassembly, annotated, read back | 37 |
| Combination gate | `174`–`176` (3) | the 5 combo-gate inputs resolved to pins, annotated, read back | 38 |
| TX pack stage | `241`–`245`, `177`–`184` (13) | pack primitives, 384-entry signal map, two-phase spine correction | 39 |
| Request bus | `185`–`187` (3) | four request words decoded per bit, lock ingress | 40 |
| RKE receive chain | `188`–`198` (11) | MS `0x100` d6:d7 → 13-bit code → demux; the `get16` correction | 41 |
| Lock request hop | `199`–`209` (11) | edge detector, gates, producers; the (retracted) inert claim | 42 |
| The writer, by p-code | `210`–`220` (11) | `CALLOTHER` userop method; retraction of §42 | 43 |
| The origin | `221`–`226` (6) | copy network (4,292 edges), the state-machine writer | 44 |
| Scheduling + RKE join | `227`–`236` (10) | periodic proof, Path A ≠ Path B, `APP_rke_to_body_cmd` | 45 |
| Consolidation | `237`–`240` (4) | docs↔Ghidra audit, 15-block chain named, doc numbers verified | — |
| Audit | `99_project_audit`, `verify_pass.sh` | DB read-back + proprietary-identifier leak check | 25 |

246 numbered scripts in total (`00`–`245`). Ignore `fix_doc_heading*.py` / `fix_open_items.py` — one-off
editing helpers for this document, not part of the analysis.

> **The `163`–`170` passes need the vehicle CAN databases** at
> `/home/gl/Projects/ford/CANBus/` (`CAN-HS.dbc`, `CAN-MSX.dbc`, `CAN-MS.csv`). They are read at
> **runtime only**: no signal name is stored in any repo file, and `163_dbc_join.py` writes its join
> to `/tmp/rx_dbc_join.json`, deliberately outside the repo (§35.1). Without the databases the other
> passes still run and simply omit the names. Order: `163` → `164` → `165` (verify) → `166` → `167`
> (verify) → `168` → `169` (verify) → `170`.

Two scripts are re-run with arguments at different points — `36_force_functions.py 0xdbd34` (DID
dispatcher) and `36_force_functions.py 0xfc218 0xfc2f6 0xfc63e` (the CAN codec). Force-creating
functions Ghidra never discovered exposed a whole subsystem each time (§11.1, §14.1).

Read-only helpers, usable at any point:

```bash
python3 work/owner/gq.py dec 0x160 0x750    # decompile
python3 work/owner/gq.py dis|xref|funcs|stats
python3 work/owner/dump.py 0x140000 0x100   # hex dump by range
python3 work/owner/15_callgraph.py 0xADDR --src --depth=1
```

Only one process may hold the project at a time; every script closes it in a `finally`.
`gq.py`, `dump.py` and `02_periph_scan.py` open read-only.

> **pyghidra environment traps** (stale `Analyzed` flag, the JVM that never exits) are documented
> once in **`AGENTS.md` §2.1** — they apply to every pyghidra script in this repo, not just this
> analysis. Read them before writing a new one.

---

## 28. Layer 17 — the pad/mux map, and the decode bug that hid it (a)

Prompted by the question "the GPIO pins must be initialised *somewhere* — where?". They always were:
**`PBL_pads_init` @ `0x0072FC` and seven application functions.** §24.6/§24.7 had them in hand and
misread their data.

### 28.1 The bug: a field that could not be non-zero

`123_pcr_values.py` decoded the pad-alternate-function field as `(v >> 5) & 7`. Every PCR value this
firmware writes has a **zero low byte** — `0x0100`, `0x0200`, `0x0500`, `0x0600`, `0x0A00`, `0x0E00` —
so that expression is **identically zero for all of them**. "PA = 0 on 33 pads / 48 values / zero
exceptions" measured the extraction code, not the firmware.

The inconsistency was visible in the script's own docstring. §24.6 had *already* moved OBE and IBE
down from the datasheet reading because the evidence forced it (0 consistent → 17 consistent), yet
left `PA` at the position from the same disproved reading.

### 28.2 The correct frame, read from the manual

RM0037 §21.5.3.8 Figure 179 numbers bits **MSB-first** (`bit0` = MSB). Converting (`lsb = 15 - msb`):

| Field | RM bit | LSB-first |
|---|---|---|
| reserved / SMC / APC | 0 / 1 / 2 | — / 14 / **13** |
| **PA[1:0]** | **4–5** | **11:10** |
| OBE | 6 | **9** |
| IBE | 7 | **8** |
| ODE / SRC / WPE / WPS | 9 / 12–13 / 14 / 15 | 6 / 3:2 / 1 / 0 |

⚠ The `SMC`/`APC` positions here were corrected in **§30.3** (the row starts with a reserved bit, so
`APC` is bit 13, not 14). `PA`/`OBE`/`IBE` — everything this section's conclusions rest on — are
unaffected.

The same conversion reproduces the two positions §24.6 derived **empirically** — that agreement is the
cross-check that the conversion is right, not the datasheet's authority.

### 28.3 The falsifiable test (`126_pcr_bitfield_redo.py`)

Rather than assert the new decode, it was tested against evidence the PCR values know nothing about:
a pad muxed to a peripheral (`PA != 0`) must **never** be driven through the SIUL `GPDO` byte
registers, because the peripheral drives it instead.

| | in GPDO set | not in GPDO |
|---|---|---|
| `PA == 0` | **9** | 0 |
| `PA != 0` | 0 | **11** |

**Perfect separation, 20/20.** Under the old decode the same table is 9/11 vs 0/0 — no signal at all.

### 28.4 The pad map (level 5 — independently anchored)

35 pads, every one resolved against the datasheet AF table (`127_pad_altfunc_table.py`):

| pad | pin | PCR | dir | PA | function | configured by |
|---|---|---|---|---|---|---|
| 0 | `PA[0]` | `0x0100` | in | 0 | in: WKPU[19], E0UC[0] | `0x110FD6` |
| 4 | `PA[4]` | `0x0100` | in | 0 | in: LIN5RX, WKPU[9], E0UC[4] | `0x110FD6` |
| 12 | `PA[12]` | `0x0100` | in | 0 | in: EIRQ[17], SIN_0, E0UC[28] | `0x0072FC` |
| 13 | `PA[13]` | `0x0600` | out | 1 | **SOUT_0** (DSPI_0) | `0x0072FC` |
| 14 | `PA[14]` | `0x0600` | out | 1 | **SCK_0** (DSPI_0) | `0x0072FC` |
| **16** | `PB[0]` | `0x0600` | out | 1 | **CAN0TX** — HS-CAN | `0x0072FC` |
| **17** | `PB[1]` | `0x0500` | in | 1 | **CAN0RX** — HS-CAN | `0x0072FC` |
| **18** | `PB[2]` | `0x0600` | out | 1 | **LIN0TX** — SWM bus | `0x0FAD06` |
| **19** | `PB[3]` | `0x0100` | in | 0 | **LIN0RX** — SWM bus | `0x0FAD06` |
| 26 | `PB[10]` | `0x0500` | in | 1 | in: WKPU[8], ADC0_S[2] | `0x0072FC`, `0x110FD6` |
| 30 | `PB[14]` | `0x0E00` | out | 3 | **CS3_0** (DSPI_0) | `0x0072FC` |
| 34 | `PC[2]` | `0x0200` | out | 0 | GPIO[34] | `0x0072FC` |
| 40 | `PC[8]` | `0x0600` | out | 1 | **LIN2TX** | `0x110C4A` |
| 41 | `PC[9]` | `0x0100` | in | 0 | in: WKPU[13], **LIN2RX** | `0x110C4A`, `0x110FD6` |
| **42** | `PC[10]` | `0x0600` | out | 1 | **CAN1TX** — MS-CAN | `0x0072FC` |
| **43** | `PC[11]` | `0x0500` | in | 1 | **CAN1RX** — MS-CAN | `0x0072FC`, `0x110FD6` |
| 48 | `PD[0]` | `0x0500` | in | 1 | in: WKPU[27], ADC0_P[4] | `0x0072FC` |
| 57 | `PD[9]` | `0x0500` | in | 1 | in: ADC0_P[13] | `0x0072FC` |
| 62 | `PD[14]` | `0x0200` | out | 0 | GPIO[62] | `0x0072FC` |
| 63 | `PD[15]` | `0x0600` | out | 1 | **CS2_1** (DSPI_1) | `0x110ED2`, `0x1112E0` |
| **72** | `PE[8]` | `0x0600` | out | 1 | **CAN2TX** — MSX-CAN | `0x0072FC` |
| **73** | `PE[9]` | `0x0500` | in | 1 | **CAN2RX** — MSX-CAN | `0x0072FC`, `0x110FD6` |
| 77 | `PE[13]` | `0x0200` | out | 0 | GPIO[77] | `0x111B04` |
| 93 | `PF[13]` | `0x0100` | in | 0 | in: WKPU[16], E1UC[26] | `0x110FD6` |
| 105 | `PG[9]` | `0x0100` | in | 0 | in: WKPU[21], E1UC[18] | `0x110FD6` |
| 107 | `PG[11]` | `0x0200` | out | 0 | GPIO[107] | `0x0072FC` |
| 109 | `PG[13]` | `0x0200` | out | 0 | GPIO[109] | `0x111B04` |
| 112 | `PH[0]` | `0x0100` | in | 0 | in: **SIN_1** (DSPI_1), E1UC[2] | `0x0072FC`, `0x110ED2`, `0x1112E0` |
| 113 | `PH[1]` | `0x0A00` | out | 2 | **SOUT_1** (DSPI_1) | `0x0072FC`, `0x110ED2` |
| 114 | `PH[2]` | `0x0A00` | out | 2 | **SCK_1** (DSPI_1) | `0x0072FC`, `0x110ED2` |
| 115 | `PH[3]` | `0x0A00` | out | 2 | **CS0_1** (DSPI_1) | `0x0072FC`, `0x110ED2` |
| 123 | `PH[11]` | `0x0200` | out | 0 | GPIO[123] | `0x0072FC` |
| 125 | `PH[13]` | `0x0200` | out | 0 | GPIO[125] | `0x0072FC` |
| 133 | `PI[5]` | `0x0200` | out | 0 | GPIO[133] | `0x0072FC` |
| 145 | `PJ[1]` | `0x0200` | out | 0 | GPIO[145] | `0x0072FC` |

> **Level-5 validation.** `BCM_CAN_Pins` (vehicle-side ground truth, never consulted by the analysis)
> records `HS-CAN PB0/PB1 · MS-CAN PC11/PC10 · MSX-CAN PE8/PE9`. This map derives **exactly those six
> pins on all three buses**, from firmware bytes and the datasheet alone. That is the anchor; the rest
> of the table rides on the same decode.

### 28.5 Why input pins looked unconfigured — the other half of the mux

RM0037 §21.5.3.8, in the same section as the bitfield:

> *"Please note that input and output peripheral muxing are separate. For output pads: select the
> alternate function in PCR. For INPUT pads: select the feature location from PSMI register; set the
> IBE bit in the appropriate PCR."*

**`PA` muxes outputs only.** A peripheral *input* is routed by `PSMI0_3..PSMI60_63`
(`SIUL + 0x500..0x53C`) — a register block no earlier pass had examined, listed in §24.7 as untested
candidate #2. It is written in **four** places:

| Register | Value | Selects | Feeds |
|---|---|---|---|
| `PADSEL0` `0xC3F90500` | 1 | `PCR[43]` = `PC[11]` | **CAN1RX** |
| `PADSEL1` `0xC3F90501` | 0 | `PCR[73]` = `PE[9]` | **CAN2RX** |
| `PADSEL8` `0xC3F90508` | 2 | `PCR[112]` = `PH[0]` | **SIN_1** (DSPI_1) |
| `PADSEL58` `0xC3F9053A` | 0 | `PCR[41]` = `PC[9]` | **LIN2RX** |

Consistency check: all **4/4** explicit PSMI writes select a pad whose PCR has `IBE` set — and the two
halves are configured by *different* functions, so agreement is meaningful. `CAN0RX`/`LIN0RX` on
`PB[1]` need no PSMI entry: they are non-multiplexed inputs (the datasheet lists them with no `AFn`
marker), which is why only `IBE` is set there.

### 28.6 Two pads no constant-scan could ever see

`130` found 35 pads with a PCR *reference* but only 33 with a recovered *value*. The gap is pads
**18/19 — the LIN0 (SWM) pins** — because `LIN0_pads_and_ctrl_init` @ `0x0FAD06` writes them through a
pointer/mask table at `0x0001AE70`, not as immediates:

```c
*(ushort *)PTR_DAT_0001ae78 = DAT_0001ae8c | 0x200;   // PCR[18] = 0x0400|0x200 = 0x0600  LIN0TX
*(ushort *)PTR_DAT_0001ae7c = DAT_0001ae8e | 0x100;   // PCR[19] = 0x0000|0x100 = 0x0100  LIN0RX
```

Both the PCR addresses *and* the OR-masks live in that table (`131_lin_pads_and_final_map.py` reads it
out of the image; the table's `GPDO`/`GPDI` entries independently resolve to the same two pads).

**This is the SWM bus that `acc-fix` depends on** — now traced to physical pins `PB[2]`/`PB[3]`,
complementing §24.2's driver-level work.

### 28.7 Lesson

The `0x0200`-vs-`0x0600` distinction was in front of every previous pass; only the field width was
wrong. A scan whose result is **constant across every input** deserves the same suspicion §24.7 gave
a scan returning zero: *check whether the field you are reading can vary at all before reporting that
it doesn't.*

---

## 29. Layer 18 — the call-graph gap, and a correction to §23's headline (a)

§23 closed the **disassembly** gap. It did not close the **connectivity** gap, and its "13,588
functions" figure needs qualifying.

### 29.1 The measurement

`134`/`135`, over the whole image: **8,978 of 13,588 functions (66.1 %) have no caller.** Rather than
treat that as 8,978 undiscovered subsystems, each was classified by its *incoming references* and by
whether the preceding instruction falls through into it:

| Class | Count | Share | Meaning |
|---|---|---|---|
| `FALLTHROUGH` | **6,939** | 77.3 % | continuation of the preceding function |
| `BRANCH_INTO` | **1,297** | 14.4 % | a basic block of a neighbour, reached by a jump |
| `ISOLATED` | **720** | 8.0 % | no incoming reference of any kind |
| `DATA_PTR` | **22** | 0.2 % | entry stored in a table — genuinely dispatched |

### 29.2 ⚠ Correction to §23.4

**91.7 % of the callerless functions are not functions.** The linear sweep placed entry points on
prologue *signatures*, so it split existing functions at interior block boundaries. §23.4's "Functions
2,403 → 13,588" overstates what was discovered: the **code** it uncovered is real (that result stands,
and §23.5's measurements over it are unaffected), but the function *count* is inflated by ~8,200
block-starts.

The practical consequence is the useful part: the unexplored surface is **720 blocks, not 11,185**.

### 29.3 Where the connectable work is

Only **122 orphans (1.4 %)** have their entry address stored anywhere as a 32-bit word. Clustering
those pointer sites into runs of ≥4 consecutive words yields just **two** tables:

| Table | Entries | Note |
|---|---|---|
| `0x00020B80` | **486** | the DID handler table (§10) — mostly repeats of `0x0DBD34` |
| `0x0001FE14` | 4 | `0x107E8E`, `0x107F2E`, `0x107F88`, `0x0F6816` |

This independently re-confirms §14.4 from a third direction: **this firmware does not connect its
subsystems through stored function pointers in flash.** Binding the remaining blocks will not come
from more static reference scanning — consistent with §26 item 1's conclusion that the route left is
dynamic.

Artifacts: `orphan_tables.json`, `orphan_classes.json`.

---

## 30. Layer 19 — the table-driven pad HAL, and PI15/PF12 reversed (a)

§28 mapped the pads configured with **immediate** PCR addresses. This section finds the *other* pad
path — the one that configures **all 149 pads** and that no address-based scan can see — and with it
overturns the "CLOSED (negative)" verdict of `interior_button_gpio_trace.md`.

### 30.1 How it was found

Not by scanning for the target pads (that had failed repeatedly), but by asking which **SIUL access
is indexed rather than constant**. Exactly one exists (`137_parallel_gpio.py`):

```c
FUN_0003B4FC(desc):  *(ushort *)(&DAT_c3f90c40 + (uint)*desc * 2)   // PGPDI, index from data
```

That single dynamic access proved a generic, data-driven pad layer exists, and pulling its thread
led to the config table and the byte reader.

### 30.2 The pad HAL

| Function | Role |
|---|---|
| `FUN_0003F3B6` ← `APP_mcu_driver_init` | fetches the config header (fallback `0x00017374`), calls the applier, stores it at `0x40004214` |
| **`FUN_0003F3E0`** | **applies the whole table**: per record, optionally preset `GPDO`, then `SIUL_PCR[pad] = value`; finally copies 16 words into `PSMI` |
| `FUN_0003F440` / `FUN_0003F484` | runtime re-config of one pad / refresh of all pads (direction changes) |
| **`FUN_0003B4AE(pad)`** | **the generic reader** — returns `GPDI[pad]` if the pad's `IBE` is set, else `GPDO[pad]` |

Header `0x00017374` = `{count=0x95 (149), records=0x00017380, psmi_image=0x00017334}`.
Record = 4 bytes: `[u8 pad][u8 flags][u16 PCR]`. Records are a **perfect permutation of pads 0..148**
(`139_verify_pad_table.py` T1), and the table alone reproduces **6/6 CAN bus pins** (T3).

> **This is the general answer to "where are the GPIO pins initialised".** §28's 35 pads are the
> immediate-write path; this table is the default applied to *every* pad at boot. Neither is complete
> alone, and the 25 pads present in both differ mostly in the low byte (`SRC`/`WPE`/`WPS`) — the table
> is the boot default, later code refines individual pads.

### 30.3 ⚠ Correction to §28.2 — APC is bit 13, not bit 14

`140` classified 13 pads as "fully disabled"; all 13 carried `PCR=0x2000` and all 13 are **ADC-capable
pins**. Disabling both digital buffers and setting `APC` is exactly how an analog input is configured,
so `0x2000` *is* `APC`. RM0037 Fig.179's bit row begins with a reserved bit before `SMC`:

| | RM bit (MSB-first) | LSB-first |
|---|---|---|
| reserved | 0 | 15 |
| SMC | 1 | **14** |
| APC | 2 | **13** |

Test: `APC = bit 13` → 15 pads set, **15/15 ADC-capable, 0 false**; `APC = bit 14` → 0 pads set
(`141_apc_bit_correction.py`). **`PA`, `OBE`, `IBE` are unchanged, so every §28 conclusion stands.**
Re-classified, the table holds 71 inputs, 34 output+readback, 28 outputs, 15 analog, and exactly
**1** truly-off pad (24, the 32 kHz oscillator pin).

> A second lesson of the same family as §28.7: `139`'s test T4 ("APC never set on a non-analog pin")
> **passed vacuously** — nothing is ever set at bit 14, so the check could not fail. A test that
> cannot fail is not evidence.

### 30.4 PI15 and PF12 — configured, polled, debounced

| | PI15 (LOCK) | PF12 (UNLOCK) |
|---|---|---|
| Record | `8f 41 0100` @ `0x0175BC` | `5c 82 0100` @ `0x0174F0` |
| PCR | `0x0100` → **IBE**, PA=0, APC=0 | `0x0100` → **IBE**, PA=0, APC=0 |
| Read as | `FUN_0003B4AE(0x8F)` — **9 sites** | `FUN_0003B4AE(0x5C)` — **5 sites** |
| Debounce reg | `0x40004300` | `0x400042A4` |
| State bit | `0x40003AA5` **bit 5** | `0x40003AA5` **bit 4** |

Both read sites are structurally identical:

```c
if (FUN_000414CC(2) == 0)  goto skip;          // same enable gate
if (DAT_40003D0C < 4)      goto skip;          // same power/mode gate
v = FUN_0003B4AE(pad);
s = (s & 3) << 1 | LZCOUNT(v) >> 5;            // 3-bit shift register
if (s == 0) state &= ~bit;                     // stable -> update bit 4 / bit 5
```

`LZCOUNT(v) >> 5` is the compiler's idiom for `v == 0` (clz(0)=32, 32>>5=1), so the bit shifted in is
the **inverted** pin level — an **active-low** input, i.e. a switch to ground. Two adjacent bits of one
state byte, fed through identical gates by two pins, is the signature of a **paired LOCK/UNLOCK
switch**. `FUN_00050726` then reads both bits and repacks them into the signal plane.

### 30.5 Why this was missed four times

Both the pad number and the PCR value are **data**; the register addresses are computed
(`&SIUL_PCR_PA0 + pad`). **No PI15/PF12 register address exists anywhere in the image** — the literal
scan was *correct* and its interpretation was wrong. §3.1 and `owner_backup_analysis.md` §5 re-ran the
same method, so they multiplied confidence without adding independence.

The identical blind spot had already been recorded **twice** — the WKPU driver
(`interior_button_gpio_trace.md` §2a) and the LIN0 pads (§28.6) — in the very document whose headline
conclusion it invalidated.

> **Rule:** "no address for X appears in the image" is evidence about *addressing style*, not about
> whether X is used. On this firmware, absence of a constant is the **expected** case: the CAN codec
> (§14.4), WKPU, the LIN pads and now the whole pad layer are all table-driven. Never close a question
> on an address scan alone.

### 30.6 What this opens

The interior-lock shortcut is **not** closed. PI15/PF12 are inputs, so the move is not to "drive" them
but to force the debounced state — `0x40003AA5` bits 4/5, or the consumer `FUN_00050726`. This is a
plausible alternative to the `rke-lock` `0x3A` bus injection, and it needs no bench measurement to
explore. Not yet attempted.

---

## 31. Layer 20 — the discrete-input (switch) plane and the central-lock chain (a)

Follow-on from §30: having proved PI15/PF12 are polled, trace the whole cluster they belong to.

### 31.1 It is ONE polling routine, not 17 functions

`146` reported 17 "functions" calling the pad reader, with **strictly nested** pad counts
(55, 50, 37, 28, 27, 21, 20, 16, 14…). That is the §29.2 signature exactly: `147` confirms the nine
big blocks are **byte-contiguous with 0 callers each**, i.e. one routine entered at **`0x04152E`**
that the linear sweep split at interior branch targets. Each "function" is really a *suffix* of the
same code, which is why decompiling a later block re-lists all the pads the earlier ones read.

> **Do not report these as separate features.** The same artifact will appear anywhere the sweep hit
> a large switch-polling loop.

### 31.2 The discrete-input plane

The routine polls **60 distinct pads** through `FUN_0003B4AE(pad)`, each with the same
gate → read → 3-bit debounce → commit-bit shape (§30.4). The debounced levels land in a
**4-byte switch state word at `0x40003AA4..A7`** (plus some per-input bytes elsewhere).

| | |
|---|---|
| Polling entry | `0x04152E` |
| Pads polled | 60 |
| State word | `0x40003AA4..0x40003AA7` (big-endian: `AA4`=bits 31..24 … `AA7`=bits 7..0) |
| Debounce regs | one 3-bit shift register per input, in `0x400042xx`/`0x4000430x` |

**PI15 → `0x40003AA5` bit 5 · PF12 → `0x40003AA5` bit 4**, both confirmed at the **disassembly**
level (`149`): the commit is `e_rlwimi r5,r0,0x5,0x1a,0x1a` (insert bit 5) / `…,0x4,0x1b,0x1b`
followed by `se_stb r5,0x1(r30)` → `0x40003AA5`.

> ⚠ **`148`'s full 48-pad bit map is NOT reliable.** Its "walk forward from the read to the first
> masked commit" heuristic produced a **non-injective** map — 5 word bits claimed by two pads each
> (`149` §1). A pad→bit map must be injective, so those are parser errors. Only the two
> disassembly-confirmed pairs above are established (level a); the other 46 are a lead (level c).
> `switch_state_bits.json` is retained for the leads, clearly marked.

### 31.3 A multi-switch combination gate

`FUN_000506D6` tests five bits of the switch word at once:

```c
return (Ram40003aa4 >> 4 & 0x92021) == 0x92021;   // word bits 4, 9, 17, 20, 23
```

Word bit 20 is **PF12/UNLOCK**. The other four are among `148`'s unconfirmed set, so the *identity*
of this combination is not yet established — but its **shape** is: a simultaneous multi-input
condition, the classic form of a service/diagnostic or anti-theft combo. Worth resolving.

### 31.4 The chain, as far as it goes inside the BCM

```
PI15/PF12 pad ──FUN_0003B4AE──▶ debounce (0x40004300 / 0x400042A4)
            ──▶ switch word 0x40003AA5 bits 5/4
            ──▶ FUN_00050726 repack:  bit5→dest bit2, bit4→dest bit4
            ──▶ application state plane 0x40003B8x/0x40003B9x + 0x40003D0F
            ──▶ (Volcano codec) ──▶ CAN
```

`FUN_00050726` is itself a 0-caller block of a larger routine starting `0x05071A`. It reads all four
switch bytes and redistributes bits into **15 cells** of `0x40003B8x..0x40003B9x`, which are
wide-fan-in application state cells (9–55 referencing functions each) — the feature state plane, not
a CAN structure.

**The routine touches ZERO frame-image cells** (`150` §4), exactly as §14.4 requires: application code
never writes frame images; the codec packs them from the signal plane on the next TX.

### 31.5 ⚠ Negative result: the BCM does not drive the lock motors from GPIO

The natural hypothesis — interior button → BCM logic → lock-actuator output pin — is **false on this
module**. `151` cross-referenced the 9 plain-GPIO outputs of §28.4 against the lock state cells:

| Output pad | Driven by | Nature |
|---|---|---|
| 34, 107, 133, 145 | `PBL_pads_bootmode` `0x006E00` | bootloader |
| 34, 62, 123, 125 | `PBL_pads_init` `0x0072FC` | bootloader |
| 62 | `PBL_pad_PD14_low/high` | bootloader (toggled line) |
| 77 | `FUN_0011128C` | MCU driver layer |
| 109 | `FUN_001111F0` | MCU driver layer |

**Functions that touch lock state *and* drive a GPIO output: 0.** Every GPIO output belongs to the
PBL or the MCU driver layer; none is a body load. So this BCM **gateways** the lock request onto the
bus and the door modules actuate — which is precisely why `rke-lock` had to inject MS-CAN `0x3A`
(`docs/rke-lock.md`), and independent confirmation that the bus-injection design was the right call.

This also partly answers **open item 17**: the 9 GPIO outputs are *not* vehicle loads.

### 31.6 What this changes for the interior-lock shortcut

§30.6 proposed forcing the debounced state bit. §31 sharpens it — three viable injection points, in
increasing distance from the pin:

1. **`0x40003AA5` bit 5/4** — the debounced switch state. Overwritten by the poll loop every cycle,
   so a patch must either write it after the commit or fake the pad read.
2. **`FUN_00050726`'s output bits** in `0x40003B8x` — past the debounce, one repack away from the
   feature logic.
3. **The `0x3A` TX mailbox** — what `rke-lock` already does, proven on the vehicle.

Route 3 remains the shipped solution. Routes 1–2 are *cheaper in bytes* but sit inside a 0-caller
swept-block region, so hooking them needs the entry (`0x04152E` / `0x05071A`) re-derived carefully.
**Not attempted; no evidence yet that 1 or 2 is better than the working mod.**

---

## 32. Layer 21 — the runtime spine: from `APP_main` to the feature modules (a)

§31 left the discrete-input cluster floating: its blocks had no callers. This section connects it —
and, in doing so, recovers the **periodic architecture of the whole application**, which answers
open item 6 ("find the periodic-handler registry") and explains §7.4/§8.4's missing feature bodies.

### 32.1 The method that unstuck it: recover the true entry, then climb

§29.2 predicted this: the linear sweep put entries on *prologue signatures*, so a real function got
split into blocks and only the **first** kept its callers. So before asking "who calls this?", walk
**backwards over contiguous 0-caller blocks** to the real entry (`152_true_entries.py`):

| Seed (what §31 saw) | True entry | Recovered by |
|---|---|---|
| `0x04152E` poll routine, 0 callers | **`0x041526`** (`e_stwu r1,-0x20(r1)`) | called by `0x0449C4` |
| `0x05071A` repack, 0 callers | **`0x0506F8`** (`se_mflr r0`) | called by `0x050954` |

The true entries are **8 and 34 bytes earlier** — the sweep had cut each function's prologue off from
its body. Applying this at every level (`153_callgraph_up.py`) reaches `APP_main` in 2–4 hops.

> **Generalise this.** Any "0-caller" finding in this project is suspect until the backwards walk has
> been applied. It is cheap, and here it converted two dead ends into a full call path.

### 32.2 The spine

```
APP_reset_entry 0x10F4A0
  └─ APP_main 0x02F12E
       ├─ APP_wake_init / APP_mcu_driver_init / APP_can_gateway_init / APP_feature_init
       ├─ APP_os_activate_task(0..9)
       └─ APP_os_start ─▶ [RTOS task] ─▶ APP_periodic_dispatch 0x02F20A
                                           │  switch (APP_periodic_mode 0x40004103)
                                           ├─ APP_input_acquire    0x0449C4   (10 callees)
                                           ├─ APP_signal_process   0x05799C   (12 callees)
                                           ├─ APP_feature_periodic 0x062848   (46 callees)
                                           ├─ 0x0D472A, 0x061C26, 0x02E71E, 0x02EA2A
```

**`APP_periodic_dispatch` @ `0x02F20A`** is the hinge of the whole application — where the RTOS meets
the feature code. It is mode-switched on `APP_periodic_mode`:

> ⚠ **INCOMPLETE — corrected in §39.3.** What follows is only the **first of two phases**. The
> routine continues by *fallthrough* at `0x2F262` into a **second** switch on the same mode cell,
> dispatching an **egress twin** of each layer below (`0x449F2`/`0x579D6`/`0x62914` + per-mode
> variants). The acquire half feeds the RX unpack stage; the egress half feeds the **TX pack stage**
> (`APP_tx_compose` `0x4B7AA`, §39.2), which was entirely unknown when this section was written. The
> real tick is *read inputs → unpack RX → run features → **pack TX***. The function is now named
> `APP_periodic_task`. Nothing in the table below is wrong; it is half the picture.

| mode | dispatched |
|---|---|
| 0 | input_acquire, signal_process, `0xD472A`, `0x2EA2A`, **feature_periodic** |
| 1 | input_acquire, signal_process, `0x2EA2A` (reduced set — no feature layer) |
| 2 | `0x61C26` first, then input_acquire, signal_process, `0xD472A`, `0x2EA2A`, `0x2E71E` |
| 6 | as mode 2 without `0x61C26` |
| other | **return** — module idle |

It has **no caller**: it is reached from one of the ten OS tasks, consistent with §7.3's RTOS model.

### 32.3 The three periodic layers

The spine is three periodic layers (§32.3) — but see **§39.3**: each has an *egress* twin, so the
complete list is six, and the missing three are the transmit path.

| Layer | Entry | Callees | Character |
|---|---|---|---|
| **Input acquisition** | `0x0449C4` | 10 | reads hardware → state/signal planes. Contains `APP_discrete_input_poll` (60 pads) and `0x048C6C` — an **11 KB** routine with **197** refs into signal plane `0x40002800` |
| **Signal processing** | `0x05799C` | 12 | transforms signals; contains the switch-state repack chain |
| **Feature periodic** | `0x062848` | **46** | the body-feature runtime bodies |

> **This resolves open item 6 and corrects §8.4.** §7.4 found 83 feature modules whose `init(1)`
> constructors only zero state, and §8.4 concluded the runtime bodies were "caller-less, possibly
> undiscovered". They were neither missing nor undiscovered — they are the **46 callees of
> `APP_feature_periodic`**, and nearly every one references the signal planes
> (`0x40001E00`/`0x40002800`/`0x40003C00`). This is the feature↔signal-plane boundary in one place.

### 32.4 The combination state machine (a)

Directly above the repack sits **`FUN_00050954`**, a 3-state machine driven by
`APP_switch_combo_gate` (§31.3, the 5-input combination incl. PF12/UNLOCK):

```
state 0 (idle):   combo ? count++ (cap 2000) : count = 0
                  repack(1); 0x40003C48 &= ~0x40
                  if door_fn() -> state 2, count=0;  elif count >= 2000 -> state 1
state 1 (active): combo ? count = 0 : count++ (cap 2000)
                  repack(0); 0x40003C48 |= 0x40          <-- inverted repack + flag SET
                  if door_fn() -> state 2;  elif count >= 500 -> state 0
state 2:          repack(1); clear flag; if !door_fn() -> state 0
```

Cells: state `0x4000452D`, edge flag `0x4000452C`, hold counter `0x40007C64` (private to this
function), output bit `0x40003C48` bit 6 — a signal-plane byte shared with **16** functions.
`FUN_0005092C` wraps `FUN_00043C9C`, a door/latch status read.

**Reading:** holding the 5-switch combination for **2000 periodic ticks** latches a mode that
*inverts the repack argument* and raises a signal-plane flag; it drops out after **500** ticks without
the combo, or immediately on the door event. That is the shape of a **service / transport / lock-inhibit
mode toggle**. The exact tick period is not yet measured, so the real-world hold time is unknown —
stated at level (b) pending the OS tick rate.

### 32.5 Annotations

`156_annotate_l21_runtime.py` names the spine and the discrete-input RAM;
`157_verify_l21_and_combo.py` **reads it back from disk** — 8/8 functions named with plate comments,
2/2 data labels, 13 `OwnerFlash-RUNTIME` bookmarks, all checks passed.

| Address | Name |
|---|---|
| `0x02F20A` | `APP_periodic_dispatch` |
| `0x0449C4` / `0x05799C` / `0x062848` | `APP_input_acquire` / `APP_signal_process` / `APP_feature_periodic` |
| `0x041526` / `0x03B4AE` | `APP_discrete_input_poll` / `APP_pad_read` |
| `0x0506F8` / `0x0506D6` | `APP_switch_state_repack` / `APP_switch_combo_gate` |
| `0x40003AA4` / `0x40004103` | `APP_switch_state_word` / `APP_periodic_mode` |

### 32.6 Where to dig next

The highest-value unread aggregators, by fan-out and signal-plane contact:

| Function | Size | Why |
|---|---|---|
| `0x048C6C` | **11 KB** | 197 refs into `sig2800` — the largest single input-processing routine in the image |
| `0x062848`'s 46 callees | — | each is one body feature; naming them names the features |
| `0x0D472A` | 350 B | in every dispatch mode, touches `state4000` + `sig3C00` |
| `0x04D1C2` | 770 B / 29 blocks | 32 refs into `sig3C00` |

---

## 33. Layer 22 — the RX unpack stage, found via the call graph (a)

**README §8 item 1 / open item 1 is resolved.** §20.2 and §23.5 concluded the unpack stage could not
be found statically and needed bench instrumentation. That conclusion was **true of reference
scanning and false of the call graph** — and §32's spine walked straight into it.

### 33.1 What it is

**`APP_rx_unpack_main` @ `0x048C6C`**, reached as
`APP_main → APP_periodic_dispatch → APP_input_acquire → 0x048C6C`. ~11 KB over 5 swept blocks. The
body is one pattern repeated per signal:

```c
if (VOL_frame_arrived(&flagdesc))                 // test + clear arrival flag
    DAT_40002xxx = VOL_sig_get8(&PTR_DAT_00142xxx);   // extract one signal
```

with three primitives:

| Function | Meaning |
|---|---|
| **`VOL_sig_get8`** `0x0FBB62` | `(*(byte*)d[0] & *(byte*)(d+0x0C)) >> (*(byte*)(d+0x0D) & 31)` |
| **`VOL_sig_get16`** `0x0FBB38` | `CONCAT11(*(byte*)(d+0x0C) & *(byte*)d[0], *(byte*)(d[0]+1))` — 16-bit BE |
| **`VOL_frame_arrived`** `0x048C40` | test-and-clear the frame's arrival flag (§17.4) |

Descriptor: **`+0x00` = pointer to the source byte in the RX frame image, `+0x0C` = mask,
`+0x0D` = right shift.**

### 33.2 The evidence

| Measure | Result |
|---|---|
| Descriptors in `0x048C6C` | 332 |
| Whose source lies in the RX frame-image band `0x40000600..0CFF` | **332 / 332** |
| Signal-plane destinations written | 242 |
| Unpack routines in the whole image (callers of the primitives) | **30** |
| Distinct RX source bytes across all 30 | 221, spanning `0x40000678..0x40000CA1` |

332/332 is the load-bearing number: a descriptor table that *always* points into the frame-image band
is the unpack stage by definition.

### 33.3 Why it hid from every scan

The descriptor holds the frame pointer **in data**. No function references a frame image absolutely,
so §23.5's measurement ("1 function touches frame images") was correct — and said nothing about
whether unpacking exists. Exactly the §30.5 blind spot again, now on the last open CAN item:

> **an address scan measures addressing style, not usage.** The call graph was never exhausted.

### 33.4 ⚠ The two acc-fix bytes are NOT unpacked — and that is consistent

`0x40000707` (`0x0C0` d0) and `0x40000705` (`0x060` d6) appear in **no** descriptor. This is not a
coverage failure:

- both lie **inside** the covered range `0x40000678..0x40000CA1`;
- their **immediate neighbours are unpacked** (`0x706`, `0x708`, `0x70D`, `0x6FF`).

So the BCM **receives** those frames — the RX copier writes them into the image, which is exactly how
`acc-fix` reads them — but **extracts no signal from those two bytes**, because this ECU has no
feature that consumes them. *Being in the RX image and being unpacked are different things.* This
independently explains why acc-fix had to read the image directly, and why doing so is safe: nothing
else in the firmware is looking at those bytes.

### 33.5 The `rx_frame_map` discrepancy, now split into two causes (§34.2)

An earlier draft reported "101 unpacked bytes absent from `rx_frame_map.json`" as a single anomaly.
§34's join shows it is **two different things**, and one of them was a reporting error:

| | Count |
|---|---|
| Unpack source bytes that join to a CAN id | 72 (102 descriptors) |
| **In the map, but the record has an empty `can_id_by_bus`** | **48** |
| Genuinely absent from the map | 101 |

The 48 were never "missing" — the byte *is* in `rx_frame_map.json`; its mailbox record simply carries
no CAN id (e.g. `0x40000678`, mailbox 63), so the **join key** is absent, not the byte. The remaining
**101 lie entirely outside every mapped frame span** (`0x400007D4..0x40000CA1`), i.e. a genuinely
unmodelled image region — open item 21 stands, but is now precise. `rx_frame_map.json` remains a
lower bound.

### 33.6 What this unlocks

The descriptor tables are a **machine-readable RX signal dictionary**: 221 source bytes → 242 signal
cells, each with mask and shift. Decoding all 30 routines' descriptors and joining them to
`rx_frame_map.json` would give `(CAN id, byte, mask, shift) → signal cell` for the whole receive
path — the RX counterpart of §18's TX map, and the natural next step.

---

## 34. Layer 23 — the RX signal dictionary (a)

Open item 22. Decodes every unpack descriptor in the image and joins it to §17's RX frame map,
producing the receive-side counterpart of §18's TX map.

### 34.1 The dictionary

`162_rx_signal_dict.py` → `work/owner/rx_signal_dict.json` + `rx_signal_dict.md`.

| Measure | Value |
|---|---|
| Blocks calling an unpack primitive | 33 (30 true routines) |
| Descriptors decoded | **346** |
| Joined to a CAN id | **102** across **29 frames** |
| With a resolved signal-plane destination | **184** |

Each row is `(CAN id, byte index, mask, shift, width) → signal cell`, e.g.

| CAN id | byte | mask | shift | signal cell |
|---|---|---|---|---|
| `0x0C0` (MB30) | d1 | `0xE0` | 5 | `0x40002E1B` |
| `0x160` | d6 / d2 / d5 / d4 | `0x78`/`0xFF`/`0xFF`/`0x03` | 3/0/0/0 | 4 signals |
| `0x010` | d6 / d4 / d4 | `0x7F`/`0x7F`/`0x80` | 0/0/7 | 3 signals |

> **Independent cross-check.** The dictionary places `0x0C0` on **mailbox 30**. `AGENTS.md` Step D
> records "In `-AD`: MB30" for that frame, derived years earlier from the acceptance-filter list and
> reception descriptors — a completely separate route. The unpack descriptors agree.

### 34.2 Item 21 resolved into two causes

See §33.5: 48 of the "missing" bytes are present in the map under a record with an **empty
`can_id_by_bus`** (join-key gap, not a data gap); 101 are genuinely outside every mapped frame span.
Only the latter is a real open question.

### 34.3 Four parser bugs, all caught by cross-checks rather than shipped

Recorded because each produced a confident, wrong number:

1. **0 joins out of 414 addresses.** The loader looked for a flat `can_id` key; the real schema puts
   the id in **`can_id_by_bus`**. A join returning exactly zero against an overlapping key space is a
   bug in the join (AGENTS.md rule 8) — not a finding about the firmware.
2. **`dest` = 0 for all 346 descriptors.** The decompiler routes the result through a temporary
   (`uVar5 = get8(...); DAT_x = uVar5;`), so a single-line regex matched nothing. Fixed by tracking
   temp→descriptor then temp→destination: 184 destinations.
3. **Rows triplicated (777 for 346 descriptors).** `rx_frame_map.json` contains duplicate records per
   mailbox; binding lists needed de-duplication.
4. **`0x40000678` reported "unmapped" while being in the map** — the `setdefault` kept only the first
   binding per address, discarding valid joins. This is what made §33.5's original framing wrong.

### 34.4 What is still unbound

162 descriptors (346 − 184) have no recovered destination, and 244 do not join to a CAN id — mostly
the 101 unmodelled bytes plus descriptors whose destination is written through a pointer the text
scan cannot resolve. The dictionary is therefore a **verified lower bound**, not a complete map.

---

## 35. Layer 24 — project annotation: purposes, debounce, and CAN signal meanings (a)

Everything from §30–§34 is now in the Ghidra database, together with **signal meanings resolved
against the vehicle CAN databases**.

### 35.1 Confidentiality model

The vehicle databases are proprietary, and the Ghidra project **is git-tracked**. The split used:

| | |
|---|---|
| **Ghidra database** (binary `.gbf`) | may contain database signal names — this is where they are useful |
| **Repo text** (scripts, docs, `work/owner/*.json`) | must stay clean |

`164_annotate_l24_signals.py` therefore **hardcodes no signal name**: it re-derives them at runtime
from `/home/gl/Projects/ford/CANBus/` via `163_dbc_join.py`, whose output is written to **`/tmp`**,
deliberately outside the repo. Verified both directions:

```
names present in ghidra_proj_fullflash/...db.51.gbf        -> yes (as intended)
names in *.py / *.md / *.json under the repo           -> none
leak_check.py: 2,294 identifiers x 246 files           -> clean
```

### 35.2 The DBC bit convention, tested not assumed

The descriptor gives `(byte, mask, shift)`; a DBC start bit is either the field's MSB (Motorola,
`@0`) or LSB (Intel, `@1`). Both were scored against the databases by exact `(start, length)` match:

| Candidate | Matches |
|---|---|
| **Motorola / MSB** (`byte*8 + shift + len - 1`) | **58** |
| Intel / LSB (`byte*8 + shift`) | 19 |

Motorola wins decisively, consistent with Ford's HS-CAN convention. **65 of 102** dictionary entries
resolve to a named database signal; **35** of those have a signal-plane destination and so became
labelled cells.

> **Independent sanity check.** `0x0C0` d1 `mask 0xE0 >>5` resolves to an **immobiliser status**
> signal, and `0x060` d7 to the matching **immobiliser command** — a core BCM↔PCM function, on the
> exact frame `acc-fix` already uses. `0x1A0` d1 carries the cruise-control status field. The join is
> landing on plausible, BCM-relevant signals rather than noise.

### 35.3 What was applied

| Kind | Count |
|---|---|
| Functions given purpose names | 3 new (+11 confirmed from §32/§33) |
| Data labels (debounce, state, `RXsig_*`) | 41 |
| Comments (EOL + plate) | 167 |
| `OwnerFlash-SIGNALS` bookmarks | 65 |

Newly named this pass:

| Address | Name | Purpose |
|---|---|---|
| `0x050954` | `APP_combo_hold_statemachine` | the 3-state 2000/500-tick combination-hold machine (§32.4) |
| `0x05092C` | `APP_door_latch_status` | door/latch probe used as its exit condition |
| `0x05066E` | `APP_scale_adc_to_mv` | `(raw * 5000) / 0x3FF` — ADC counts → millivolts |

Debounce and state cells now carry both a label and an explanation, e.g.

```
0x40004300  APP_debounce_PI15   3-bit debounce shift register for pad 143 PI15 (interior LOCK).
                                Each cycle: sr = (sr & 3) << 1 | (pin == 0). Active-low input.
0x40007C64  APP_combo_hold_counter   caps at 2000; 500 is the drop-out threshold
0x40003C48  APP_combo_output_flags   bit 6 set while the combination mode is active
```

Each RX signal cell carries its full provenance, and the **source byte in the frame image** is
commented too, so the binding is visible from either end:

```
0x40002E1B  RXsig_<name>   CAN0_HS:0x0C0 d1 mask 0xE0 >>5 len 3  =  <frame>.<signal> -- <description>
0x40000708                 RX image: CAN0_HS:0x0C0 d1 mask 0xE0 >>5 ...
```

### 35.4 Project state (read back, not self-reported)

| Check | Value |
|---|---|
| `Analyzed` flag | True |
| Functions | 13,588 |
| User-defined symbols | **1,065** |
| `Note` bookmarks | **490** across 14 categories |

Verified by `165_verify_l24.py` (all checks passed) and `99_project_audit.py`.

---

## 36. Layer 25 — the TX side annotated, validated by the shipped mods (a)

§35 bound the **receive** signals. This does the **transmit** side — the 15 frames the BCM sends
(`tx_frame_map.json`, §18), which is where both shipped mods operate.

### 36.1 Validation: the database reproduces acc-fix's bit map

The Motorola bit walk (convention proved in §35.2) was checked against `0x030` **before** anything was
written. `AGENTS.md` §0 lists the six bit positions acc-fix manipulates, derived years ago from
composition traces and confirmed on the vehicle. Walking the database's `0x030` definition
independently lands on **all six**:

| acc-fix bit | AGENTS.md name | Database signal at that bit |
|---|---|---|
| d1 bit 6 | `ACC_Res_Plus` | the cruise resume/increment button flag |
| d1 bit 5 | `ACC_Lim` | the speed-limiter button flag |
| d5 bit 7, bit 5 | `CC_Set_Plus`, `CC_Res` | two bits of the 11-bit cruise-button status field |
| d6 bits 6-5 | `CC_Lim` | the 2-bit limiter switch-position field |

Six independent hits, including a multi-byte field whose span the walk had to compute correctly.
This validates the bit convention, the walk, and the TX map in one step — against a source that has
been **proven on the car**.

### 36.2 ⚠ What `tx_frame_map.json` does not cover

The verifier initially asserted `0x40000A0F` (the MS `0x3A` image `rke-lock` drives) and **failed**.
The cause is not the annotation: `tx_frame_map.json` models **one controller's 15 mailboxes**, placing
mailbox 1 (`0x3A`) at `0x40000772`, whereas the image the mod actually writes is at `0x40000A0F`.
So the TX map, like the RX map (§33.5), is a **partial** model — it does not include the record set
that owns the `0x3A` image. Recorded as **open item 23**; the assertion was removed rather than left
failing for an unrelated reason.

### 36.3 What was applied

| | |
|---|---|
| TX frames matched to a database | **15 / 15** |
| TX image bytes annotated | **111 / 111** |
| `OwnerFlash-TXSIG` bookmarks | 111 |

Every TX image byte now carries the frame and the signals occupying it, with bit positions, e.g.

```
0x40000766  TX: HS:0x030 <frame>.<limiter switch position> bits 6,5
                | HS:0x030 <frame>.<cruise button status UB> bit 7
                | HS:0x030 <frame>.<forward-collision audio flag> bit 0
```

Note the multi-bus reality: one mailbox image is annotated with its HS, MS **and** MSX
interpretations, because the same physical bytes are transmitted with different frame ids per bus
(§9.2). The listing shows all of them.

### 36.4 Effect on the mods

The bytes `acc-fix` rewrites are now self-documenting in the listing: opening `0x40000761` shows the
source button bits, `0x40000765` the cruise-status field, `0x40000766` the limiter field — each with
its database meaning. Anyone porting the mod (the task `AGENTS.md` exists for) can now read the bit
map straight from the project instead of re-deriving it from composition traces.

### 36.5 The mod-critical images, and a caveat about the databases (a)

§36.2 found `tx_frame_map.json` does not model the MS `0x3A` image. Both mod-critical images are
nonetheless fully documented in the repo from **on-vehicle** work (`docs/rke-lock.md`), so
`168_annotate_mod_images.py` annotates them from that evidence plus database signal detail:

| Image | Base | Bytes labelled |
|---|---|---|
| MS `0x3A` TX (rke-lock writes) | `0x40000A0F` | 8/8 `TX_img_MS_03A_d0..d7` |
| MS `0x100` RX (rke-lock reads) | `0x40000918` | 8/8 `RX_img_MS_100_d0..d7` |

#### ⚠ The vehicle databases are a generic platform export, not this build

Comparing the two independent sources bit-by-bit (`169`) gives **6/6 coverage but only 3 exact
semantic matches**:

| Bit | On-vehicle (proven by candump + flashing) | Database | Verdict |
|---|---|---|---|
| `0x3A` d3 | lock command, `0x01`=LOCK `0x02`=UNLOCK | 8-bit central-lock command | **match** |
| `0x3A` d1 bit1 | UB flag set with the strobe | lock-command UB | **match** |
| `0x100` d6 bit2 | decrypted-message valid (_UB) | same | **match** |
| `0x100` d7 bits0-1 | RKE LOCK / UNLOCK buttons | inside a 13-bit decrypted keyless payload | consistent |
| `0x100` d1 bit7 | key outside | a 3-bit passive-entry request spanning bits 5-7 | **partial** |
| `0x3A` d1 bit6 | **execute strobe (one-shot)** | a vehicle-speed quality field | **disagrees** |

Three exact hits — including the lock-command byte and both UB flags — confirm the join and the bit
convention. The two mismatches are on bits this project **proved on the car**, so where they conflict
the **documented behaviour wins**. `170_precedence_notes.py` writes that precedence into the listing
as pre-comments, so a future reader cannot mistake a database name for ground truth.

> **General caveat for §35 and §36:** the database-derived names are a strong *lead*, validated where
> it counts (the acc-fix bit map, §36.1, and three exact matches here), but they describe a platform,
> not this exact part number. Treat them as level (b) unless corroborated by a capture.

---

## 37. Layer 27 — the discrete-input bit map resolved (a)

Open item 19. §31.2 had only PI15/PF12 at level (a) because `148`'s text-walk map was
**non-injective** and was rejected. This redoes the whole set with the disassembly method that proved
those two pairs (`171_discrete_bit_map.py`).

### 37.1 Method and acceptance test

Per pad read, take the pad number from the instruction that loads **`r3`** (the argument register —
not "any preceding immediate", which is what made `148` unreliable), then accept a commit only when

* the insert is `e_rlwimi rD,rS,SH,MB,ME` with **`MB == ME`** (a genuine single-bit insert), and
* a store to a state cell in `0x40003A00..0x40003BFF` follows within a short window.

**Injectivity is the acceptance test.** A `(cell,bit)` claimed by two pads means the extraction is
wrong there, so those pairs are **dropped, not guessed**:

| | |
|---|---|
| Candidate commits found | 73 |
| Pads with exactly one commit | 51 |
| `(cell,bit)` claimed by >1 pad → dropped | 7 |
| **Unambiguous pad → bit pairs** | **37** |

### 37.2 Two independent confirmations

1. **Regression on known truth** — both capture-verified pairs reproduce exactly:
   `PI15 → 0x40003AA5 bit 5`, `PF12 → 0x40003AA5 bit 4`. The script fails loudly if they don't.
2. **Agreement with the rejected map** — of the 33 pads `148` also had a value for, **31 agree
   exactly** (2 differ, 4 are new). Two unrelated extraction methods converging on 31 pairs is much
   stronger than either alone; the 2 disagreements are inside the dropped/ambiguous set.

### 37.3 The map

37 pads across **11 state bytes**. The four busiest:

| State byte | Bits resolved |
|---|---|
| `0x40003AA5` | 6 — incl. bit 5 = **interior LOCK**, bit 4 = **interior UNLOCK** |
| `0x40003AA4` | 6 |
| `0x40003AA7` | 5 |
| `0x40003AA6` | 5 |
| `0x40003B92` | 5 |

Both directions are now navigable in the listing: each state byte carries a plate comment listing
every pad committed into it (bit, pad number, package pin), and **all 37** pads' `PCR` registers carry
a back-link `debounced -> 0x4000xxxx bit N`.

### 37.4 Honest limit

**37 of 60** polled pads are resolved. The remaining 23 either commit through a path this extraction
does not match (multi-bit fields, or a commit further than the search window) or fall in the 7
ambiguous bits. They are *not* in the map rather than being present with a guessed value.
`discrete_bit_map.json` records the dropped pads and clashing bits explicitly.

---

## 38. Layer 28 — the combination gate's five inputs (a/c)

Open item 20, unlocked by §37's bit map.

### 38.1 All five inputs resolved to physical pins

`APP_switch_combo_gate` tests `(word >> 4 & 0x92021) == 0x92021`. Decoding the word
(`0x40003AA4..A7`, big-endian) against the §37 map resolves **5/5**:

| word bit | state cell | bit | pad | pin | function |
|---|---|---|---|---|---|
| 4 | `0x40003AA7` | 4 | 59 | `PD[11]` | unknown |
| 9 | `0x40003AA6` | 1 | 110 | `PG[14]` | unknown |
| 17 | `0x40003AA5` | 1 | 99 | `PG[3]` | unknown |
| **20** | `0x40003AA5` | 4 | **92** | **`PF[12]`** | **interior UNLOCK** (capture-verified) |
| 23 | `0x40003AA5` | 7 | 102 | `PG[6]` | unknown |

§31.3's single known member (PF12) is confirmed, and the other four now have pins.

### 38.2 What can and cannot be concluded

**Established (a):** the gate requires five specific discrete inputs simultaneously, one of them the
interior unlock button; its consumer `APP_combo_hold_statemachine` additionally requires the state to
persist ~2000 periodic ticks before latching, dropping out after ~500 without it.

**Not established (c):** *which* feature this is. A deliberate five-input hold is the signature of a
service / transport / assembly-plant mode rather than a driver feature, but naming it needs a capture
with the five inputs exercised — four of the five pins have no established vehicle function, and
guessing from pin numbers is exactly the error class this project keeps catching.

The gate is annotated in the listing with all five pins, so it reads as a named combination rather
than a magic constant, and each contributing pad's `PCR` is cross-referenced back to it.

---

## 39. Layer 29 — the TX pack stage, and a two-phase correction to §32 (a)

Full evidence: **`docs/tx_pack_stage.md`**. Scripts `241`–`245`, `177`–`184`. This is the summary.

Started from "find where central locking lives and where it meets ignition"; following the
*aggregators* instead of the feature produced the entire transmit half of the codec, which had been
missing from this project since the start. The lock command then fell out as one row of a 384-entry
table.

### 39.1 The missing codec half (a)

§33 closed the receive path and left the transmit path unlocated. It sits `0x272` bytes from
`VOL_sig_get8`:

| Primitive | Address | Refs |
|---|---|---|
| **`VOL_sig_set8`** | `0x0FBDD4` | **351** — the busiest primitive in the image |
| `VOL_sig_set16` / `VOL_sig_setN` | `0x0FBD80` / `0x0FBE20` | 27 / 27 |
| `VOL_sig_getN` | `0x0FBB88` | 37 — completes §33's RX set |
| `VOL_test_and_clear_dirty` | `0x031360` | the change-driven transmit gate |

Same 32-byte descriptor as RX, read the other way: `+0x00` = **destination** byte in the TX frame
image, `+0x0C` mask, `+0x0D` left shift, plus two dirty-flag pointers at `+0x04`/`+0x08`.

Invisible for the same tier-0 reason as §33: the destination address lives **in data**.

### 39.2 `APP_tx_compose` @ `0x04B7AA` (a)

One straight-line routine packing every signal the BCM transmits (sweep-split into `0x4B7B0`,
`0x4C0EA` and ~14 tails). **405** pack sites, **404** destinations and **384** sources resolved,
spanning images `0x40000748..0x40000C97`; sources cluster in `0x40002E00`/`0x40002F00`.

**Injectivity acceptance test passed: 0 of 384 `(dest,mask)` pairs has more than one source.**
Output `work/owner/tx_signal_dict.json` — the transmit counterpart of §34's RX dictionary.

~¼ of the sites are wrapped in `if (test_and_clear(&flag,bit))`, so a signal is re-packed only after
its producer marks it changed. **This completes §14.5**: the `rke-lock` sticky write survives for two
compounding reasons — the packer's post-TX AND-mask clears command bits *after* transmit, and the
dirty gate means nothing re-packs them *before* the next one.

### 39.3 ⚠ Correction to §32 — the periodic task has TWO phases

§32 reported `0x2F20A` as the whole periodic body. **It is the first half.** The routine continues by
**fallthrough** at `0x2F262` with a *second* switch on the same `APP_periodic_mode`, dispatching an
**egress twin** of each layer — and every twin is the byte-adjacent sibling of its acquire entry:

| Layer | Acquire | ends | Egress twin |
|---|---|---|---|
| input | `0x449C4` | `0x449F1` | **`0x449F2`** (+ `0x44A04`, `0x44A20`) |
| signal | `0x5799C` | `0x579D5` | **`0x579D6`** (+ `0x57A02`, `0x57A34`) |
| feature | `0x62848` | `0x62913` | **`0x62914`** |

The halves reach **disjoint** codec stages (acquire → `APP_rx_unpack_main`/`VOL_sig_get8`;
egress → `APP_tx_compose`/`VOL_sig_set8`), so one tick is:

> **read inputs → unpack RX → run features → pack TX**

`APP_tx_egress` `0x449F2` is the only path into the pack stage.

> **⚠ Method bug worth propagating.** `179` first reported *empty* callee sets and "no crossover" —
> `getCalledFunctions()` truncates at every swept block boundary. §32.1's **backwards** walk recovers a
> function's *entry*; a **forwards fallthrough** walk is needed to recover its *body* for reachability.
> **Every reachability measurement in this project taken before this layer is a lower bound**,
> including those that motivated "static analysis is exhausted" (new open item 26).

### 39.4 The central-lock command, end to end (level 5)

```c
if (test_and_clear(&APP_lock_command_dirty /*0x40003FC0*/, 4))
    VOL_sig_set8(desc 0x1439D4, APP_lock_command /*0x40002E70*/);   /* -> MS 0x3A d3 */
```

`0x40002E70` → image `0x40000A12`, mask `0xFF`; wire meaning `0x01`=LOCK / `0x02`=UNLOCK proven on
the vehicle (`docs/rke-lock.md` §3). The firmware also writes `0x1F`, `0x3F`, `(x<<1)|1` — wider
codes than the wire shows (open item 28).

26 blocks in `0x087000..0x08F000` write it → **24 true entries**, 10 converging on the state machine
`0x93CC6`; 10 remain 0-caller (open item 25).

**The ignition intersection is `FUN_00087A0E`** — the one function that both tests `APP_power_mode`
`0x40001D85` (`==1`, `==3`) and writes the lock command + dirty flag. `181` verified the mode cell is
genuinely multi-valued (constants `0,1,2,3,4` over 102 readers), not a constant (rule 8).

**Deliberately NOT concluded:** that `APP_power_mode`'s `0..4` codes equal the wire power state of
`ign_powermode_0x80.md` (`0..7`), and that any branch in `0x87A0E` is the RKE-with-ignition refusal —
no such comparison was isolated. The intersection is *located*, not yet *read*. (`ign_powermode_0x80.md`
§2 already carries a standing retraction on this exact subject.)

### 39.5 Both shipped mods write signal slots this build never packs (a)

`177` regressed the map against facts proven on the car: **4 of 5** mod-critical image bytes
reproduce, including acc-fix's exact masks (`0x40000761` `0x20>>5`, `0x40>>6`; `0x40000766` `0x60>>5`)
— an independent re-derivation of the bit map §36.1 validated against the vehicle database.

The exceptions carry the finding. The scan sees **7 of 8** bytes of the `0x030` image, so it is
populated and an absence is meaningful:

| Image byte | Pack setters |
|---|---|
| **HS `0x030` d5** (`0x40000765`) — acc-fix's target | **none** |
| **MS `0x3A` d1 bit 6** — rke-lock's proven execute strobe | **none** |

This is the transmit twin of §33.4 (acc-fix's two RX bytes are received but never unpacked), and it
explains why both mods are safe: they occupy slots this build does not produce, so nothing upstream
competes and nothing downstream clears them. It also sharpens §39.4 — if the strobe is never packed
from a signal cell, the ignition-on refusal may not be a suppressing comparison at all, but a command
path that **does not exist** in this build's generated codec. Testable, not concluded.

### 39.6 Annotation

`183_annotate_l29_txpack.py` names 9 functions and 7 data cells with plate comments and 16
`OwnerFlash-TXPACK` bookmarks. `184_verify_l29.py` reopens **read-only** and asserts all 16 items,
**11 anchors from earlier layers** (catching a rolled-back transaction), that the
`OwnerFlash-TXPACK` count is exactly 16, and that three **caveat strings** survive in the plate
comments so §39.4's uncertainty cannot evaporate from a later summary. **All checks passed**;
project now at 1,107 user-defined symbols.

---

## 40. Layer 30 — the body-control request bus, and the lock ingress (a)

Full evidence: **`docs/tx_pack_stage.md` §7**. Scripts `185`–`187`; read-back by the extended `184`.
Resolves open items 25 and 27, sharpens 28, adds 31/32.

### 40.1 §39.4's blocker was a decompiler artifact (a)

§39.4 recorded `FUN_00087A0E`'s branch conditions as unreadable because the decompiler renders its
base as `&UNK_FFFF8E70 + param_4`. **The disassembly already had it** — Ghidra attaches the absolute
reference to every access (`e_lwz r3,0x88(r6)` → `40008e70`). `185` harvests those resolved
references and **checks self-consistency**: every `(register, displacement)` pair must imply one
base. `r6` → **`0x40008DE8`**, single-valued. (`r4`/`r5` came back *inconsistent* and were reported
as such — they are reloaded mid-function. Flagging that beats averaging it.)

> **Method note.** A `UNK_`/negative-offset base in decompiler output does not mean the structure is
> unreachable. Read the disassembly, harvest the resolved references, verify the implied base is
> consistent. This reopened an item that had been written up as needing fresh work.

### 40.2 `0x40008E70` is an event bus, not a lock variable (a)

It is one of **four** 32-bit request/event words at `0x40008E68`/`6C`/`70`/`74` (struct `+0x80`…`+0x8C`),
written by **73 functions** across `0x086000..0x095000` — how the body features signal each other.

| Word | Ref sites | Bit ops matched | Value bits | True REQUEST bits |
|---|---|---|---|---|
| `APP_req_word_68` | 467 | 257 | 31 | 17 |
| `APP_req_word_74` | 406 | 232 | 32 | 24 |
| **`APP_req_word_70`** | **373** | **211** | **31** | **21** |
| `APP_req_word_6C` | 336 | 249 | 32 | 24 |

Idiom: `se_bseti` raise, `se_bclri` consume/ack, `se_btsti` test. Map in
`work/owner/request_word_bits.json`.

> ⚠ **`se_btsti`/`bseti`/`bclri` number bits MSB-first**: operand `N` = value bit `31-N`.
> `se_btsti r3,0x1B` tests value bit **4**. Getting this backwards yields a plausible but wholly
> wrong bit map — the §28.1 error class. Controls passed: 31–32 distinct bits per word (populated and
> varied), and test-only bits are reported as a *measurement limit*, not as a finding.

### 40.3 The lock ingress — "0 callers" was the wrong question (a)

§39.4 left 10 of 24 lock entries caller-less. They are not called: they are **bus consumers**.
`APP_lock_request_dispatch` @ `0x087A0E` branches on four bits of `APP_req_word_70`, each arm
emitting a command plus `APP_lock_command_dirty = 0xFF`:

| Value bit | Producers | Command |
|---|---|---|
| 4 | set elsewhere | `0x1F`; also sets `APP_power_mode = 1` |
| 3 | `0x894FE`, `0x897DE` | `0x02` (UNLOCK) or `(x<<1)\|1` |
| 2 | `0x91070` | `0x1F`/`0x3F` via `Ram4000247C` bit 25 |
| 10 | `0x9309C`, `0x93556`, `0x9389C`, `0x93C7C` (+12 clearers) | `0x1F`/`0x3F` |

**Item 28 sharpened:** producers `0x894FE`/`0x897DE` write `APP_lock_command = 6` — a sixth code.
The enumeration is `0x02`, `0x06`, `0x1F`, `0x3F`, `(x<<1)|1`, while the wire has only ever shown
`0x01`/`0x02`. d3 is a **multi-code command byte** of which captures have exercised two states.

### 40.4 A conditioned automatic-lock gate (b shape / c identity)

`APP_lock_condition_gate` @ `0x08A096` fires on `trigger && mode==1 && pending && (status < 7 ||
(gear-lever test && value < threshold && value2 > 1))`. A gear-lever test ANDed with a threshold is
the signature of a **speed/gear-conditioned auto-lock** — but three of four inputs have no
established meaning, so the feature stays **unnamed** (open item 31), caveat asserted in the listing.

### 40.5 The ignition gate: confirmed intersection, unconfirmed mechanism

`APP_lock_request_dispatch` is **the** intersection — the only function that both tests
`APP_power_mode` (`==1`, `==3`) and writes the lock command (and writes `APP_power_mode = 1`).

**Not established, with a stronger reason to doubt the original framing:** every arm *emits* a
command; none was seen *suppressing* one. Combined with §39.5 (the execute strobe has no pack
descriptor anywhere), the ignition-on refusal may well be a **command path absent from this build**
rather than a comparison to patch out. The decisive test is a **capture**, not more static work —
see open item 30 for the exact discriminator. If it is a missing path, bus injection is *necessary*,
which retroactively validates the shipped `rke-lock` design on stronger grounds than convenience.

### 40.6 Annotation

`187` names 4 functions and 5 data cells (9 `OwnerFlash-REQBUS` bookmarks). The extended `184`
re-opens **read-only** and asserts **25 items**, **11 anchors from earlier layers**, **7 caveat
strings**, and both bookmark counts. **All checks passed**; 1,116 user-defined symbols.

---

## 41. Layer 31 — the RKE receive chain: 7 of 8 links proven (a)

Full evidence: **`docs/tx_pack_stage.md` §8**. Scripts `188`–`198`; read-back by `184`.
Answers the question "is there a full path from an RFA fob press to the lock command for DDM/PDM?"

### 41.1 The chain

| # | Link | Status |
|---|---|---|
| 1 | RFA radio → MS-CAN `0x100` (the RFA *is* the receiver, so MS is the only route) | **PROVEN** (capture) |
| 2 | mailbox 53 → RX image `0x40000918..1F` | **PROVEN** (copier `0x1520F8`) |
| 3 | `d6:d7` → 13-bit code → `APP_rke_command_code` `0x40002DA2` + valid `0x40003F53` | **PROVEN** (`get16` desc `0x142FD4`) |
| 4 | code → one-hot per-command bits `0x40009034`/`38` | **PROVEN** (`APP_rke_command_demux` `0x0992B2`) |
| **5** | **one-hot bits → `APP_req_word_70` bit 3** | **⚠ OPEN** (item 33) |
| 6–8 | request bit → dispatch → `APP_lock_command` → `0x3A` d3 → walker → DDM/PDM | **PROVEN** (§40, §39) |

`APP_rke_code_commit` @ `0x058538` is the RX-side entry, paired with validator `0x0584A4`; both
switch on `FUN_0010DF6A()` (a 0..3 variant selector, item 36). The demux is on the spine:
`APP_feature_periodic` → `0x9BA92` → `0x9B41C` → `0x99A60` → `0x0992B2`.

### 41.2 ⚠ Two method bugs of mine, and the retraction they force

**`docs/rke_0x100_lock.md` §3's negative result is RETRACTED.** It recorded MS `0x100` d7 as having
"ZERO references … provably not findable statically". Re-verified: d7 genuinely has **no pointer
anywhere in the image** (raw-flash scan, positive control on d1 passing). Correct measurement,
**wrong inference** — `VOL_sig_get16` reads *the descriptor's byte and the next one*, so a 16-bit
signal on `d6:d7` is anchored on **d6** and d7 is never addressed directly. Descriptor `0x142FD4`
(src d6, mask `0x1F`) yields exactly the capture-decoded 13-bit field. → **new golden rule 12**.

Second bug: script `194` searched for a `0x01`/`0x02` **bitmask** because that is the *wire* decode,
and reported "no per-button decode exists". The firmware uses a command **ENUM**:
`(code & 0xF) == 1`. → **new golden rule 13**.

> **What caught both:** the user's domain constraint that the lock button can only arrive on MS-CAN
> because the RFA is the radio receiver. It refuted my HS-CAN hypothesis and forced me to look for a
> fault in my *method* rather than my conclusion. → **new golden rule 14**.

### 41.3 The open hop is an unexplored layer, not missing evidence

`0x40009034`/`38` are read/written by **~56 and ~60** functions in `0x099000..0x09C000` — a subsystem
with exactly **one** user symbol across `0x095000..0x0B0000`. None of them, with the forwards
fallthrough walk applied, touches the lock module or the request bus. Since the behaviour
demonstrably works, the hop exists and is simply **unread**: items 33/34. This is now the
highest-value unexplored region in the image.

### 41.4 Annotation

`198` names 3 functions and 4 data cells (7 `OwnerFlash-RKE` bookmarks). `184` now spans layers
29–31: **32 items, 11 prior anchors, 10 caveat strings, 3 bookmark counts — all passed**;
1,123 user-defined symbols.

---

## 42. Layer 32 — the RKE→lock hop bounded to one byte ~~which nothing writes~~

> ### ⚠⚠ RETRACTED IN §43 — the byte **is** written
> §42.2's "no writer" and the "path is inert" conclusion are **wrong**. The writer is `0x9749A`, in an
> **unswept block** where no reference-based method can see it. The four measurements were correct;
> the inference was not. Kept verbatim as the record. See §43.


Full evidence: **`docs/tx_pack_stage.md` §9**. Scripts `199`–`209`; read-back by `184`.

### 42.1 Downstream of the request input: fully proven (a)

Working **backwards** from `req_word_70` bit 3 was what unstuck it. Its two producers are
*fallthrough tails*, and their parents test a bit of a **different** request word:

```
APP_lock_request_input 0x40008D2C (level)
 └ APP_lock_req_edge_detect_A/B 0x86F90 / 0x8A812
     if (b==1 && !(req74&bit9)) req74 |= bit10;     // rising edge -> event
     if (b==0 &&  (req74&bit9)) req74 &= ~bit10;
     req74 = (b&1)<<9 | (req74 & ~bit9);            // bit9 = level memory
 └ APP_lock_req_gate_A/B 0x894D2 / 0x897B2   (also tests 0x40008D2D == 1)
 └ APP_lock_req_producer_A/B 0x894FE / 0x897DE  -> req70 bit3, cmd=6, dirty=0xFF
 └ APP_lock_request_dispatch -> APP_lock_command -> MS 0x3A d3 -> DDM/PDM
```

**`APP_req_word_74` bit 9 = previous level, bit 10 = edge event.** The bus is a multi-hop event
chain — which is why every single-hop search failed.

### 42.2 The byte has no writer — four controlled methods (b)

| Method | Result | Control |
|---|---|---|
| resolved xrefs (`203`) | 11 READ, **0 WRITE** | `req_word_74`: 246 R / 160 W |
| base-resolved stores (`204`) | 136 into the page, **none** to the cell | 136 real stores found |
| **indexed** `stbx/sthx/stwx` (`207`) | 241 sites, 146 resolved, **0** in `0x40008C00..0x40009100` | 146/241 |
| flash literal pointers (`203`) | 0 | **uninformative** — control also 0 |

It is in **`.bss`**, zeroed every reset (§12.1), and the controls are in the *same region* with
160/151 writers. ⇒ **permanently 0, the edge detectors never fire, this path is inert in this
build** — the §39.5 pattern again (present but not wired for this part number).

> Level **(b)**, not (a): one hypothesis is untested — a write through a pointer held in a struct
> field, invisible to every address-based method. `184` asserts that caveat in the listing.

### 42.3 Refutations recorded

HS-CAN copy carries the button (`190` + domain constraint) · d7 never extracted (`191`) · demux
output reaches the lock module (`197`) · producers' inputs come from the RKE subsystem (`200`) ·
the latch stage feeds `0x40008D2C` (`205` — **12 deltas, extrapolation refused**) · an indexed
store writes it (`207`).

### 42.4 Two method notes

**A crash was the evidence.** `203` died silently on `region(None)` — a write whose instruction has
no containing function. The bug *was* the finding; such writes exist (unswept blocks) and are now
reported as a `NO-FUNC` class.

**Rank by specificity, not fan-out.** `199` ranked a generic error latch (`0x40006408`, 115 readers)
top at score 158 — rule 9 exactly. The useful constraint was the narrow end: two producers reading
~6 cells each.

### 42.5 How to actually close it

1. **p-code dataflow** for `obj->field` writes resolving to `0x40008D2C` (the only untested static route).
2. **On-vehicle correlation (cheaper):** press lock with ignition off — which works today — and watch
   whether `req_word_74` bit 10 ever toggles via a DID exposing the body-state block
   (`did_readers.json`). If it never does, §42.2 is confirmed on the car and the same capture
   identifies which request bit *is* live.

### 42.6 Annotation

`209` names 4 functions and 3 data cells (7 `OwnerFlash-LOCKREQ` bookmarks). `184` now spans layers
29–32: **39 items, 11 prior anchors, 13 caveat strings, 4 bookmark counts — all passed**; 1,130
user-defined symbols. It caught a real mismatch on first run (asserted caveat text vs the comment's
markup), which is the verifier doing its job.

---

## 43. Layer 33 — the writer found by p-code, and §42 retracted (a)

Full evidence: **`docs/tx_pack_stage.md` §10**. Scripts `210`–`220`; read-back by `184`.

### 43.1 The retraction

§42.2 concluded `0x40008D2C` has **no writer** and the lock-request path is **inert**. Both are
**wrong**:

```
00097496  e_lbz  r0,0xf(r21)   ; 0x40008EF7
0009749a  se_stb r0,0xc(r29)   ; -> 0x40008D2C   APP_lock_request_input
0009749e  se_stb r0,0xd(r29)   ; -> 0x40008D2D
```

`getFunctionContaining(0x9749A)` is **`None`** — an **unswept block**. Ghidra never analysed it, so it
never created references, so *every* reference-based method (xrefs, base-register walk, indexed-store
scan) is structurally blind there. The four §42.2 measurements were each correct; the **inference**
was not.

### 43.2 The control that makes it a fact

The language models memory access as `CALLOTHER` userops, and they are **disjoint** (`217`):
`0x10000002` = STORE (199 sites, all `e_stb`/`se_stb`) vs `0x10000001` = LOAD (285 sites, all
`e_lbz`/`se_lbz`). The op at `0x9749A` carries the STORE userop identically in **four** independently
decompiled hosts.

⚠ Honest limit: the register walk could **not** resolve `r29` (established upstream, in unswept code).
P-code is the primary evidence, corroborated by the neighbours landing on a contiguous run
`0x40008D29..0x40008D33` matching their loads.

### 43.3 Three instrument bugs worth remembering

1. **Signed displacements (`210`)** — `int(d,16) if d.startswith("0x") else int(d)` raises on `-0xbc`,
   and a bare `except ValueError: pass` swallowed it: **361 stores silently dropped**, and the target
   is at `-0xBC` from the base. Re-measured correctly, the answer held — a fixed instrument agreeing
   with the broken one is the good case.
2. **p-code `STORE` walk (`211`)** — returned 0 on a 160-writer control. Rule 7 caught it; `212`
   found the real shape.
3. **`os._exit(0)` in `finally` (`214`)** — a raised exception is killed before the traceback prints:
   **a crashing script exits 0 and prints nothing**. Wrap the body in
   `except Exception: traceback.print_exc()`.

### 43.4 The chain now

```
APP_lock_src_producer 0x978D2  -> APP_lock_src_level 0x40008EF7 / _2 0x40008EF8
  -> [unswept latch copy 0x9749A/0x9749E] -> APP_lock_request_input(_2)
  -> edge detect -> req74 bit10 -> gate -> producer -> req70 bit3
  -> APP_lock_request_dispatch -> APP_lock_command -> MS 0x3A d3 -> DDM/PDM
```

**Exactly one unknown remains: what sets `r6` in `APP_lock_src_producer`.**

### 43.5 A refusal vindicated

`205` refused to extrapolate the latch mapping (12 distinct deltas). `218` shows why: the block
interleaves **two** copy streams (`r21`/`r28`→`r29` and `r23`→`r20`). Extrapolating would have named
the wrong source cell confidently.

### 43.6 Verification

`220` annotates 1 function, 4 cells, 4 sites; the retraction is written into
`APP_lock_request_input`'s plate comment (opening `*** RETRACTED CLAIM — READ THIS FIRST ***`) and
asserted by `184`. The two stale layer-32 caveat assertions were **removed** — asserting them would
now assert a falsehood. `184` spans layers 29–33: **ALL CHECKS PASSED**, 1,133 symbols.

---

## 44. Layer 34 — the origin resolved; three scans, three blind spots (a / b)

Full evidence: **`docs/tx_pack_stage.md` §11**. Scripts `221`–`226`; read-back by `184`.

### 44.1 The last §43 unknown, resolved

`221` resolved the whole copy network of `0x096000..0x098000` by p-code (**4,292 edges**, controls
against §43's two known edges). `r6` at `0x97990` loads **`0x40008D6B`**, which has **no copy edge** —
it is produced by code, at `0x959C2`, by a 658-byte state machine that *selects* the value:

```
000959ae  se_lwz r6,0x18(r3) ; se_li r0,0x1 ; e_rlwimi    <- state 1
000959b8  se_lwz r6,0x18(r3) ; se_li r0,0x2 ; e_rlwimi    <- state 2
000959c0  se_li r0,0x0
000959c2  se_stb r0,0x3(r7)                               <- stores the selection
```

**The chain is LIVE end to end:**

```
APP_lock_src_state_machine 0x95770 -> APP_lock_src_origin 0x40008D6B
  -> APP_lock_src_level 0x40008EF7 -> APP_lock_request_input 0x40008D2C
  -> edge -> req74 b10 -> gate -> producer -> req70 b3
  -> APP_lock_request_dispatch -> APP_lock_command -> MS 0x3A d3 -> DDM/PDM
```

### 44.2 Three methods, three answers — the important part

| Method | Answer | Blind spot |
|---|---|---|
| p-code `CALLOTHER`, full image, controls passed | **1** writer | `FUN_00095770` yields only 4 ram-resolved ops in 658 bytes — accesses go through a **pointer parameter**, so no `ram` varnode exists |
| raw signed base+disp sweep | **3** writers | right answer, **broken instrument** (r7 leaked across a function boundary) |
| **Ghidra reference manager** | **3**, correct | blind in *unswept* blocks — where it failed in §43 |

§43: refs blind, p-code right. §44: **exactly reversed.** Neither dominates — **reconcile, and treat
disagreement as the finding**. Stopping at the p-code scan (passing controls, full-image scope) would
have given "one writer, an initialiser ⇒ cell constant 0 ⇒ path dead" — **the §42 error one level
deeper**.

### 44.3 A right answer from a broken instrument

At `0x95758` the sweep said `0x40008D6B`; a careful per-function re-derivation said `0x40008DE7`;
Ghidra says `0x40008D6B`. The sweep was right **by accident** — it carried `r7` across a function
boundary and never saw `e_addi r7,r4,0x7c` at `0x9573E`. Per-function scoping is mandatory, and **a
correct output does not validate a method**.

### 44.4 What is NOT established (asserted as caveats in the listing)

1. **Scheduling of `APP_lock_src_state_machine`** — 0 callers, true entry `0x95716` also has none.
   Do not assume it runs every tick.
2. **That this is the RKE path** — it is the origin of the *lock-request level*; whether its input is
   the RKE demux output, a door switch, or something else is **not traced**. §41 proved links 1–4,
   §§43–44 prove links 5–9; **the join between them is exactly this unknown.**

### 44.5 Verification

`226` annotates 3 functions, 2 cells, 3 sites. `184` spans layers 29–34: **ALL CHECKS PASSED**,
1,138 symbols, `OwnerFlash-LOCKPROD` = 8.

---

> **Consolidated view of layers 29–35:** `docs/central_locking_chain.md` states the whole
> locking picture (both paths, all addresses, open items) in one place.

## 45. Layer 35 — scheduling closed, and the RKE path relocated (a)

Full evidence: **`docs/tx_pack_stage.md` §12**. Scripts `227`–`236`; read-back by `184`.

### 45.1 Item 36 closed — the chain is periodic

Open item 36's premise was **my own script's bug**: `225` used `Function.getCallingFunctions()`,
which skips call sites inside unswept blocks. The reference manager showed the caller at once
(`0x97540`, "in -"). Climbing with **JUMP + CALL + fallthrough** (CALL-only stalls immediately):

```
APP_feature_periodic 0x62848 --CALL--> 0x96B9C -> ... -> APP_lock_periodic_chain 0x97382
  -> 0x95716 -> APP_lock_src_state_machine
```

One routine split by the sweep into **15 zero-caller blocks**. The chain is periodic.

### 45.2 Item 37 answered — in the negative

SM input struct derived by control (`0x9576A` + `0x95764` ⇒ `r4 = 0x40008CEC`), then:

| Test | Result |
|---|---|
| RKE-cell readers ∩ SM-struct writers | **EMPTY** |
| RKE-cell readers ∩ lock-source-cell writers | **EMPTY** |
| flow reachability from demux (10 blocks) ∩ struct writers | **NONE** |
| control: 5/5 known latch writer sites | **PASS** |

⇒ **disjoint code.** The §43–44 chain is a *different* lock actuator, not the fob path — exactly the
caveat §44.4 refused to assume away.

### 45.3 Where RKE really joins

```
0008d54a  e_lhz  r0,0x82(r5)           ; APP_rke_command_code 0x40002DA2
0008d562  se_li  r7,0x3                ; command 3
0008d56a  se_li  r7,0x1                ; command 1
0008d56c  e_rlwimi r0,r7,0xb,0x12,0x14 ; -> APP_body_cmd_bus value bits 11..13
```

`APP_rke_to_body_cmd` `0x8D522` (and sibling `0x88504`) write a **3-bit command enum** — rule 13's
pattern for the third time — into `APP_body_cmd_bus` `0x40008E58`, inside the lock module.

### 45.4 A decoder reported as broken, not as a result

`235` claimed bits 11..13 are "3 write, **0 read**". Rule 7: a write-only field is as suspect as a
zero. The decoder ignored the **rotate amount** and emitted impossible ranges ("bits 17..13"). The
warning lives in `APP_body_cmd_bus`'s plate comment; open item 38 is the fix.

### 45.5 The whole RKE question, honestly

**RFA → MS `0x100` d6:d7 → 13-bit code → demux → command enum on the body bus → [one unresolved
hop] → lock module → `APP_lock_command` → MS `0x3A` d3 → DDM/PDM.**

Every arrow but one is proven — and the section previously believed to be the middle of this chain
belongs to a different feature.

### 45.6 Verification

`236` annotates 3 functions, 2 cells, 3 sites. `184` spans layers 29–35: **ALL CHECKS PASSED**,
1,143 symbols, `OwnerFlash-RKEJOIN` = 8.
