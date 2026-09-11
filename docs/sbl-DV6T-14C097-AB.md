# DV6T-14C097-AB — Secondary Bootloader support for owner recovery

## Right-to-repair scope

This document supports maintenance of an owner-operated BCM from a 12-year-old car for which the
manufacturer no longer provides firmware support. The goal is to preserve the module's existing
firmware as a verifiable owner backup before repair or replacement work. This is bench work over a
wired diagnostic connection to the owner's module; it is not a security assessment, a remote-access
technique, or work on a third party's vehicle.

**Question answered:** Does this SBL support creating a complete owner backup of MCU flash, or does
it only support programming?

**Stock-artifact verdict: NO.** This SBL is a **programming (erase + write + verify) loader only**.
It has no general flash read-out path and cannot create a complete recovery image as delivered.

**Temporary SRAM recovery routine: COMPLETE and bench validated.** The normal loader path was
used on the bench to append and call VLE code at `0x40006000`; that code directly emitted an
eight-byte raw FlexCAN marker. See [`sbl-upload-patch.md`](sbl-upload-patch.md) for the bench result,
current backup-reader architecture, safety constraints, and remaining work.

---

## 1. Container facts (VBF header)

| field | value |
|---|---|
| `sw_part_type` | `SBL` (Secondary Bootloader) |
| `description` | "Secondary Bootloader" |
| network | `CAN_HS`, `ecu_address = 0x726` (CEM/BCM), 11-bit |
| `call` (RAM entry) | `0x40002000` |
| blocks | 6 |
| `file_checksum` | `0x9FB8D36B` |

Blocks (all RAM, base `0x40002000`, PowerPC:BE:64:VLE-32addr = e200z0h, same core family as the
main BCM app):

| blk | start | len | role |
|---|---|---|---|
| 0 | `0x40002000` | 13214 | **all code** |
| 1 | `0x4000E3B8` | 4 | ptr `0x40002A24` |
| 2 | `0x4000E400` | 32 | descriptor table: `SBL1→0x4000E600`, `SBL2→0x4000E6D8`, `SBL3→0x00320000`, `SBL4→0x0FC00000` |
| 3 | `0x4000E480` | 214 | reloc/data |
| 4 | `0x4000E600` | 238 | reloc/data |
| 5 | `0x4000E6F0` | 4 | `0x000003E8` (=1000, a timeout/count) |

Reproduce: `python3 work/vbf_extract.py DV6T-14C097-AB.vbf work/sbl_bins`; merged flat image
`work/sbl_merged.bin`; Ghidra project `ghidra_proj_sbl` (name `SBL`), built by `work/sbl_setup.py`
+ `work/sbl_analyze.py` (75 functions). Decompile helper: `work/sbl_decompile.py`.

## 2. UDS services actually dispatched

From the service dispatcher `FUN_40003f66` (+ the sub-dispatch in `FUN_40003d00`), the SBL handles
exactly these SIDs (via a runtime RAM vtable at `DAT_400021b0`):

```
0x10 SessionControl   0x11 ECUReset        0x19 ReadDTC        0x22 ReadDataByID
0x27 SecurityAccess   0x2E WriteDataByID   0x31 RoutineControl 0x34 RequestDownload
0x35 RequestUpload    0x36 TransferData    0x37 RequestTransferExit  0x3E TesterPresent
```

**Notably ABSENT: `0x23` ReadMemoryByAddress** — the one service that would give general
read-out. `0x22` ReadDataByID only returns fixed, code-defined DIDs (identity/status), not memory.

## 3. Why 0x35 (RequestUpload) cannot create a flash backup

The single transfer executor is `FUN_40003502(addr, buf, len)`, reached from `TransferData`.
Its direction is decided **solely by the target address**, not by the 0x34-vs-0x35 request:

- **Upload branch fires only for a hard-coded sentinel.** `addr == 0x6BA0` is remapped to a **fixed
  RAM buffer `0x40013FE8`**, and the payload streamed back is a **constant 5-byte block copied from
  `0x4000219D`** (XOR'd with one byte), sent out via a PBL "PBLD" transmit callback in
  `FUN_40002F8C`. It is a fixed status/seed readback — it never reads a caller-supplied address.
- **Any other address → DOWNLOAD (program) branch.** The `else` path loops
  `FUN_40002C08(addr, buf)` = the C55 flash **PROGRAM** state machine (sets MCR PGM/EHV, writes the
  double-word, polls DONE/PEG). It *writes to* flash; it does not read it back to the tester.

Issuing RequestUpload against a real flash address cannot back it up: the request routes into the
program path (a write), not a read-out. There is no code anywhere that takes an
externally-supplied address, reads flash at it, and returns the bytes over CAN.

> **Contrast with the PRIMARY bootloader** (`docs/owner_flash_layers.md` §6, analysed from the owner
> full-flash dump — the PBL is not shipped in any VBF, so it could not be examined before).
> The PBL is a *different* binary and behaves differently here: its `0x34`/`0x35` share one handler
> that **is** genuinely address-parameterised, and `PBL_transfer_data_read` @ `0x33BA` is a real
> 32-byte-per-block read-out path. It is nonetheless still not a general backup primitive, because a
> hook (`PBL_upload_address_filter` @ `0x76EC`) vetoes every upload outside
> `0x008000–0x00BFFF` and `0x140000–0x17FFFF` — **the application block is excluded**.
> The PBL likewise has **no `0x23`**, so the headline conclusion of §2 above holds for both loaders.
> Net new capability: the **F10A calibration block can be read out with stock services**.

The blank-check validator `FUN_400037DC(addr,len)` shows the same design: for the sentinel it reads
the fixed buffer; every other address is only *scanned for 0xFF* (erased check), never returned.

## 4. What it *is* capable of (write side)

- `0x34 RequestDownload` + `0x36 TransferData` + `0x37 TransferExit`: ISO-TP segmented download
  (`FUN_400038E8` transport) into a receive buffer, then **program** to flash.
- **Flash ERASE**: `FUN_40002A52` — C55 flash-controller erase state machine (MCR ERS/EHV,
  interlock write of `0xFFFFFFFF`, DONE/PEG poll).
- **Flash PROGRAM**: `FUN_40002C08` — program state machine.
- **Verify / checksum** via `0x31 RoutineControl` (`FUN_40004C26` → routine table dispatch;
  compare/CRC of a just-written region).
- `0x27 SecurityAccess` seed/key gate; `0x2E WriteDataByID`; session/reset/TP housekeeping.
- Erase/program target windows come from descriptor `SBL3=0x00320000` / `SBL4=0x0FC00000` and the
  region table `0x40002170` (`FUN_400026F2`).
- Talks to the resident **Primary BootLoader (PBL)** through a shared callback struct tagged
  `PBLB/PBLD/PBLE/PBLF` (low-RAM `~0x00006C50`) for CAN TX and low-level flash primitives.

## 5. Conclusion

- **Reading full flash: NOT supported.** No `0x23`, no address-parameterised upload; `0x35` only
  returns a fixed 5-byte buffer.
- **Writing: fully supported** (erase + program + verify) — its entire purpose.
- **Cannot create a complete MCU flash backup with this SBL** as delivered. A read-out would require
  either (a) a different SBL/routine that implements ReadMemoryByAddress/real upload, or (b) adding
  a temporary, read-only flash-to-CAN recovery routine to the owner-loaded SRAM image. The latter is
  feasible because the SBL runs from RAM with bus access. The stock artifact does not provide it.

### Subsequent bench result

Option (b) no longer depends on the PBL callback: a seventh VBF block at `0x40006000` directly
wrote CAN0 MB0 and produced `5A5#44554D5054455354` (`DUMPTEST`) on the bench. This validates
temporary SRAM execution and raw CAN output without modifying persistent flash. A subsequent bounded
reader first recovered `0x0000C000..0x0000C0FF` twice as 64 self-indexing records plus a completion
marker. Testing then found an exact 8.175 s resident-platform execution ceiling; live SWT register
reads showed `SWT_CR.WEN=0`. The root cause was an incomplete copy of the OEM main-loop setup: OEM
code activates timer `0x4000FE04` with `FUN_400049F2(...,10)` before its timer update and SBL2
callback calls. The reader initially called the latter two routines without activating their timer.
After adding that initialization, a 262,144-byte run completed in 15.5107 s and matched the earlier
CFlash capture byte-for-byte.

The validated host workflow can reload fixed `0x18000`-byte-or-smaller readers for restartability,
while corrected keepalive initialization also permits longer runs. It captured CFlash
(`0x00000000..0x0017FFFF`), shadow flash
(`0x00200000..0x00203FFF`), and DFlash (`0x00800000..0x0080FFFF`) twice. All second captures matched
their first capture byte-for-byte. The hashes are respectively
`d90b84abe6aada40c8e491f495d5ca3d88d6c3733e9d1cc8b4f35f32087cc76d`,
`2b4e703abd8e8b28857a3e519b7815876956c402af8467b1a1f4aef8a56b16ce`, and
`5bfe2886d3f25873e9cb13d43b9f00c69eae6cfb5364763845926a9d2381ca25`.
