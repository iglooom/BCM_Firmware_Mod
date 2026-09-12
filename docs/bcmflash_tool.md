# `bcmflash` — a VBF flashing tool for the BCM

**Status:** built, dry-run verified against the OEM capture. **Nothing has been flashed with it yet.**

Files: `work/flash/bcmflash.py`, `work/flash/test_against_oem_log.py`

---

## 1. Why not just replay the OEM log

The reference capture `hscan_bcm_flash.log` is **not an application flash**. Reading the requests
back out of it and matching them against the VBFs in the repo identifies it exactly:

| | OEM capture | `JV6T-14C095-AB.VBF` |
|---|---|---|
| erase | `31 01 FF00 0000C000 00004000` | `erase = { { 0x0000C000, 0x4000 } }` |
| download | `34 00 44 0000C000 004000` | one block at `0xC000`, len `0x4000` |

It is a flash of the **`JV6T-14C095-AB` "Local Configuration" `DATA` part** — a calibration.
(An earlier draft of this document called `0xC000` the PBL. That was wrong: the PBL is never
flashed by this tooling, and `0xC000` is where the local-configuration DATA part lives.)

The application part is a different shape entirely:

| | `14C095-AB` (DATA) | `14C094-AD` (EXE) |
|---|---|---|
| erase regions | 1 | **11** (`0x10000`…`0x140000`) |
| data blocks | 1 | 2 (RCHW `0x10000` + app `0x10020`) |
| payload | 16 KiB | **1.2 MiB** |

Hardcoding the capture's addresses would erase 16 KiB of the wrong region and leave the application
half-written. **Therefore `bcmflash` derives the erase list and every block address from the VBF's
own header, never from the log.**

## 2. The sequence

Replicated from the capture, with the parts that generalise made data-driven:

```
3E 00                      wake  (first request after idle is always dropped)
22 F111                    identity - must match the VBF's part, else refuse
10 02                      programmingSession
27 01 / 27 02 <key>        securityAccess L1 (seed->key from load_sbl.py)
3E 80                      TesterPresent, suppressed
--- SBL stage (RAM) ---
34 00 44 <addr><len>       per SBL block
36 <bc> <data>             chunked to the 74 response's maxNumberOfBlockLength
37
31 01 0301 <call>          start the SBL (call address from the SBL VBF header)
--- application stage ---
31 01 FF00 <addr><len>     ONCE PER VBF ERASE REGION
34 / 36 / 37               per data block
11 01                      ECUReset
```

## 3. Safety properties

- **Dry run is the default.** `flash` prints the full plan and every frame it *would* send;
  `--execute` is required to transmit.
- **VBF integrity is checked before the ECU is touched** — all block CRC-16s and the file CRC-32.
  A corrupt VBF is never partially transmitted.
- **Identity gate.** The ECU's software part number must match the VBF's, or the tool refuses
  (`--force` overrides). See §4.2 — *which DID to ask* was itself a bug.
- **`7F xx 78` (responsePending) is a CONTINUE, not a failure.** This is the one that matters most:
  the OEM erase answers `7F 31 78` **first**, and only ~230 ms later `71 01 FF 00`. A tool that
  treated the first negative response as an error would abort **after erasing and before writing** —
  the one genuinely dangerous state in the whole sequence. `busyRepeatRequest` (`0x21`) is retried.
- **Progress + rate** are printed during the 1.2 MiB transfer, so a stall is visible.

## 4. Regression test against the OEM capture

`work/flash/test_against_oem_log.py` reassembles every ISO-TP request from the capture and compares
it against our dry-run plan for the *same* VBF. **ALL CHECKS PASSED:**

- erase bytes **byte-identical** to the OEM: `3101FF000000C00000004000`
- **7/7** RequestDownloads match on address *and* length (6 SBL blocks + 1 data block)
- SBL start identical: `3101030140002000`
- opens with `3E00, 3E00, 1002, 2701, 3E80`

and, for the application VBF, that the plan is correctly **different**:

- 11 erase regions, first is `3101FF000001000000008000` (**not** the capture's)
- regions span exactly `0x10000..0x140000`, ascending, non-overlapping
- both data blocks lie inside the erased span

### ⚠ 4.1 The test's own bug — a vacuous pass

The first run reported 9 failures against a tool that was correct. The extraction regex
`\[dry\]\s+\S*\s*([0-9A-F]{4,})` assumed the label had no spaces, but labels look like
`sbl blk0 34` — so `\S*` stopped at `sbl` and the capture group landed on **fragments of the label**
(`F111`, `0000C000`) instead of payloads.

Two lessons, both recorded in the test:

1. **The failure was in the instrument, not the subject.** The tool's output was right all along.
2. **One check "passed" on empty input** — "erase regions are contiguous" is vacuously true for zero
   regions. That is a rule-8 vacuous pass, and it would have stayed green forever. The test now
   asserts **extraction is non-empty** before comparing anything, and every predicate is guarded
   with `bool(...)` so an empty list fails instead of passing.

### ⚠ 4.2 The identity gate asked the wrong DID

Running `ident` against the live bench BCM exposed a second self-inflicted bug. The gate compared
`22 F111` against the VBF's `sw_part_number` — and `F111` is **not** the software part:

| DID | meaning | bench BCM |
|---|---|---|
| **`F188`** | **application sw part** | **`JV6T-14C094-AD`** |
| **`F124`** | **calibration part** | **`JV6T-14C095-AB`** |
| `F111` | ECU hardware/assembly | `DV6T-14C245-FF` |
| `F113` | ECU core assembly | `DV6T-14A073-FK` |
| `F110` | diagnostic spec | `DS-JV6T-14A073-BB` |
| `F180` | bootloader | `FORD-PBL-V013` |

`F111` can never equal an EXE VBF's part number, so the "safety" check would have **refused every
legitimate application flash** — a safety feature that only ever fires as a false positive is worse
than none, because the habit it teaches is `--force`.

Fixed: the gate now picks the DID by the VBF's `sw_part_type` (`EXE → F188`, `DATA → F124`) and
requires an exact match. Verified live: `F188` reads `JV6T-14C094-AD`, matching the probe-bank VBF.

Note this also confirms the bench unit is running the expected app and calibration — and that
`F124` = `JV6T-14C095-AB` independently corroborates §1's identification of the OEM capture as a
**calibration** flash.

## 5. Usage

```bash
python3 work/flash/bcmflash.py info   work/probe-bank/JV6T-14C094-AD_probe-bank.VBF
python3 work/flash/bcmflash.py verify work/probe-bank/JV6T-14C094-AD_probe-bank.VBF
python3 work/flash/bcmflash.py ident                       # what part is on the bench?
python3 work/flash/bcmflash.py flash  <vbf>                # DRY RUN
python3 work/flash/bcmflash.py flash  <vbf> --execute      # for real
python3 work/flash/test_against_oem_log.py                 # regression
```

## 6. What is NOT established

- **The tool has never transmitted a single frame.** Every result so far is a dry run plus a
  comparison against a capture.
- The `can_isotp` module is loaded and `work/sbl-upload/uds.py` is proven for the *SBL upload* path,
  but a **1.2 MiB** transfer has never been exercised — chunking, flow control and timeouts at that
  scale are untested here.
- `31 01 FF00` erase timing for a **128 KiB** region is unknown; only the 16 KiB case
  (~230 ms of `responsePending`) has been observed. `--erase-timeout` defaults to 60 s per region.
- Whether the app part needs `31 01 0304`-style "check programming dependencies" or a post-flash
  routine before `11 01` — the DATA capture shows none, but an EXE part may differ.
- Whether the BCM accepts an application write **while the SBL is running** in exactly this order —
  proven for DATA, assumed for EXE.
- No recovery path is implemented. If an app flash is interrupted after erase, the module is in
  programming mode with no application; recovery means re-running the flash, which requires the PBL
  to still answer — **untested**.
