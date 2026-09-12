# `bcmflash` — a VBF flashing tool for the BCM

**Status:** used for real — `docs/bench_session_2.md` §1 records the first successful 1.2 MiB
application flash (log `work/flash/logs/run1.log`). The §7 caveats below are what remains untested.

Files: `work/flash/bcmflash.py`, `work/flash/test_against_oem_log.py`, `work/flash/quietprobe.py`

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
                           [--quiet-bus] 7DF#02 10 82 x20   <- silences the bus
10 02                      programmingSession
27 01 / 27 02 <key>        securityAccess L1 (seed->key from load_sbl.py)
3E 80                      TesterPresent, suppressed
                           <- from here a background thread broadcasts
                              7DF#02 3E 80 every 2 s until step 6 completes
--- SBL stage (RAM) ---
34 00 44 <addr><len>       per SBL block
36 <bc> <data>             chunked to the 74 response's maxNumberOfBlockLength
37
31 01 0301 <call>          start the SBL (call address from the SBL VBF header)
--- application stage ---
31 01 FF00 <addr><len>     ONCE PER VBF ERASE REGION
34 / 36 / 37               per data block
11 01                      ECUReset
                           [--quiet-bus] 7DF#02 11 81       <- reset all modules
```

## 3. Safety properties

- **Dry run is the default.** `flash` prints the full plan and every frame it *would* send;
  `--execute` is required to transmit.
- **VBF integrity is checked before the ECU is touched** — all block CRC-16s and the file CRC-32.
  A corrupt VBF is never partially transmitted.
- **Identity gate.** The ECU's software part number must match the VBF's, or the tool refuses
  (`--force` overrides). See §5.2 — *which DID to ask* was itself a bug.
- **`7F xx 78` (responsePending) is a CONTINUE, not a failure.** This is the one that matters most:
  the OEM erase answers `7F 31 78` **first**, and only ~230 ms later `71 01 FF 00`. A tool that
  treated the first negative response as an error would abort **after erasing and before writing** —
  the one genuinely dangerous state in the whole sequence. `busyRepeatRequest` (`0x21`) is retried.
- **Progress + rate** are printed during the 1.2 MiB transfer, so a stall is visible. A **permanent
  line is emitted every 5%** (`PROGRESS_STEP`) in addition to the live `\r` counter, so the logfile
  keeps a timestamped record of throughput instead of one overwritten line.

## 4. Session keepalive and `--quiet-bus`

### 4.1 Broadcast TesterPresent (always on)

A background daemon thread broadcasts `7DF#02 3E 80` every 2 s (`--tp-interval`, 0 disables) from
just after security access until the ECUReset. It uses a **separate raw `AF_CAN` socket**, not the
ISO-TP one, because the flash spends long stretches blocked inside a single `recv()` — a 128 KiB
erase or a TransferData — which is exactly the window in which S3 (5 s) would expire. The
suppress bit (`0x80`) is set so no ECU answers and nothing can be confused with the reply to the
request currently in flight on the physical channel.

### 4.2 What actually silences the bus — and what does not

`--quiet-bus` (opt-in, default **off**) sends **`7DF#02 10 82` twenty times** (`QUIET_ARM_REPEAT`,
~0.45 s at 20 ms spacing) immediately before the physical `10 02`, and `7DF#02 11 81` (functional
hardReset) after step 6.

**Measured on the vehicle:** a module in programmingSession stops transmitting its normal
application frames, so the functional `10 02` quiets the whole network on its own. **Confirmed
working on a real car.**

⚠ **The repeat count is not cosmetic.** At 5 repeats the bus went quiet but **some modules kept
transmitting**; raised to 20. Because the request is suppressed there is no way to detect which
module missed it, so the only available remedy is to repeat the sweep — see §4.4.

⚠ **Two wrong models were tried first. Both are recorded so nobody re-derives them:**

1. **"TesterPresent quiets the bus."** It does not. `3E 80` only refreshes the S3 timer of a module
   **already** in a non-default session; a module in its default session ignores it and keeps
   transmitting. TesterPresent is what makes the quiet *persist*, not what causes it.
2. **`10 03` + `85 02` + `28 03 01`** (extendedSession, DTC-setting off, CommunicationControl
   disableRxAndTx) — the textbook answer, and on this vehicle the bus stayed noisy.

The second failure is the instructive one. Every request carried the suppress bit, so **no module
could answer even to reject** — a unanimous `7F 28 22 conditionsNotCorrect` would have been
byte-for-byte indistinguishable from success. The first candump offered as evidence was also
filtered to `0x7DF`, i.e. it could only show *our own* frames and was structurally incapable of
answering the question (rule 27: an empty instrument reading is inconclusive, never a negative).

### 4.3 `quietprobe.py` — reading the NRCs a suppressed request hides

`work/flash/quietprobe.py` exists for exactly that blindness. It **clears** the suppress bit so every
module's positive response or NRC is visible, listens on a raw socket (a functional request is
answered by *every* module at once — an ISO-TP socket bound to one rx ID cannot see that storm), and
counts traffic per CAN ID **before / during / after**, with the null control on both sides of the
stimulus. A silent baseline is reported `INCONCLUSIVE` rather than as a success.

```bash
python3 work/flash/quietprobe.py listen                 # baseline; sends NOTHING
python3 work/flash/quietprobe.py probe --comm-types 1,2,3
python3 work/flash/quietprobe.py probe --ids 0x7DF,0x7E0
```

⚠ **Its own first version was broken in the same family as everything above.** `collect_responses`
matched on the ISO-TP PCI nibble alone, so an ordinary application frame like
`030#8000E180A000B307` (first nibble 0) was classified as a single frame and printed as a *positive
response* — ~100 fabricated responses per window against a live bus, burying the one real NRC. It now
matches the reply against the service sent (`sid+0x40`, or `7F <sid> <nrc>`), verified on the live
bus with an injected NRC and a positive reply while real traffic ran underneath: 2 matched, 0 leaked.

### 4.4 What `--quiet-bus` does not prove

The arm and the reset are **fire-and-forget**: the response is suppressed, so a module that misses
the frame stays noisy and the tool cannot tell. This is not hypothetical — **at 5 repeats some
modules on a real vehicle stayed noisy**, which is why the count is now 20 (`QUIET_ARM_REPEAT`).
Note what that implies: 20 is a count that *happened to work*, not a derived bound. If a module
still transmits, raise it further, and **confirm with an unfiltered `candump` on a second
terminal** — the tool's own output is a statement of intent, not evidence.

A residual noisy module is worth diagnosing rather than drowning: use `quietprobe.py` (§4.3) with
the suppress bit clear to see whether it answers `10 03` at all, or whether it simply never receives
the functional ID. A module that rejects the request will keep rejecting it 20 times.

Two consequences worth weighing before use:

- The restore is a **network-wide hardReset**. It reboots every module *including the BCM just
  flashed*, which already received its own physical `11 01` in step 6 — so that module is reset
  twice in quick succession.
- It also fires on the **abort path**. If the flash dies mid-erase, every module on the bus is reset
  while the BCM is half-erased. S3 (~5 s after the last TesterPresent) is the backstop if the reset
  itself fails to send.

## 5. Regression test against the OEM capture

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

### ⚠ 5.1 The test's own bug — a vacuous pass

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

### ⚠ 5.2 The identity gate asked the wrong DID

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

## 6. Usage

```bash
python3 work/flash/bcmflash.py info   work/probe-bank/JV6T-14C094-AD_probe-bank.VBF
python3 work/flash/bcmflash.py verify work/probe-bank/JV6T-14C094-AD_probe-bank.VBF
python3 work/flash/bcmflash.py ident                       # what part is on the bench?
python3 work/flash/bcmflash.py flash  <vbf>                # DRY RUN
python3 work/flash/bcmflash.py flash  <vbf> --execute      # for real
python3 work/flash/bcmflash.py flash  <vbf> --execute --quiet-bus   # + silence the network
python3 work/flash/test_against_oem_log.py                 # regression
python3 work/flash/quietprobe.py listen                    # is the bus even talking?
```

Flash options beyond `--execute` / `--force` / `--erase-timeout`:

| option | default | effect |
|---|---|---|
| `--tp-interval` | `2.0` | broadcast TesterPresent period, seconds; `0` disables |
| `--tp-id` | `0x7DF` | functional CAN ID for TesterPresent and `--quiet-bus` |
| `--quiet-bus` | off | `7DF#02 10 82` ×20 before the session, `7DF#02 11 81` after the reset |

## 7. What is NOT established

- **`--quiet-bus` cannot confirm itself.** The arming frame is suppressed, so the tool cannot tell
  which modules acted on it. Confirmed working on a real car, but **at 5 repeats some modules stayed
  noisy**; 20 is an empirical count, not a derived bound, and no upper limit has been established —
  see §4.4.
- The functional ID `0x7DF` and the choice of `10 02` as the quieting request are correct for the
  vehicle tested and are **not** derived from this part number's database. A different network may
  need `--tp-id`.
- **`--quiet-bus`'s network-wide hardReset has not been exercised on the abort path**, only on a
  clean run and in dry runs.
- `31 01 FF00` erase timing for a 128 KiB region: observed to complete well inside the 60 s
  `--erase-timeout` on one run (`bench_session_2.md` §1), but the `responsePending` path was never
  actually stressed at that size.
- Whether the app part needs `31 01 0304`-style "check programming dependencies" or a post-flash
  routine before `11 01` — the DATA capture shows none, and the one EXE flash succeeded without it.
- No recovery path is implemented. If an app flash is interrupted after erase, the module is in
  programming mode with no application; recovery means re-running the flash, which requires the PBL
  to still answer — **untested**.
