# DV6T-14C097-AB — RAM-based firmware recovery and bench validation

Status: **stock SBL backup limitations confirmed statically and on hardware; temporary SRAM routine
execution and direct raw FlexCAN transmission confirmed on hardware; complete CFlash, shadow-flash,
and DFlash backups captured twice with byte-identical hashes. The OEM SBL2 keepalive initialization
has also been reproduced and validated beyond the former 8.175-second cutoff.**

This is owner-directed right-to-repair work on a bench BCM from a 12-year-old vehicle for which the
manufacturer no longer provides firmware support. The purpose is to preserve the owner's existing
firmware before repair or replacement work. It is not a vulnerability assessment, a remote-access
project, or work on a third party's vehicle. The temporary routines discussed here run only from
SRAM and are loaded through the module's normal wired programming path. The tests below did not
erase or program persistent flash; a reset or power cycle restores the original execution path.

See also [`sbl-DV6T-14C097-AB.md`](sbl-DV6T-14C097-AB.md) for the stock-loader disassembly and its
read-vs-write capability verdict.

---

## 1. Executive result

`DV6T-14C097-AB.vbf` cannot create a general owner backup as supplied:

- live `0x35 RequestUpload` returns `7F 35 11` (`serviceNotSupported`);
- live `0x23 ReadMemoryByAddress` returns `7F 23 7F`;
- static analysis finds no caller-selected memory-read path;
- its apparent internal upload branch only serves a fixed sentinel and fixed five-byte buffer;
- normal transfer addresses enter the C55 flash **program** path.

A small custom VLE block can, however, be appended to the OEM SBL VBF, downloaded through the
normal PBL path, and called from SRAM. This was validated on the bench. Code at `0x40006000` directly
programmed a CAN0 FlexCAN transmit mailbox and emitted:

```text
can0 5A5#44554D5054455354
```

The eight payload bytes decode to ASCII `DUMPTEST` (the marker name is retained in the existing
tooling). This routine uses a direct mailbox path rather than the SBL's UDS dispatcher or PBL
transmit callback. It validates the building blocks needed by a minimal owner-backup reader:
**run a temporary SRAM routine, read the module's memory, and transmit addressed CAN records.**

The remaining repair-tooling work is to run the new bounded reader first against a 256-byte known
CFlash sector range, validate mailbox completion and watchdog servicing on hardware, then expand to
the documented physical regions and compare repeat captures.

---

## 2. Target and bench facts

| Item | Confirmed value |
|---|---|
| Bench BCM identity (`22 F111`) | `DV6T-14C245-FF` |
| MCU family | SPC560B64L7 / MPC5607B, PowerPC e200z0h, big-endian VLE |
| SRAM base | `0x40000000` |
| Stock SBL entry | `0x40002000` |
| Custom probe entry | `0x40006000` |
| Diagnostic bus | CAN0 / HS-CAN, 500 kbit/s |
| Tester → BCM | `0x726` |
| BCM → tester | `0x72E` |
| Recovery marker frame | `0x5A5`, data `DUMPTEST` |
| CAN0 FlexCAN base | `0xFFFC0000` |
| CAN1 FlexCAN base | `0xFFFC4000` (static hardware/application evidence only for this experiment) |

Linux kernel `CAN_ISOTP` sockets are sufficient; `python-can` is not required. The bench BCM can
sleep, so the first wake/tester-present command may need to be retried. At the time of the CAN1
proposal, only `can0` existed on the host; no `can1` interface was available for a live test.

The standard UDS `SecurityAccess` programming step was reproduced against the owned bench module
with the hardware-family-specific selection used by the working tool. The protocol detail is not
needed to explain the recovery design. The local bench implementation is
`work/sbl-upload/test_seckey.py`, and the loader implementation is
`work/sbl-upload/load_sbl.py`. The older `/home/gl/Dropbox/FoCCCus-dev/` tree was found to be stale;
live traffic remains the authority over either reverse-engineered tool tree.

---

## 3. Recovered and replayed SBL loading protocol

Source capture: `hscan_bcm_flash.log`. Decoder: `work/sbl-upload/decode_log.py`.

The proven sequence is:

1. `10 02` — programming session.
2. `27 01`, then `27 02 <key>` — security access.
3. `3E 80` — tester present with response suppression.
4. For each VBF block:
   - `34 00 44 <address:u32-be> <length:u32-be>`;
   - response `74 20 0C62` advertises the transfer size;
   - one or more `36 <block-sequence-counter> <data...>` messages;
   - `37` transfer exit;
   - positive response `77 <block-crc16>`.
5. `31 01 03 01 <call-address:u32-be>` — call downloaded RAM code.

For the OEM image, calling `0x40002000` returned `71 01 03 01 10`. All six OEM blocks were loaded
successfully and each transfer-exit response echoed the expected VBF block CRC-16.

`work/sbl-upload/load_sbl.py` implements this exact flow. It accepts a VBF path and reads the call
address and blocks from that VBF rather than assuming the OEM entry point.

---

## 4. Stock SBL compatibility checks on the bench

After loading and starting the stock SBL on the owned module:

- `35 00 44 <address> <length>` was tried against flash, calibration-like, and SRAM addresses;
  every test returned `7F 35 11`.
- `0x23 ReadMemoryByAddress` was tried with the relevant address/length encodings and returned
  `7F 23 7F`.
- The loader remained alive after the failed checks: `3E 00` returned `7E 00`, and fixed DIDs still
  responded.
- `hscan_bcm_flash.log` contains no successful upload transaction; it is a download/programming
  session.

Probe tool: `work/sbl-upload/probe_upload.py`.

These results agree with the static analysis in the companion document. The stock artifact should
not be pointed at arbitrary flash addresses under the assumption that SID `0x35` implies a read:
its internal transfer executor routes ordinary addresses to the flash-program state machine.

---

## 5. Why the design changed from a UDS extension to a minimal backup reader

An early design proposed rewriting the sentinel readback branch in `FUN_40003502` and preserving
the SBL/PBL framing state machine. Bench tests then showed that the running dispatcher rejects
`0x35`, while temporary SRAM blocks can already be downloaded and called through the normal loader.

The smaller and better-isolated design is therefore:

1. retain the six OEM SBL blocks byte-for-byte so the known initialization environment exists;
2. append one custom SRAM code block;
3. change only the VBF `call` address to the custom block;
4. have custom code read flash directly and send raw CAN frames;
5. make no persistent flash-controller writes.

This avoids modifying the stock UDS dispatcher, guessing at runtime PBL vtables, or implementing
RequestUpload/TransferData response state twice.

---

## 6. First bench test: PBL/SBL transmit callback (inconclusive)

`work/sbl-upload/build_probe.py` assembled a payload at `0x40006000` which:

- calls stock initialization `FUN_40004322`;
- clears the TX primitive state at `0x40012AE0`;
- services `FUN_40004A24` and `FUN_400030DE`;
- calls `FUN_40002F8C` with an eight-byte `DUMPTEST` buffer at `0x40006100`;
- loops while the primitive reports busy, then halts.

This test depended on runtime PBL callback state and did not establish a clean marker frame. It was
retained as engineering evidence but replaced by the direct-mailbox test below.

---

## 7. Direct FlexCAN transmit validation (confirmed on the owned module)

Builder: `work/sbl-upload/build_direct_probe.py`.

The validated routine calls `FUN_40004322` for stock SBL timer/runtime initialization, then writes CAN0
mailbox 0 directly:

| Register | Address/value | Purpose |
|---|---|---|
| MB0 CS | `0xFFFC0080` ← `0x08080000` | mark mailbox inactive before editing |
| MB0 ID | `0xFFFC0084` ← `0x16940000` | standard ID `0x5A5 << 18` |
| MB0 data 0 | `0xFFFC0088` ← `0x44554D50` | `DUMP` |
| MB0 data 1 | `0xFFFC008C` ← `0x54455354` | `TEST` |
| MB0 CS | `0xFFFC0080` ← `0x0C480000` | arm one 8-byte data-frame transmission |

The mailbox layout agrees with the independently reversed OEM FlexCAN descriptors:

- `MB[i].CS = base + 0x80 + i*0x10`;
- ID register is `CS+4`;
- payload starts at `CS+8`;
- standard identifiers are stored as `id << 18`;
- OEM inactive/TX-once CS words are `0x08080000` and `0x0C480000`.

The code was assembled with Ghidra's VLE assembler using context `0x20000000`, written into a
scratch transaction, redisassembled, and checked byte-for-byte before packaging.

### Packaging and integrity

`work/sbl-upload/build_probe_vbf.py`:

- preserves all six OEM VBF blocks byte-exact;
- appends the custom block at `0x40006000`;
- changes header `call` to `0x40006000`;
- recomputes CRC-16/CCITT-FALSE for every block;
- recomputes the reflected file CRC-32.

`work/sbl-upload/verify_probe_vbf.py` independently verified:

- seven blocks total;
- six OEM blocks unchanged;
- all per-block CRC-16 values valid;
- file CRC-32 valid;
- call address and appended bytes match `probe_blob.json`.

For the bench-validated 64-byte direct-probe build:

| Artifact fact | Value |
|---|---|
| Probe block length | `0x40` |
| Probe block CRC-16 | `0x2E8B` |
| VBF file CRC-32 | `0xFABF8545` |
| VBF SHA-256 | `a0621a0371b33def8e0a86369b115e87145a7fdcbbb1490f190422878bc01101` |

Live runner: `work/sbl-upload/run_probe.py`. It captured 2,085 frames and observed the ECU's raw
marker frame immediately after the positive call response:

```text
(3.817334) can0 72E#0571010301100000
(3.817858) can0 5A5#44554D5054455354
```

The runner deliberately accepts only an exact `0x5A5` raw frame, so the copy of `DUMPTEST` sent to
the ECU inside the downloaded VBF cannot create a false positive. Result: **PASS**.

---

## 8. Proposed complete-backup wire format

For classical CAN, use fixed ID `0x5A5` with self-indexing 8-byte records:

| Bytes | Meaning |
|---|---|
| 0..3 | absolute source address, big-endian |
| 4..7 | four bytes read from that address |

Advantages:

- every record is independently placeable;
- receiver can deduplicate repeated frames;
- missing addresses are detectable without relying only on sequence state;
- capture can resume/retry ranges;
- two complete backups can be compared byte-for-byte.

The receiver should prefill unknown bytes, reject out-of-range/misaligned addresses, track duplicate
conflicts, report missing 4-byte cells, and hash each completed region. Optional start/end records
or a second control ID may carry a region identifier and checksum, but they are not required for
basic reconstruction.

### First bounded reader build and bench result

`work/sbl-upload/build_backup_reader.py` now assembles a conservative first-stage implementation:

- compile-time source range `0x0000C000..0x0000C0FF` (256 bytes, inside documented CFlash sector 2);
- one aligned 32-bit flash read per record;
- CAN0 MB0 only, using the already validated `0x5A5` direct-mailbox path;
- polling of the mailbox's big-endian CS CODE byte for inactive value `0x08` before every reuse
  (the first bench attempt incorrectly compared the whole halfword to `0x0808`; after TX the
  non-CODE SRR/IDE/DLC bits need not return to their original values, so it sent one record and
  waited forever);
- selectable helper servicing (`both`, `sbl2`, or `none`) so the effect of the stock timer/callback
  routines can be tested rather than assumed;
- one final `FFFFFFFF#444F4E45` (`DONE`) completion record;
- halt in SRAM after the final mailbox returns inactive.

The Ghidra assembler accepted and round-trip disassembled every generated VLE routine. The current
minimal `--service-mode none` form is `0xB0` bytes.
`build_backup_vbf.py` packages it as a seventh block without changing any OEM block, and
`verify_backup_vbf.py` verifies all CRCs, byte-exact OEM preservation, the bounded source metadata,
and that all stores in the custom listing target the CAN-mailbox base register. The generated VBF
remains a bounded hardware-test artifact rather than a complete firmware backup tool.

`run_backup_reader.py` captures only raw `0x5A5` eight-byte records, rejects out-of-range or
misaligned addresses, detects conflicting duplicates and holes, requires the `DONE` record, and
writes a binary plus metadata only after a complete consistent capture. Its default filenames are
timestamped and it refuses to overwrite an existing artifact.

The first bench run exposed one concrete FlexCAN state-machine bug: it transmitted the record for
`0x0000C000`, then waited forever because the routine compared the complete CS halfword against
`0x0808`. The TX operation can preserve changed SRR/IDE/DLC bits when CODE returns to inactive.
Changing the poll to compare only the first big-endian CS byte against CODE `0x08` fixed the loop.

Two subsequent runs each produced all 64 data records plus `DONE`, with no rejected records, holes,
or conflicts:

| Capture | Records | SHA-256 |
|---|---:|---|
| `backup_0000C000_00000100_20260911T082744Z.bin` | 64 + `DONE` | `f8782736388e7802853d55ec0a34c696e5e1554d0309b00c96a4e8ec6349dc00` |
| `backup_0000C000_00000100_20260911T082759Z.bin` | 64 + `DONE` | `f8782736388e7802853d55ec0a34c696e5e1554d0309b00c96a4e8ec6349dc00` |

The second run used the first binary as `--reference` and passed the byte-exact comparison. The
captured range begins with the plausible calibration identifier `JV6T-14C095-AB`. The tested reader
VBF SHA-256 is `e67235bf7a525bb60137cdf9098fd84eef3987a0329dcaae8fc8b5939a85c38c`.

CAN1 remains the preferred bulk-output bus if it can be initialized safely, because CAN0 remains
the proven UDS/control path. A practical fallback is CAN0 raw output using the already-proven
mailbox primitive, with the vehicle isolated on the bench and no diagnostic traffic after start.

---

## 9. Memory regions and scope of a complete owner backup

Do not equate the application's end at `0x0013FFFF` with all nonvolatile memory. Existing project
evidence identifies at least these distinct ranges:

| Region | Address range | Existing VBF coverage |
|---|---|---|
| CFlash sectors 0–1 (PBL / early initialization) | `0x00000000..0x0000BFFF` | absent from available app/cal VBFs |
| Calibration F124 | `0x0000C000..0x0000FFFF` | covered |
| Main application | `0x00010000..0x0013FFFF` | covered |
| Remaining physical CFlash | `0x00140000..0x0017FFFF` | F10A covers only a used prefix through `0x0015BF4B` |
| Flash shadow array | `0x00200000..0x00203FFF` | absent |
| Data flash / EEPROM emulation | `0x00800000..0x0080FFFF` | absent |
| BAM | `0xFFFFC000+` | mask ROM, not flash |

RM0037 Rev 10 Table 436 confirms 1.5 MiB of contiguous user CFlash at
`0x00000000..0x0017FFFF`, plus the separate 16 KiB shadow sector. Table 437 confirms 64 KiB of user
DFlash at `0x00800000..0x0080FFFF`. TestFlash ranges contain OTP and reserved areas and are excluded
from the first backup plan. Back up each user region separately rather than walking through gaps or
reserved/test space. A bus error in temporary SRAM code may reset or halt the ECU and leave an
incomplete capture.

The most valuable first recovery range is `0x00000000..0x0000BFFF`, because it contains the PBL /
early hardware initialization missing from all currently available VBFs. Then capture the known
code/calibration ranges, shadow flash, and data flash as separate artifacts.

---

## 10. OEM keepalive timer, former 8.175 s ceiling, and chunking

A single `0x40000`-byte run reproducibly stopped after **34,405 records / 137,620 bytes**. The first
record timestamp to last-record timestamp was **8.1752 s**, ending at source address `0x00031990`.
The prior `0x20000`-byte run completed in 7.7871 s. Removing both helper calls did not move the stop:
the helper-free run again ended after 34,405 records at the same address-relative position.

This is not the MCU SWT timeout. A live read of `0xFFF38000..0xFFF38017` recovered:

```text
SWT_CR=0xFF00000E  SWT_IR=0x00000000  SWT_TO=0x00007D00
SWT_WN=0x00003E80  SWT_SR=0x00000000  SWT_CO=0x000050A1
```

`SWT_CR.WEN` is clear. Decompiling the OEM SBL entry loop then exposed the missing step. After
`FUN_40004322`, OEM `FUN_400041A6` explicitly calls
`FUN_400049F2(0x4000FE04, 10)` before entering its infinite event loop. `FUN_400030DE` checks that
timer and invokes the resident `SBL2` callback only when it expires; merely calling
`FUN_40004A24`/`FUN_400030DE` without first activating the timer does not provide the callback.

The custom reader originally copied the two loop calls but omitted `FUN_400049F2`, so the PBL/SBC
supervisory callback was never produced. This explains why removing the helpers made no difference
and why the OEM SBL, which performs all three steps, runs indefinitely. The builder now starts the
10 ms timer whenever helper servicing is selected.

A corrected `0x40000`-byte run transmitted 65,536 addressed records plus `DONE` in **15.5107 s**,
well past the former cutoff. It reconstructed SHA-256
`57fcdf8a84eff4cd49b6f5fee2f1f5c31bedd7e225320a50819a7063bea9f093` and matched the same slice of
the previously repeated CFlash backup byte-for-byte. This bench result confirms the missing timer
initialization as the cause, although the exact resident supervisor implementation is still in PBL
code rather than the SBL image.

The already completed recovery used `run_chunked_backup.py`: it rebuilds and reloads the SRAM
reader for fixed chunks smaller than the ceiling, validates every chunk independently, then joins
only contiguous successful chunks. A conservative `0x18000` (96 KiB) chunk takes about 5.8 s and
leaves useful margin. A second invocation with `--reference-dir` requires every recaptured chunk to
match before accepting the combined region. Chunking remains useful for restartability even though
the corrected keepalive now permits longer single runs.

This strategy completed all physical user nonvolatile ranges twice:

| Region | Range | Bytes | SHA-256 (both captures) |
|---|---|---:|---|
| CFlash | `0x00000000..0x0017FFFF` | 1,572,864 | `d90b84abe6aada40c8e491f495d5ca3d88d6c3733e9d1cc8b4f35f32087cc76d` |
| Shadow flash | `0x00200000..0x00203FFF` | 16,384 | `2b4e703abd8e8b28857a3e519b7815876956c402af8467b1a1f4aef8a56b16ce` |
| DFlash | `0x00800000..0x0080FFFF` | 65,536 | `5bfe2886d3f25873e9cb13d43b9f00c69eae6cfb5364763845926a9d2381ca25` |

All recaptures passed byte-exact reference comparison. Every chunk had `DONE`, complete address
coverage, and zero rejected records or conflicting duplicates.

---

## 11. CAN1 work still required

The application analysis identifies CAN1 at `0xFFFC4000` and normally uses it as MS-CAN at
125 kbit/s. That does not by itself prove that the PBL/SBL leaves CAN1 clocked, pin-muxed, the
external transceiver enabled, and usable when custom code starts.

Before claiming CAN1 output, establish and test:

1. module clock and freeze/reset sequence;
2. MCR/CTRL bit timing for the desired bitrate;
3. SIUL pin mux for CAN1 TX/RX;
4. UJA1078A/transceiver enable state;
5. mailbox selection and inactive/active CS values;
6. host `can1` adapter configuration and physical connection;
7. one bounded `DUMPTEST` marker frame, exactly as was done on CAN0.

Until that marker is captured on CAN1, direct CAN1 transmission is a design, not a verified result.

---

## 12. Safety invariants for the final backup reader

- Execute only from SRAM.
- Do not set C55 erase/program/EHV bits.
- Treat source flash as `volatile` read-only memory.
- Use fixed, compile-time region bounds for the first hardware tests.
- Make address advance monotonic and exactly four bytes per accepted record.
- Wait for mailbox availability/transmit completion before overwriting it.
- For long runs, activate timer `0x4000FE04` with a 10 ms period, then call both
  `FUN_40004A24` and `FUN_400030DE`; copying only the loop calls is insufficient.
- Keep `0x18000`-byte chunks available as the proven restartable fallback.
- Power-cycle between failed payload tests if the custom code halts.
- Capture twice and require matching per-region hashes before treating the backup as authoritative.

---

## 13. Reproduction map

| Path | Purpose |
|---|---|
| `DV6T-14C097-AB.vbf` | immutable OEM SBL input |
| `hscan_bcm_flash.log` | known-working on-wire programming capture |
| `ghidra_proj_sbl/SBL.gpr` | persistent SBL analysis project |
| `work/sbl_merged.bin` | merged SRAM image for analysis |
| `work/sbl_setup.py`, `work/sbl_analyze.py` | project creation and analysis |
| `work/sbl_handlers.py`, `work/sbl_trace.py`, `work/sbl_txprim.py` | dispatcher/transfer/TX analysis |
| `work/sbl-upload/uds.py` | Linux CAN_ISOTP client |
| `work/sbl-upload/decode_log.py` | captured UDS transaction decoder |
| `work/sbl-upload/load_sbl.py` | VBF block loader and RAM call client |
| `work/sbl-upload/probe_upload.py` | stock `0x35`/`0x23` compatibility checks |
| `work/sbl-upload/build_probe.py` | earlier callback-based marker test |
| `work/sbl-upload/build_direct_probe.py` | live-proven direct FlexCAN marker builder |
| `work/sbl-upload/build_probe_vbf.py` | append custom block and repair VBF integrity |
| `work/sbl-upload/verify_probe_vbf.py` | structural/CRC/OEM-preservation verifier |
| `work/sbl-upload/run_probe.py` | load, raw-CAN capture, exact marker assertion |
| `work/sbl-upload/probe_capture.log` | bench marker capture |
| `work/sbl-upload/build_backup_reader.py` | assemble + round-trip the bounded addressed-record reader |
| `work/sbl-upload/build_backup_vbf.py` | append the reader while preserving all OEM blocks |
| `work/sbl-upload/verify_backup_vbf.py` | CRC, OEM-preservation, bounds, and store-target checks |
| `work/sbl-upload/run_backup_reader.py` | raw-CAN capture, reconstruction, hole/conflict checks, metadata |
| `work/sbl-upload/run_chunked_backup.py` | rebuild/reload per bounded chunk, reference-check, join, manifest |
| `work/sbl_decompile.py` | decompile SBL functions by containing address |

Generated files (`probe_blob.json` and `DV6T-14C097-AB_dump-probe.VBF`) retain their historical
development names. They contain only the current marker routine, **not a complete backup reader**.

---

## 14. Definition of done for a trustworthy owner backup

- [x] Stock SBL parsed and disassembled as VLE RAM code.
- [x] Stock arbitrary-read capability rejected by static analysis.
- [x] Stock `0x35` and `0x23` rejection confirmed live.
- [x] OEM SBL download and RAM call reproduced live.
- [x] Custom seventh SRAM block assembled and VBF integrity verified.
- [x] Direct raw FlexCAN marker transmitted and captured on CAN0.
- [x] Runtime ceiling measured and bounded chunk/reload strategy validated.
- [x] Exact user CFlash, shadow, and DFlash region list checked against RM0037 Rev 10.
- [x] Bounded flash-read/addressed-frame loop built and round-trip disassembled.
- [x] Receiver reconstructs ranges and detects holes/conflicts (host-side implementation complete).
- [x] CAN0 explicitly selected as the proven isolated-bench fallback.
- [x] Small bounded range captured twice with byte-identical hashes.
- [x] Every target region captured twice with identical hashes.
