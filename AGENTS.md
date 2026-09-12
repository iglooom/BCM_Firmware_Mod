# AGENTS.md — BCM firmware research and ACC-FIX porting guide

This file is for an engineer or agent modifying or analysing this Ford BCM firmware, especially when
porting the ACC-FIX SWM cruise-button remap to another OEM application version.

All addresses, hook sites, mailbox indices, cave locations, RAM cells, bit assignments and checksum
locations are version-specific. Re-derive them for the target image. Values from
`JV6T-14C094-AD` are examples and must not be copied blindly.

Read first:

- `README.md`: image layout, integrity, gateway model, shipped modifications and retractions
- `docs/acc-fix.md`: current ACC-FIX implementation and validation
- `docs/gateway_map.md`: gateway tables and frame maps
- `docs/0c0_standby_read.md` and `docs/030_composition_trace.md`: RX and composition evidence
- `docs/rke-lock.md` and `docs/key_outside_gate.md`: second use of the mailbox-injection method
- `docs/owner_flash_layers.md`: detailed research history and corrected conclusions

## 1. Repository and project boundaries

There are four separate Ghidra projects. Their addresses and purposes are not interchangeable:

- `ghidra_proj/` / `BCM_C1MCA`: OEM merged application used by the shipped `acc-fix` and `rke-lock`
  builders and verifiers. Do not delete or repoint it.
- `ghidra_proj_fullflash/` / `BCM_OwnerFlash`: primary analysis project for `cflash.bin`; includes the
  PBL below `0xC000`, shadow array and DFlash.
- `ghidra_proj_accfix_rkelock/`: built modified image.
- `ghidra_proj_sbl/` / `SBL`: secondary bootloader.

Hardware identity matters too. Read the ECU identity before using version-specific addresses.
`F188` is the application software part number, `F124` is calibration and `F111` is the hardware or
assembly part. A module reflashed with only one block is a hybrid: code addresses may match the new
application while behaviour still depends on the original calibration and hardware.

## 2. Non-negotiable rules

1. **Verify every version-specific value.** Derive hook sites, mailbox gates, frame-image addresses,
   caves, scratch RAM and integrity fields from the target image. Prefer two independent methods.
2. **Repair all three integrity layers after any application edit:** internal `sum8`, per-block
   CRC-16, then file CRC-32. Missing the internal checksum puts the BCM in safe mode.
3. **Keep the application block byte-exact.** Do not realign or repad it.
4. **Assemble VLE with Ghidra only.** Set `contextreg = 0x20000000`, then assemble, write,
   re-disassemble and compare every instruction.
5. **Guard every edit with expected original bytes.** A version mismatch must stop the build.
6. **Use Ghidra read-only for analysis.** Only annotation or intentional analysis updates may open a
   project writable. One process may hold a project at a time; close it in `finally`.
7. **Treat scripts and debug tools as measuring instruments.** Validate them against known truth,
   print their scope and controls, and distinguish `FAIL` from `INCONCLUSIVE`.
8. **Static analysis is not final proof.** Validate frame behaviour with `candump` on the vehicle.
9. **Do not attach an unvalidated debugger to a live ECU.** The `xpc56` OpenOCD fork may halt the CPU
   during `init`, fail to resume it and require a physical power cycle. Prove recovery first.
10. **Do not trust summaries over evidence.** Re-check important delegated or generated claims
    against instructions, listings, captures and produced artifacts.

## 3. What ACC-FIX does

The BCM builds HS-CAN `0x030` from LIN steering-wheel-module buttons. A newer SWM puts its cruise
buttons on fields ignored by the older PCM. ACC-FIX hooks both generic FlexCAN TX packers and edits
only the mailbox carrying `0x030`:

- `ACC_Res_Plus` (`d1` bit 6) becomes `CC_Res` (`d5` bit 5) when cruise or limiter is cancelled and a
  stored speed exists; otherwise it becomes `CC_Set_Plus` (`d5` bit 7). The original bit is cleared.
- `ACC_Lim` (`d1` bit 5) becomes `CC_Lim`, `d6[5:6] = 0b10`. The original bit is cleared.
- Resume versus Set+ uses both `0x0C0 d0` (PCM state) and `0x060 d6` (stored set-speed).

The edit belongs at the TX mailbox because the source and destination fields are composed by
separate PDUs. The physical button is held while `0x030` repeats, so the Resume/Set+ decision must be
latched on the press edge and held until release.

`rke-lock` applies the same technique to MS-CAN `0x3A`, sharing the existing caves and hooks. Its key
lesson is that command bits may be one-shot strobes rather than levels. Capture the ECU's native
action before reproducing a command frame.

## 4. Environment

```bash
cd <repo>/BCM/Research
. .venv/bin/activate

# Ghidra 12.x: /opt/ghidra
# Language: PowerPC:BE:64:VLE-32addr
python3 work/gw_dec.py 0xADDR [0xADDR ...]  # decompile entries
python3 work/gw_mbfull.py                   # FlexCAN mailbox/filter lists
```

The merged big-endian image is `work/flash_merged.bin`; the application starts at file and memory
address `0x10000`, and SRAM starts at `0x40000000`. Build a target image from its own VBF set with the
README's `vbf_extract` / `build_image` pipeline.

For owner/full-flash addresses use the owner tools and data, especially
`work/owner/rx_frame_map.json`. Do not substitute mappings from the other project.

## 5. Porting procedure

### A. Build and analyse the target image

1. Extract the target VBFs and validate their CRCs.
2. Build a new `flash_merged.bin` without changing block layout or padding.
3. Load it into a new Ghidra program with VLE context on code regions, then analyse it.
4. Keep the target separate from every existing Ghidra program.

### B. Find the `0x030` TX path

1. Use the CAN0 acceptance-filter and mailbox lists to locate TX frame `0x030` and its mailbox index.
2. Find the generic TX packer by locating the write that arms the mailbox CS/CODE word. The packer
   copies payload bytes to `base + 0x80 + index*0x10 + 0x8` and then writes the CS word.
3. Find both the single-frame and periodic-walker paths. Hook both unless the target genuinely has
   only one.
4. Record the exact displaced instruction or instructions. A 4-byte `e_b` may replace two adjacent
   16-bit VLE instructions; replay all displaced work in the cave.

### C. Derive the mailbox gate

For the target mailbox, compute:

```text
MB_CS = CAN_base + 0x80 + mailbox_index * 0x10
```

For CAN0 the base is normally `0xFFFC0000`. Payload byte `d0` is at `CS+0x8`, so `d1`, `d5` and `d6`
are at `CS+0x9`, `CS+0xD` and `CS+0xE`. Confirm the controller base and mailbox index from the target
rather than assuming these values.

### D. Derive RX frame-image addresses

Read received data from decoded RAM frame images, not raw RX mailboxes.

Preferred route for the owner image:

```bash
python3 work/owner/80_rx_record_decode.py
python3 work/owner/83_annotate_l13_rxmap.py
```

Then use `work/owner/rx_frame_map.json`. For a new image, regenerate it and verify at least one entry
manually:

1. Find the RX frame in the controller's acceptance-filter list. Its filter-list position is the
   hardware mailbox index; verify this in the mailbox initialisation loop.
2. Find the reception-descriptor record with that mailbox index.
3. Read its frame-image pointer and byte copy mask.
4. Confirm the RX copier's exact behaviour.

The copier may compact bytes: the destination offset is the number of set copy-mask bits below the
wire-byte index, not necessarily the wire-byte index itself. In `-AD`, for example, `0x060` uses mask
`0xFE`; `d6` is stored at base plus five.

Known `-AD` examples, for cross-checking only:

- `0x0C0 d0`: MB30, RAM `0x40000707`
- `0x060 d6`: MB22, RAM `0x40000705`

### E. Re-derive button and state semantics

Confirm the target's `0x030` fields from composition handlers, decoded captures and
`PCM/PCM_Research/SWM_CRUISE_BUTTONS.md`.

For `-AD`, Resume is selected when:

```text
(0x0C0_d0 & 0x48) != 0  AND  0x060_d6 != 0
```

Otherwise the press becomes Set+. This two-frame test is required because the `0x0C0 d0` cancelled
state decays after roughly two seconds into the same value used before any speed is stored. Tests
using bit 3, `(d0 & 0x28) == 0x08`, or bit 6 alone failed on the vehicle.

Do not carry these status values to another model year without a fresh capture. Exercise every
state, including the post-cancel decay, and correlate frame values with actual vehicle behaviour.

### F. Select code caves and scratch RAM

Choose non-overlapping `0xFF` caves inside the application block and inside the internal-checksum
range. In `-AD`, the two caves are at `0x117100` and `0x117300`; these are examples only.

Use a persistent scratch byte for the press latch:

```text
if button_held:
    if latch == 0:
        latch = RESUME if resume_condition else SET_PLUS
    apply(latch)
else:
    latch = 0
```

Both TX caves must share the same latch. Do not reuse live SWM state bytes.

A scratch address must be:

- inside the startup zero/ECC-initialised RAM range;
- outside the stack and SDA-accessible regions;
- absent from firmware references and writes;
- checked for pointer escape to callees, not only direct references.

`-AD` uses `0x40011000`, but this must be re-proven for another image. Remember that PPC `r0` cannot
serve as a load/store base register.

### G. Build and round-trip the trampolines

Use `work/acc-fix/build_caves.py` as the template. Update:

- mailbox gate and packer-specific mailbox base register;
- data-byte masks and offsets;
- RX frame-image addresses;
- hook and return addresses;
- displaced OEM instructions.

Set VLE context before assembly and disassembly. Round-trip every line and compare the resulting
instruction stream. Before using a scratch register across calls, count its references in the whole
enclosing function rather than relying only on ABI convention.

If Ghidra rejects a mnemonic, find the same instruction form in OEM code and reproduce its bytes
with the assembler. Do not guess encodings.

### H. Patch the VBF and repair integrity

Use `work/acc-fix/build_vbf.py` as the template. It must:

1. Assert expected OEM bytes at every hook and cave edit.
2. Apply the generated blobs.
3. Repair internal `sum8`.
4. Recompute CRC-16 for every VBF block.
5. Recompute the file CRC-32.

Output only the application VBF unless the target requires another block edit.

### I. Verify before flashing

Use `work/acc-fix/verify.py` and require all checks to pass:

- VBF structure, every block CRC-16 and file CRC-32;
- internal `sum8`;
- cave re-disassembly from the rebuilt image;
- hook destinations and displaced-instruction replay;
- behavioural simulation across all relevant PCM states;
- OEM diff limited to hooks, caves and integrity fields.

A verifier must derive cave spans, identifiers and expected sets from build output such as
`patch_blobs.json` or `build_info.json`. Do not hard-code lengths that can silently become stale.
When a checker fails, determine whether the artifact or checker is wrong; do not weaken the test just
to make it pass.

### J. Annotate, flash and validate

Run `work/acc-fix/annotate_ghidra.py` with target-specific addresses. Reopen the project read-only and
verify annotations by address set.

Before flashing, identify the ECU with `F188` and derive erase regions from the VBF header. Handle
UDS `7F 31 78` as `responsePending` and wait for the final positive response; aborting after erase
but before write can leave the ECU unusable until recovered.

After flashing:

1. Confirm that the BCM boots without an integrity or safe-mode fault.
2. Capture `0x030` while pressing RES+ and LIM in every cruise and limiter state.
3. Confirm one stable output choice for the full held press and correct release behaviour.
4. Update the implementation documentation with target addresses and artifact hash.

## 6. Integrity algorithms

The known `-AD` layout is:

```text
sum8   stored at 0x13FFFE, low 16 bits
       sum(bytes[0x10000:0x13FFFE]) & 0xFFFF
       high half at 0x13FFFC remains 0xFFFF

CRC16  per VBF block: CRC-16/CCITT-FALSE
       poly=0x1021, init=0xFFFF, no reflection

CRC32  zlib.crc32 from the first block's start-address field through EOF
       stored in header: file_checksum = 0x...;
```

Repair order is data, `sum8`, all block CRC-16 values, then file CRC-32. Re-derive the internal
checksum location and range on another firmware by comparing at least two OEM versions and requiring
the same algorithm/range to match both stored values.

## 7. Ghidra and pyghidra pitfalls

- The GUI's `Analyzed` flag can be stale even when analysis exists. Inspect database counts first,
  then use `GhidraProgramUtilities.markProgramAnalyzed()` and
  `markProgramNotToAskToAnalyze()` when appropriate. Helper:

  ```bash
  python3 work/owner/07_check_analyzed_flag.py
  python3 work/owner/07_check_analyzed_flag.py --fix
  ```

- pyghidra may leave non-daemon JVM threads alive. For read-only scripts, print and flush exceptions,
  flush stdout/stderr, then use `os._exit(0)`. Never put a bare `os._exit(0)` in `finally`; it hides
  tracebacks and exits with success.
- Large writes must exit normally after saving; `os._exit()` can kill the JVM before disk flush.
- Save a `GhidraProject` program with `project.save(program)`, not
  `program.getDomainFile().save(monitor)`.
- Aborting a nested transaction can roll back the enclosing transaction. Commit the transaction and
  explicitly undo rejected units instead.
- After any bulk write, close and reopen the project read-only, then verify persisted counts or
  address sets.
- `project.close()` releases the program. Do not also call `program.release(project)`.
- `setBookmark` replaces an existing bookmark with the same address, type and category. Verify the
  expected address set, not a raw bookmark count.
- Ghidra may zero-pad displayed addresses. Verification string matching must use the actual listing
  format and, where possible, assert expected call counts rather than loose substrings.

### VLE assembly notes

- Assembler: `ghidra.app.plugin.assembler.Assemblers.getAssembler(program.getLanguage())`
- Assembly context: `AssemblyPatternBlock.fromBytes(0, JByteArray([0x20, 0, 0, 0]))`
- Before disassembly, set the program context register to `0x20000000`, clear existing code units and
  run `DisassembleCommand`.
- Comment constants are on `ghidra.program.model.listing.CodeUnit`.
- Open writable with `openProgram("/", "<name>", False)`, edit in a transaction, then call
  `project.save(program)`.

## 8. Research and validation discipline

The detailed failure histories remain in the linked research documents. Apply these rules to new
work:

### Controls and null results

- Zero, constant, saturated or empty results are not automatically negatives. First prove the
  instrument can observe variation and that the reference channel is alive.
- A positive control is valid only if it covers the subject's code range and addressing form.
  Evaluate controls per scan arm and assert expected sites or counts, not merely `> 0`.
- State scan ranges, addressing forms, unswept-function counts and search bounds in script output.
  A bounded walk that hits its limit is `PARTIAL`, not complete.
- Run null controls before and after the stimulus, reset state between trials and record initial
  values separately from edges.
- Before crediting a write, baseline the target cell without the stimulus. Writing the value a cell
  already holds proves nothing.

### Static-analysis coverage

- Check whether the neighbourhood of a reader or writer belongs to a Ghidra function. Reference-based
  scans are blind in unswept blocks.
- On this VLE target, memory accesses may appear as `CALLOTHER` userops rather than `LOAD`/`STORE`.
  Use p-code, reference-manager and raw base-plus-displacement methods as complementary instruments.
- Scope register tracking per function, but account for Ghidra functions whose base register is set
  just outside the assigned body.
- Before claiming "no writer", check direct references, base-relative struct fields, unswept blocks
  and pointer escape into callees. Several agreeing tools may share the same blind spot.
- Follow `CALL`, `JUMP` and fallthrough edges with `ReferenceManager.getReferencesTo()`.
  `getCallingFunctions()` alone misses callers in unswept code.
- Literal-pointer scans are weak here because addresses are commonly built with
  `e_lis` + `e_add16i`. Run a known-pointer control before interpreting a null.
- If every access is `disp(rX)`, test whether the apparent global is a field in a common structure.
  Enumerate the structure instead of treating every field reference as a use of one global.

### Decode and mapping correctness

- Model primitive width. A 16-bit decoder anchored on `d6` may consume `d7` without any direct `d7`
  descriptor or reference.
- Match the firmware's internal representation, not assumed wire semantics. A captured bit flag may
  become an enum in code.
- Decode PowerPC `rlwinm` and `rlwimi` with rotate, wraparound masks and full load/insert/store shape.
  Validate complementary insert/extract pairs on a known field.
- State bit-numbering convention at every claim. Decompiled shifts normally use LSB numbering;
  PowerPC `mb`/`me` use MSB numbering. Prefer literal masks such as `0x600` where possible.
- Require one-to-one maps to be injective. Drop collisions and report holes rather than inventing a
  complete map.
- Validate a decode with a falsifiable prediction against independent evidence. If known behaviour
  contradicts the result, inspect the instrument before rationalising the discrepancy.
- Compare meanings, not mere overlap or coverage. On-vehicle captures outrank generic platform
  databases for this part number; document conflicts.

### Timing and behavioural inference

- Pair events with the nearest valid counterpart and state the pairing rule.
- Vary stimulus cadence before calling a constant offset a pipeline delay. For multi-event bursts,
  compare every destination value; a stable offset may be internal burst spacing.
- Verify edges move with stimulus timing. A repeated timestamp across different cadences is not
  stimulus-locked.
- Reachability to a target proves little unless unrelated starting points do not reach the same
  target. Compare target sets, not only hit counts.
- Static disjointness is a code-scope result, not proof that paths never meet at runtime.
- Test neighbouring off-target stimuli. A bit that rises for every command in a class is probably an
  activity indicator, not a command-specific gate.
- Prefer observables independent of the condition under test; this separates "write failed" from
  "consumer never ran".

### Hardware, UDS and capture checks

- Validate memory reads against known bytes in the flashed image before trusting debugger output.
  Working JTAG transport or status reads do not prove core register and memory reads work.
- For open-drain or bidirectional reset, assert low and release to high impedance. Do not drive high
  and read back your own output. State pull configuration and verify a functional recovery.
- Verify protocol bit indices and documented constant register bits against the reference manual.
  Print raw named fields, not only a derived verdict, and change one variable at a time.
- Test proposed wire formats on stock firmware before building a cave. Read NRCs; they often identify
  the bad assumption.
- A self-referential read, such as peeking the request buffer containing the peek address, is a strong
  liveness control for a memory-read service.
- Match UDS replies by service (`sid+0x40` or `7F <sid> <nrc>`), not merely ISO-TP PCI shape.
- A suppress-response request is unsuitable for diagnosis because rejection and success can look the
  same. Clear the suppress bit when investigating.
- A filtered `candump` that excludes the response or ordinary traffic cannot prove the bus became
  quiet.

## 9. Main files

| File | Purpose |
|---|---|
| `work/acc-fix/build_caves.py` | Assemble and round-trip caves and hook branches |
| `work/acc-fix/patch_blobs.json` | Generated hook/cave blobs and addresses |
| `work/acc-fix/build_vbf.py` | Patch APP VBF with byte guards and repair integrity |
| `work/acc-fix/verify.py` | CRC, sum8, disassembly, simulation and OEM-diff checks |
| `work/acc-fix/annotate_ghidra.py` | Add labels, comments and bookmarks |
| `work/gw_dec.py` | Decompile by entry address |
| `work/gw_mbfull.py` | Dump mailbox/filter lists |
| `work/gw_rxdesc.py` | Inspect reception descriptors |
| `work/find_algo.py`, `work/check_internal.py` | Find and verify internal integrity algorithm |
| `work/vbf_crc_validate.py` | Validate VBF CRCs |
| `work/cmp_ab_ad.py` | Compare OEM versions |

## 10. Structural differences on another target

- Different `0x030` fields: redo the composition and capture analysis, then change masks and offsets.
- One TX packer: use one hook and cave only after proving the second path does not exist.
- Two 16-bit instructions under a 4-byte hook: displace and replay both.
- Different PCM state frame: derive the actual received state and stored-speed sources. If no valid
  discriminator exists, use unconditional Set+ rather than an invented Resume rule.
- No large in-block cave: split the logic across smaller caves. Never place executable payload
  outside the flashed, internally checksummed application region.

## 11. Definition of done

- [ ] Target ECU and application identity recorded.
- [ ] Every target address and bit assignment re-derived and evidenced.
- [ ] Internal sum8, every CRC-16 and file CRC-32 pass.
- [ ] Hooks and caves re-disassemble exactly from the rebuilt image.
- [ ] Displaced OEM instructions are replayed correctly.
- [ ] OEM diff contains only expected hooks, caves and integrity fields.
- [ ] Behaviour simulation covers all relevant state combinations.
- [ ] Ghidra annotations persist after reopening the project.
- [ ] BCM boots without safe mode or integrity faults.
- [ ] Vehicle captures confirm correct RES+, LIM, hold and release behaviour in every state.
- [ ] Documentation records target addresses, cave locations, scratch RAM and artifact hash.
