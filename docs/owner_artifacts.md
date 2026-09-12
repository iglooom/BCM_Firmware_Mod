# Owner full-flash analysis — artifact index

Quick reference for the machine-readable outputs and scripts produced by the layer-by-layer analysis
in [`owner_flash_layers.md`](owner_flash_layers.md). Everything here is regenerable — see §27 of that
document for the command sequence.

- **Image:** `backups/owner-backup-20260911T090300Z/cflash.bin` (verified against `SHA256SUMS`)
- **Ghidra project:** `ghidra_proj_fullflash/` · `BCM_OwnerFlash` · program `cflash.bin`
- **Scripts:** `work/owner/` (numbered in execution order)

---

## 1. Data artifacts (`work/owner/*.json`)

| File | Contents | Produced by | Doc |
|---|---|---|---|
| `rx_frame_map.json` | **279 RX frames** — mailbox, CAN ID, copymask, DLC, arrival-flag bit, and the absolute address of every present byte | `80_rx_record_decode.py` | §17 |
| `tx_frame_map.json` | **15 HS TX frames** — mailbox, CS address, image base, present mask, request bit, alive-counter increment, per-byte addresses | `86_tx_decode_real.py` | §18 |
| `net_frame_maps.json` | Per-net TX+RX maps for all four control blocks (HS ×2, MS ×2), incl. **43 MS TX / 30 MS RX** records | `93_identify_by_flags.py` | §19 |
| `did_readers.json` | **476 diagnostic identifiers** bound to their dedicated reader functions | `37_did_readers.py` | §11 |
| `did_table.json` | The 492-entry DID identifier array | `34_did_decode.py` | §10 |
| `signal_bit_map.json` | 168 bound signal bits: signal cell → frame-image byte → bit index | `70_signal_bit_map.py` | §15 |
| `can_id_map.json` / `can_domains.json` | Mailbox→ID map and functional-domain classification, cross-validated against the vehicle databases | `25_can_db_xref.py`, `26_can_domains.py` | §9 |
| `asbuilt_config.json` | The 22 `0x28xx` as-built identifiers and the 85 retained-RAM cells behind them | `41_asbuilt_trace.py` | §12 |
| `feature_modules.json` | The 83 feature modules and their state slots | `16_feature_modules.py` | §7 |
| `peripheral_census.json` | Every peripheral the firmware touches: functions + distinct registers, on the fully-swept image | `118_peripheral_census.py` | §24 |
| `siul_pcr_values.json` | ⚠ 33 pads with PCR values — **`PA` field decoded wrongly**, see §28.1 | `123_pcr_values.py` | §24.6 |
| `pad_map_final.json` / `pad_map.md` | **The pad map**: 35 pads → pin, PCR, direction, PA, peripheral function, configuring function | `131_lin_pads_and_final_map.py` | §28.4 |
| `siul_pcr_decoded.json` | PCR values under the corrected bitfield + the GPDO/GPDI evidence used to test it | `126_pcr_bitfield_redo.py` | §28.3 |
| `pad_altfunc.json` | Datasheet pin-function table: pad → {AFn: (signal, peripheral)}, 145 pads | `127_pad_altfunc_table.py` | §28.4 |
| `psmi_table.json` | RM0037 Table 182: PADSEL field → peripheral input + the pad each value selects | `129_psmi_input_map.py` | §28.5 |
| `pad_function_map.json` | Pads joined to peripherals + every PSMI reference site in the image | `128_pad_function_map.py` | §28.5 |
| `pad_init_functions.json` | The 14 pad-init functions: pads configured, other peripheral blocks touched, callers | `130_pad_init_functions.py` | §28 |
| `orphan_classes.json` | Why each of 8,978 callerless functions has no caller (FALLTHROUGH / BRANCH_INTO / ISOLATED / DATA_PTR) | `135_orphan_classify.py` | §29.1 |
| `orphan_tables.json` | Orphan entry addresses stored as 32-bit words, clustered into dispatch tables | `134_orphan_connectivity.py` | §29.3 |
| `pad_config_table.json` | The 149-record boot pad table: every pad's PCR, flags, decoded function | `138_pad_config_table.py` | §30.2 |
| `discrete_input_map.json` | The 60 polled discrete-input pads and the routine blocks reading them | `146_discrete_input_map.py` | §31.2 |
| `combo_gate_inputs.json` | The 5 combination-gate inputs → pads/pins (§38) | `174_combo_gate_inputs.py` | §38 |
| `discrete_bit_map.json` | **The discrete-input bit map**: 37 pads → (state cell, bit), injective, regression-tested | `171_discrete_bit_map.py` | §37 |
| `switch_state_bits.json` | ⚠ pad→state-bit leads — **non-injective, unreliable** except PI15/PF12 | `148_switch_state_bits.py` | §31.2 | — superseded by `discrete_bit_map.json`
| `true_entries.json` / `callgraph_up.json` | True entries behind swept blocks, and the climb to `APP_main` | `152`/`153` | §32.1 |
| `periodic_arch.json` | The periodic dispatcher's three layers + their callees, sizes, RAM bands | `155_periodic_arch.py` | §32.3 |
| `unpack_stage.json` / `unpack_coverage.json` | RX unpack descriptors (src/mask/shift) and coverage vs the RX map | `158`/`159` | §33 |
| `rx_signal_dict.json` / `.md` | **The RX signal dictionary**: (CAN id, byte, mask, shift) → signal cell, 346 descriptors | `162_rx_signal_dict.py` | §34 |
| *(not in repo)* `/tmp/rx_dbc_join.json` | Vehicle-DB join — written **outside the repo** by design; regenerate with `163_dbc_join.py` | `163_dbc_join.py` | §35.1 |

Smaller intermediates (`signal_cells.json`, `dispatch_tables.json`, `struct_dispatch.json`,
`shared_api.json`, `tx_descriptors.json`, `app_to_can.json`) are working files from individual passes;
the doc cites them where relevant.

> ⚠ `tx_descriptors.json` holds the **361-record per-signal-bit array** (§15), which is a *different*
> structure from the TX frame records in `tx_frame_map.json` (§18). Its role is still unknown.

---

## 2. Validation status

Every address the two shipped, on-vehicle-proven mods depend on is reproduced **independently** by the
decoded tables — derived from consumer code, not copied from the mod sources:

| Address | Meaning | Mod | Doc |
|---|---|---|---|
| `0x40000707` | `0x0C0` d0, PCM cruise status | acc-fix | §17.3 |
| `0x40000705` | `0x060` d6, stored set-speed | acc-fix | §17.3 |
| `0xFFFC0080` | `0x030` TX mailbox CS | acc-fix | §18.2 |
| `0xFFFC4090` | `0x03A` TX mailbox CS | rke-lock | §19.3 |

The pad map (§28) adds a fifth, independent anchor: `BCM_CAN_Pins` records `HS-CAN PB0/PB1 ·
MS-CAN PC11/PC10 · MSX-CAN PE8/PE9`, and the decoded `PCR`/`PSMI` configuration reproduces **all six
pins on all three buses** from firmware bytes plus the datasheet alone.

Other external cross-checks: **58 MS-CAN directions agree, 0 mismatches** against the vehicle DB (§9);
**146/147 DIDs** and **29/29 security-gated DIDs** agree with a real scan-tool session (§10).

---

## 3. Verification

```bash
bash work/owner/verify_pass.sh        # annotation read-back + DB-leak check
python3 work/owner/99_project_audit.py # full project audit + key-address check
```

`verify_pass.sh` reads annotations **back out of the database** rather than trusting script
self-reports, and runs `leak_check.py`, which greps 2,294 proprietary CAN-database identifiers against
every file in `work/owner/` and `docs/` — the vehicle databases are used for analysis but their names
must never enter repo **text**.

> **Scope note (§35.1):** signal names *may* live in the Ghidra database (a binary store, useful for
> analysis); they must not appear in scripts, docs or `work/owner/*.json`. `163_dbc_join.py` therefore
> hardcodes no name and writes its join to `/tmp`. `leak_check.py` enforces the text side.

`99_project_audit.py` reports the analysed flag, symbol counts by prefix, bookmark categories, and
checks that 20 key addresses spanning all layers still carry user symbols.

Current state: **1,116 user-defined symbols**, `Analyzed=True`, 0 key addresses missing, leak check
clean (2,294 identifiers × 281 files). Layers 29–30 add the `OwnerFlash-TXPACK` (16) and
`OwnerFlash-REQBUS` (9) bookmark categories, read back by `184_verify_l29.py`.

### 3.1 Layer 29–30 artifacts

| File | Contents | Script |
|---|---|---|
| `tx_signal_dict.json` | 405 TX pack sites: `(source cell, dest image byte, mask, shift, function)`; 384 injective | `245` |
| `tx_setters.json` | destination-only first pass, kept as an independent cross-check | `242` |
| `lock_module_reads.json` | per-writer SRAM read sets for the lock-command writers | `244` |
| `lock_request_block.json` | body-state struct base + the 73 request-word writers | `185` |
| `request_word_bits.json` | per-bit producer/consumer map for all four request words | `186` |

---

## 4. Open items

Tracked in `owner_flash_layers.md` §26 (items 1–32). Status of the ones that used to gate progress:

1. ~~**The unpack stage**~~ — **RESOLVED (§33).** `APP_rx_unpack_main` `0x048C6C`, found by
   descending the call graph. The "unreachable by static analysis" verdict was true of *reference
   scanning* only.
2. ~~**The TX pack stage**~~ — **RESOLVED (§39).** `VOL_sig_set8` `0x0FBDD4` / `APP_tx_compose`
   `0x04B7AA`; both ends of the codec are now closed.
3. **Which paired configuration is live** — each bus has two control blocks, selected at bring-up in
   RAM (§19.4). Still required before any record-level patch.
4. **Is the ignition-on lock refusal a gate or a missing code path?** (§40.5, open item 30) — the
   intersection is located (`APP_lock_request_dispatch` `0x087A0E`) but no suppressing comparison
   was found, and the execute strobe has no pack descriptor at all. **Needs a capture, not more
   static work.**

> ⚠ **Cross-cutting (open item 26):** every reachability measurement taken before layer 29 is a
> *lower bound*. `getCalledFunctions()` truncates at linear-sweep block boundaries, so any
> "unreachable / no callers" conclusion in this repo should be re-tested with the forwards
> fallthrough walk (§39.3) before being trusted.
