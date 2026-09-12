# The TX pack stage, the two-phase periodic task, and the central-lock command chain

> **Layer 29** of the owner full-flash analysis (`docs/owner_flash_layers.md`).
> Scripts `work/owner/172`–`184`. Project: `ghidra_proj_fullflash/BCM_OwnerFlash` (`cflash.bin`).
> Evidence levels per the project convention: **(a)** confirmed control flow,
> **(b)** structurally strong, **(c)** lead.

**Why this exists.** The task was "achieve the rke-lock result a different way — find where the
central locking logic lives and where it intersects ignition state". Chasing the mod would have
produced one address. Following the *aggregators* instead produced the entire transmit half of the
firmware, which had been missing from the project since the beginning — and the lock command fell
out of it as one row in a 384-entry table.

---

## 1. The missing half of the codec (a)

§33 found the RX unpack stage (`APP_rx_unpack_main` @ `0x048C6C`) and its primitives
`VOL_sig_get8`/`get16`. The transmit counterpart was never located. It sits 0x272 bytes away from
`VOL_sig_get8` and has the mirror shape:

| Primitive | Address | Refs | Body |
|---|---|---|---|
| **`VOL_sig_set8`** | `0x0FBDD4` | **351** | `if (d[0x11] & 0x10) { *d[0] = (*d[0] & ~d[0x0C]) \| (d[0x0C] & (v << d[0x0D])); *d[0x04] \|= d[0x0E]; *d[0x08] \|= d[0x0F]; }` |
| `VOL_sig_set16` | `0x0FBD80` | 27 | same, 16-bit big-endian (high byte masked, low byte verbatim) |
| `VOL_sig_setN` | `0x0FBE20` | 27 | duff-device copy of 1–8 raw bytes into the image |
| `VOL_sig_getN` | `0x0FBB88` | 37 | the RX counterpart of `setN`, completing §33's primitive set |

The descriptor is the same 32-byte record as the RX side, read in the other direction:
**`+0x00` = pointer to the destination byte in the TX frame image, `+0x0C` = mask,
`+0x0D` = left shift**, plus two *dirty-flag* pointers at `+0x04`/`+0x08` with their bit masks at
`+0x0E`/`+0x0F`.

So the codec is symmetric and now closed at both ends:

```
RX:  mailbox --VOL_rx_copy_to_image--> frame image --VOL_sig_get8--> app signal plane
TX:  app signal plane --VOL_sig_set8--> frame image --VOL_tx_pack_*--> mailbox
```

### 1.1 Why it was invisible

Same tier-0 blind spot as §33, for the same reason: **the destination address lives in data**, in a
descriptor the code reaches through a `PTR_DAT_*` slot. No function names a frame-image byte, so the
five reference scans that "proved" features are decoupled from CAN could never have seen it. The
call graph, again, was never exhausted.

---

## 2. `APP_tx_compose` @ `0x04B7AA` — the aggregator (a)

One enormous straight-line routine that packs **every signal the BCM transmits**. The linear sweep
cut it into blocks (`0x4B7B0` with 129 call sites, `0x4C0EA` with 239, plus ~14 helper tails in
`0x4D9xx`–`0x4DExx`); the true entry recovered by the §32.1 backwards walk is `0x04B7AA`.

| Measure | Value |
|---|---|
| Pack call sites | **405** |
| Destinations resolved | **404** |
| Sources resolved | **384** |
| Distinct destination bytes | 249, spanning `0x40000748..0x40000C97` |
| `(dest, mask)` pairs with more than one claimed source | **0** |

That last row is the acceptance test (rule 10). A destination *byte* legitimately has several
sources — different bit fields — but a `(dest, mask)` pair must have exactly one. 384/384 injective,
so the extraction is sound. Output: **`work/owner/tx_signal_dict.json`**, the transmit counterpart of
§34's `rx_signal_dict.json`.

Source cells cluster tightly in the application signal plane:

| Band | Sources |
|---|---|
| `0x40002E00` | 198 |
| `0x40002F00` | 142 |
| `0x40003000` | 23 |
| others (`0x40001D00`, `0x40002800`, `0x40002D00`, `0x40004800`, `0x40007C00`) | 21 |

### 2.1 Transmission is change-driven (a)

Roughly a quarter of the pack sites are wrapped:

```c
if (VOL_test_and_clear_dirty(&flagbyte, bit))
    VOL_sig_set8(desc, value);
```

`VOL_test_and_clear_dirty` @ `0x031360` is `bit = 0x80 >> n; old = *p; *p &= ~bit; return old & bit;`
— a **test-and-clear**, so a signal is re-packed only on the tick after its producer flagged a
change, and the flag self-clears.

This is the missing piece of §14.5's explanation of the `rke-lock` sticky write. Two mechanisms
compound: the packer's post-TX `*img &= desc[k]` mask clears command bits *after* transmit, and the
dirty gate means nothing re-packs them *before* the next transmit. A cave that forces a mailbox byte
therefore persists until a producer marks that signal changed — not merely until the next packer pass.

---

## 3. ⚠ Correction to §32: the periodic task has TWO phases, not one (a)

§32 documented `APP_periodic_dispatch` @ `0x2F20A` with three layers (input acquire / signal process
/ feature periodic) and reported it as the whole periodic body. **It is only the first half.**

The routine continues at `0x2F262` — which the sweep made look like a separate function — with a
**second switch on the same mode cell** `APP_periodic_mode` (`0x40004103`):

```
APP_periodic_task 0x2F20A
├─ phase 1 ACQUIRE (0x2F20A)
│    mode 0 : input_acquire 0x449C4, signal_process 0x5799C, 0xD472A, 0x2E71A, feature_periodic 0x62848
│    mode 1 : input_acquire, signal_process, 0x2E71A
│    mode 2 : 0x61C26 first, then as mode 0 plus 0x2E71E   (mode 6 = same without 0x61C26)
└─ phase 2 EGRESS  (0x2F262)   ← fallthrough, NOT a call
     mode 1 : 0x579D6, 0x449F2
     mode 0 : 0x62914, 0x57A02, 0x44A04
     mode 2/6: 0x57A34, 0x44A20
```

**Every phase-2 entry is the byte-adjacent sibling of its phase-1 twin** — the compiler emitted each
periodic layer as an acquire/egress pair:

| Layer | Acquire | ends at | Egress twin |
|---|---|---|---|
| input | `0x449C4` `APP_input_acquire` | `0x449F1` | **`0x449F2`** (+ per-mode `0x44A04`, `0x44A20`) |
| signal | `0x5799C` `APP_signal_process` | `0x579D5` | **`0x579D6`** (+ `0x57A02`, `0x57A34`) |
| feature | `0x62848` `APP_feature_periodic` | `0x62913` | **`0x62914`** |

And the two halves reach **disjoint** codec stages — the crossover test (`179` P3):

| Entry | reaches RX stage | reaches TX stage |
|---|---|---|
| `0x449C4` acquire | `APP_rx_unpack_main`, `VOL_sig_get8/16` | — |
| `0x449F2` / `0x44A04` / `0x44A20` egress | — | `APP_tx_compose`, `VOL_sig_set8` |

So one periodic tick is, end to end:

> **read hardware inputs → unpack RX frames → run the feature layer → pack TX frames**

`APP_tx_egress` @ `0x449F2` is the **only** path from the periodic task into the pack stage.

### 3.1 How the correction was caught, and a method note

`179` was written to test the hypothesis "there is a second dispatcher". The fallthrough walk
**refuted it** — `0x2F262` has zero callers and is byte-contiguous with `0x2F20A`, so it is a
continuation, not an entry. The write-up follows the refutation, not the hypothesis.

The same script initially reported **empty** callee sets and "no crossover" for every entry. That was
the §29.2 artifact biting the *traversal*: `getCalledFunctions()` stops at every swept block boundary,
so call-graph reachability silently truncates after one hop. Adding a fallthrough-chain walk turned
the empty sets into the table above.

> **Generalise:** the backwards walk (§32.1) recovers a function's *entry*; a **forwards** fallthrough
> walk is needed to recover its *body* for reachability. Any reachability measurement in this project
> taken without it is a lower bound — including the ones that motivated "static analysis is exhausted".

---

## 4. The central-lock command chain (a)

The question that started this pass, answered as one row of the map.

### 4.1 The command cell

```c
/* in APP_tx_compose, at 0x4C62C */
if (VOL_test_and_clear_dirty(&APP_lock_command_dirty /*0x40003FC0*/, 4))
    VOL_sig_set8(desc 0x1439D4, APP_lock_command /*0x40002E70*/);   /* -> MS 0x3A d3 */
```

| | |
|---|---|
| **`APP_lock_command`** | `0x40002E70` → MS-CAN `0x3A` **d3** image `0x40000A12`, mask `0xFF` |
| **`APP_lock_command_dirty`** | `0x40003FC0`, bit 4 (`0x08`) |
| Wire meaning (level 5, `docs/rke-lock.md` §3) | `0x01` = LOCK, `0x02` = UNLOCK |

This is **level-5** evidence: the cell → descriptor → image byte → mailbox → wire chain is complete,
and the terminal value was proven on the vehicle by candump and by flashing.

Note the firmware writes **wider codes** than the wire shows — `0x1F`, `0x3F`, and `(x<<1)|1` — so d3
carries more than lock/unlock. Not resolved (level c).

### 4.2 The module

26 blocks across `0x087000..0x08F000` write the command; 40 write the command or its dirty flag.
The §32.1 backwards walk resolves them to **24 true entries**, of which **10 converge on
`0x93CC6`** — a large event-driven state machine that maps request codes onto lock states. Ten other
entries remain 0-caller after the walk (reached through pointers or from the swept region), so the
module's ingress is only partly closed (level b).

### 4.3 Where it intersects ignition — the honest answer (b)

The cluster `0x40001D80`/`0x40001D84`/`0x40001D85` is the power/mode state, and `181` verified it is
genuinely multi-valued rather than a constant (rule 8):

| Cell | Name given | Distinct compare constants | Readers | In the lock module |
|---|---|---|---|---|
| `0x40001D85` | `APP_power_mode` | `0,1,2,3,4` | 102 | **`0x87A0E`, `0x8A9E0`** |
| `0x40001D84` | `APP_vehicle_state_mode` | 13 values, `1..0xF` | 100 | `0x8CBFE`, `0x8CCDC` |
| `0x40001D80` | `APP_mode_flags` | `0,1,4,5,0xF` | 75 | `0x8764E`, `0x87A0E`, `0x8CBFE`, `0x8CCDC` |

**`FUN_00087A0E` is the intersection**: it is the single function that both tests `APP_power_mode`
(`== 1`, `== 3`) and writes `APP_lock_command` + its dirty flag — and it also *writes*
`APP_power_mode = 1`. Its shape is a four-way branch on a request word (`&UNK_FFFF8E70` bits 2/3/4/10)
where each arm emits a different command code (`0x1F`, `0x02`, `(x<<1)|1`, or `0x1F`/`0x3F` selected
by `Ram4000247C` bit 25) and conditionally clears a mode bit when `APP_power_mode` is `1` or `3`.

**What is NOT established, and must not be assumed:**

- That `APP_power_mode`'s `0..4` code set is the same as the **wire** power state decoded in
  `docs/ign_powermode_0x80.md` (MS `0x80` d2, codes `2`=off / `3`=post-accessory / `6`=ignition-on).
  The ranges differ. Equating them needs a capture correlating the two.
- That any branch in `0x87A0E` *is* the RKE-lock-with-ignition-on refusal. No such comparison has
  been isolated. The module's RKE ingress is still open (§4.2), and §4.4 below is a reason to expect
  the refusal may not be a simple compare at all.

> This is deliberately weaker than it could be phrased. `docs/ign_powermode_0x80.md` §2 has a
> standing retraction on exactly this subject — the "signal-accessor route" was proposed twice and
> abandoned twice. The intersection is now *located*; it is not yet *read*.

### 4.4 ⚠ The rke-lock execute strobe has no pack setter at all (a)

`177`'s regression against independently-proven facts reproduced **4 of 5** mod-critical image bytes,
including acc-fix's exact bit masks (`0x40000761` `0x20>>5` and `0x40>>6`; `0x40000766` `0x60>>5`),
which independently re-derives the bit map §36.1 validated against the vehicle database.

The exceptions are the interesting part:

| Image byte | Pack setters | Note |
|---|---|---|
| HS `0x030` d0,d1,d2,d3,d4,d6,d7 | present | 7 of 8 bytes covered — the scan is **populated**, so an absence is meaningful |
| **HS `0x030` d5** (`0x40000765`) | **none** | the byte `acc-fix` writes `CC_Set_Plus`/`CC_Res` into |
| MS `0x3A` d1 bit 6 | **none** | the **execute strobe** `rke-lock` proved on the vehicle |

Both mods write bytes/bits that **no pack descriptor ever targets**. This is the transmit-side twin of
§33.4 (the two acc-fix RX bytes are received but never unpacked), and it explains *why both mods work
and are safe*: they occupy signal slots this firmware build does not produce. Nothing upstream
competes for them, and nothing downstream clears them.

It also sharpens §4.3: if the BCM never packs the execute strobe from a signal cell, then "RKE lock
refused with ignition on" may not be a comparison that suppresses a command — it may be that the
command path for that combination **does not exist** in this build's generated codec. That is a
testable next step, not a conclusion.

---

## 5. Artifacts

| File | Contents |
|---|---|
| `work/owner/tx_signal_dict.json` | 405 pack sites; `(source cell, dest image byte, mask, shift, function)` |
| `work/owner/tx_setters.json` | the destination-only first pass (`242`), kept as an independent cross-check |
| `work/owner/lock_module_reads.json` | per-writer SRAM read sets for the 26 lock-command writers |

| Script | Purpose |
|---|---|
| `241_tx_pack_probe.py` | survey the codec region; find the pack primitives |
| `242_tx_setters.py` | resolve pack destinations via the `r3` descriptor |
| `243_lock_cell_refs.py` | all references to the lock command / dirty cells |
| `244_ign_lock_intersect.py` | shared inputs of the lock module |
| `245_tx_signal_dict.py` | full source→destination map + injectivity test |
| `177_tx_stage_structure.py` | true entries, spine climb, **regression vs the shipped mods** |
| `178_tx_stage_spine.py` | spine placement; the `0x030` d5 coverage test |
| `179_second_dispatcher.py` | the two-phase hypothesis (refuted as "second dispatcher") |
| `180_verify_two_phase.py` | structural proof of the fallthrough; decompiles the aggregator |
| `181_mode_cell_gate.py` | mode-cell identification with a non-tautology control |
| `182_lock_module_entries.py` | lock-module true entries and convergence |
| `183_annotate_l29_txpack.py` | annotation (9 functions, 7 data cells) |
| `184_verify_l29.py` | **independent read-back** — all checks passed |

Reproduce:

```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate
for n in 176 177 178 180 181 182; do python3 work/owner/${n}_*.py; done
python3 work/owner/183_annotate_l29_txpack.py
python3 work/owner/184_verify_l29.py
```

`184` re-opens the project read-only and asserts: this pass's 16 symbols, **11 anchors from earlier
layers** (to catch a rolled-back transaction), and that three specific **caveat strings** are still
present in the plate comments — so the uncertainty recorded in §4.3 cannot quietly disappear from a
later summary.

---

## 6. Open items raised by this layer

1. **Read `FUN_00087A0E`'s branch conditions properly.** The request word is
   `*(uint*)(&UNK_FFFF8E70 + param_4)` — a negative-offset frame base the decompiler could not
   resolve. Recovering `param_4` names the request bits and would settle §4.3.
2. **Close the lock module's ingress.** 10 of 24 true entries still have no caller; find the RKE
   request path into `0x93CC6`.
3. **Correlate `APP_power_mode` (`0..4`) with the wire power state (`0..7`)** from a capture, or
   demote the name.
4. **Re-audit every "unreachable / no references" conclusion** in the project with the forwards
   fallthrough walk of §3.1. The traversal bug that hid the crossover result is present in any
   reachability measurement taken before this layer.
5. **The `0x30`-plus codes** (`0x1F`, `0x3F`, `(x<<1)|1`) written to `APP_lock_command` are not
   explained by the two wire values.

---

## 7. Layer 30 — the body-control request bus, and the lock ingress (a)

Open items 25 and 27, resolved. Scripts `185`–`187`, verified by the extended `184`.

### 7.1 §39.4's blocker was a decompiler artifact, not a missing fact

§39.4 could not read `FUN_00087A0E`'s branch conditions because the decompiler renders its base as
`&UNK_FFFF8E70 + param_4` — a fake negative-offset symbol. **The disassembly had the answer all
along**: Ghidra already attaches the absolute reference to each access.

```
00087a1a  e_lwz  r3,0x88(r6)     -> 40008e70
00087a3a  e_lwz  r29,0x74(r6)    -> 40008e5c
```

`185` recovers the struct base from those resolved references and **checks self-consistency** —
every `(register, displacement)` pair must imply one base. `r6` → `0x40008DE8`, single-valued.
(`r4`/`r5` came back inconsistent, correctly flagged: they are reloaded mid-function, so their bases
are per-phase. Reporting that rather than averaging it is the point of the check.)

> **Method note worth keeping.** When the decompiler invents a `UNK_`/negative-offset base, do not
> conclude the structure is unreachable. Read the disassembly and harvest the *resolved references*,
> then verify the implied base is consistent. This unblocked an item recorded as needing new work.

### 7.2 `0x40008E70` is not a lock variable — it is an event bus (a)

The request word turns out to be one of **four** 32-bit words at `0x40008E68`, `0x6C`, `0x70`, `0x74`
(struct offsets `+0x80`,`+0x84`,`+0x88`,`+0x8C`), with **73 writer functions** spread across
`0x086000..0x095000`. This is how the body features talk to each other.

| Word | Ref sites | Bit ops matched | Value bits touched | True REQUEST bits |
|---|---|---|---|---|
| `APP_req_word_68` | 467 | 257 | 31 | 17 |
| `APP_req_word_74` | 406 | 232 | 32 | 24 |
| **`APP_req_word_70`** | **373** | **211** | **31** | **21** |
| `APP_req_word_6C` | 336 | 249 | 32 | 24 |

The VLE idiom makes it cleanly decodable: `se_bseti` = raise, `se_bclri` = consume/ack,
`se_btsti` = test. Per-bit producer/consumer lists in **`work/owner/request_word_bits.json`**.

> ⚠ **`se_btsti`/`bseti`/`bclri` number bits MSB-first.** Operand `N` means **value bit `31-N`**.
> `se_btsti r3,0x1B` tests value bit **4** (mask `0x10`), not bit `0x1B`. Every bit number in the
> table above and in the listing is the *value* bit. Getting this backwards would have silently
> produced a plausible-looking but entirely wrong bit map — the same error class as §28.1.

The extraction passes the populated/varied control (rule 8): 31–32 distinct bits per word, not one
bit repeated. Bits that are **test-only** (consumers but no matched producer) are reported as such
rather than hidden — that asymmetry means the producer is in a path the bit-op scan does not match,
which is a measurement limit, not a finding about the firmware.

### 7.3 The lock ingress (open item 25, resolved)

`APP_lock_request_dispatch` @ `0x087A0E` is the **consumer** end. It branches on four bits of
`APP_req_word_70` and emits a different `APP_lock_command` per arm, each followed by
`APP_lock_command_dirty = 0xFF` so the TX pack stage sends it on the next tick:

| Value bit | Producers | Command emitted |
|---|---|---|
| 4 | — (set elsewhere) | `0x1F`, and sets `APP_power_mode = 1` |
| 3 | `0x894FE`, `0x897DE` | `0x02` (UNLOCK) or `(x<<1)\|1` |
| 2 | `0x91070` | `0x1F` / `0x3F`, selected by `Ram4000247C` bit 25 |
| 10 | `0x9309C`, `0x93556`, `0x9389C`, `0x93C7C` (12 more clear it) | `0x1F` / `0x3F` |

**This partly answers open item 28 too**: the producers `0x894FE`/`0x897DE` write
`APP_lock_command = 6` — a *sixth* code. The firmware's enumeration (`0x02`, `0x06`, `0x1F`, `0x3F`,
`(x<<1)|1`) is far wider than the two values ever seen on the wire, so **d3 is a multi-code command
byte of which the capture has only ever exercised two states.** Item 28 is now sharper, not closed.

### 7.4 A conditioned automatic-lock gate (b on shape, c on identity)

`APP_lock_condition_gate` @ `0x08A096` is the clearest guard on the bus:

```c
if ( trigger_bit && mode == 1 && pending_bit &&
     ( DAT_40002E3F < 7
       || ( <gear-lever-position signal> == 0
            && DAT_40002E5A < threshold
            && DAT_40002E5C > 1 ) ) )
      -> emit lock state 9 or 10
```

A gear-lever test ANDed with a threshold comparison is the signature of a **speed/gear-conditioned
automatic lock**. The *shape* is established; the *identity* is not — three of the four inputs have
no established meaning, and naming it from shape alone is the error class this project keeps
catching. Recorded at (c) and the caveat is asserted in the listing.

### 7.5 What this does and does not say about the ignition gate

`APP_lock_request_dispatch` is confirmed as **the** ignition intersection: it is the only function in
the image that both tests `APP_power_mode` (`==1`, `==3`) and writes the lock command, and it also
writes `APP_power_mode = 1`.

**Still not established** — and now with a better reason to doubt the original framing:

- No branch here was shown to be the "RKE lock refused with ignition on" gate. Each arm *emits* a
  command; none was observed *suppressing* one.
- §4.4 stands: the execute strobe `0x3A` d1 bit 6 has **no pack descriptor anywhere**. If the BCM
  never packs the strobe from a signal cell, then the ignition-on refusal is more likely a **command
  path that does not exist in this build** than a comparison to patch out.

That makes the cheap decisive experiment a *capture*, not more static work: drive the vehicle to the
refusal condition and watch whether `APP_lock_command` changes at all (a gate that suppresses) or
whether d3 goes to `0x01` while d1 bit 6 never strobes (a missing path). The second outcome would
mean the rke-lock injection approach is not merely convenient but **necessary**.

### 7.6 Artifacts

| File / script | Purpose |
|---|---|
| `work/owner/lock_request_block.json` | struct-base recovery + the 73 request-word writers |
| `work/owner/request_word_bits.json` | per-bit producer/consumer map for all four words |
| `185_lock_request_block.py` | base recovery with a self-consistency check |
| `186_request_word_bits.py` | bit decode with MSB-first translation + populated/varied controls |
| `187_annotate_l30_reqbus.py` | annotation (4 functions, 5 data cells) |
| `184_verify_l29.py` (extended) | read-back: **25 items, 11 prior anchors, 7 caveat strings — all passed** |

---

## 8. Layer 31 — the RKE receive chain: 7 of 8 links proven, one hop open

Scripts `188`–`198`. **Direct answer to "do we have the full path from RFA button press to
the lock command for DDM/PDM?": almost — one hop remains genuinely unlocated.**

### 8.1 The chain, link by link

| # | Link | Status | Evidence |
|---|---|---|---|
| 1 | RFA radio → MS-CAN `0x100` (the RFA is the receiver and publishes on MS) | **PROVEN** | capture `mmcan_rke_close.log` |
| 2 | mailbox 53 → RX image `0x40000918..1F` | **PROVEN** | copier record `0x1520F8` |
| 3 | image `d6:d7` → 13-bit code → `APP_rke_command_code` `0x40002DA2` + valid flag `0x40003F53` | **PROVEN** | `VOL_sig_get16` desc `0x142FD4` (`191`/`192`) |
| 4 | code → one-hot per-command bits `0x40009034`/`0x40009038` | **PROVEN** | `APP_rke_command_demux` `0x0992B2` (`197`) |
| **5** | **one-hot bits → `APP_req_word_70` bit 3** | **⚠ OPEN** | no consumer of the demux output touches the lock module or the request bus |
| 6 | request bit → `APP_lock_request_dispatch` `0x087A0E` | **PROVEN** | `186` |
| 7 | dispatch → `APP_lock_command` `0x40002E70` + dirty | **PROVEN** | `185`/`187` |
| 8 | command → MS `0x3A` d3 image `0x40000A12` → walker → CS `0xFFFC4090` → DDM/PDM | **PROVEN** | `245` + on-vehicle |

```
RFA ─radio─▶ MS-CAN 0x100 ─MB53─▶ image d6:d7
   ─get16 desc 0x142FD4─▶ APP_rke_command_code 0x40002DA2  (13-bit, +valid 0x40003F53)
   ─APP_rke_command_demux 0x992B2─▶ one-hot 0x40009034/38
   ══════════════ ⚠ ONE HOP UNLOCATED ══════════════
   ─?─▶ APP_req_word_70 bit 3
   ─APP_lock_request_dispatch 0x87A0E─▶ APP_lock_command 0x40002E70 (+dirty 0x40003FC0)
   ─APP_tx_compose─▶ MS 0x3A d3 image 0x40000A12
   ─VOL_tx_pack_walker─▶ CS 0xFFFC4090 ─▶ wire ─▶ DDM / PDM
```

### 8.2 Two of my own method bugs, both caught by the user's domain constraint

This section exists because I twice reported a confident negative that was wrong. Both were
**wrong-expectation bugs** — the scan worked, the assumption behind it didn't.

**Bug 1 — "MS `0x100` d7 is never extracted" (`189`, `190`).** A raw-flash pointer scan found
**zero** pointers to `0x4000091F` anywhere in the image, with a passing positive control on `d1`.
The measurement was correct; the inference was not. **`VOL_sig_get16` reads the descriptor's byte
*and the next one*** (`CONCAT11(mask & *d[0], *(d[0]+1))`), so a 16-bit signal spanning `d6:d7` is
anchored on **d6** and `d7` is never addressed directly. Descriptor `0x142FD4` — src `d6`, mask
`0x1F` — is exactly the 13-bit command code `docs/rke_0x100_lock.md` §1 decoded from captures.

> **This also retires a standing negative result.** `rke_0x100_lock.md` §3 records d7 as having
> "ZERO references … no 4-aligned pointer, no raw pointer, no Ghidra xref" and its consumer as
> unfindable. All of that is *literally true* and was mis-read as "not extracted". Any per-byte
> descriptor scan on this firmware will reproduce the error.

**Bug 2 — "no per-button decode exists" (`194`).** I looked for a bitmask of `0x01`/`0x02` because
the *wire* decode is `d7 bit0 = LOCK`, `bit1 = UNLOCK`. The firmware instead treats the low nibble
as a **command enum**: `(code & 0xF) == 1`. My classifier saw `& 0xF` and filed it as "mask 0xf",
not a decode. The decoders were in front of me in the `0x0ADxxx` cluster the whole time.

**What prevented a third error:** the user's constraint that *the lock button can only arrive on
MS-CAN, because the RFA is the radio receiver*. I had hypothesised the HS-CAN copy of `0x100`
(mailbox 34) as the extraction site; that constraint killed the hypothesis and forced me to look for
a bug in my own method instead — which is where both of the above came from. **Domain knowledge beat
a clean-looking scan twice in one session.**

The generalisable rule, now also in `AGENTS.md`: **a descriptor-based scan must model the
primitive's width.** Before reporting a byte as unread, ask whether a *wider* primitive anchored on
a lower byte consumes it.

### 8.3 What the remaining hop is, and why it is not just more scanning

`APP_rke_command_demux` fans `(code & 0xF)` into one-hot bits across `0x40009034`/`0x40009038`, and
those words are read/written by **~56 and ~60 functions** in a `0x099000..0x09C000` subsystem that
this project has never explored — it holds exactly **one** user symbol. None of those consumers, with
the forwards fallthrough walk applied, touches the central-lock module or the request bus.

So the hop is not missing evidence, it is an **unexplored layer**. The honest framing:

- The RKE→lock path is **continuous in behaviour** (the car locks on a fob press with ignition off),
  so the hop exists.
- It is **not yet located in code**, and the natural next step is to explore `0x099000..0x09C000` as
  its own layer — the same way §32's spine work unstuck the last set of "0-caller" dead ends.
- Note `0x0992B2` reaches `APP_feature_periodic`, so that subsystem **is** on the runtime spine; it
  is reachable, just unread.

### 8.4 Bearing on the mod

None of this changes the shipped `rke-lock`, and it slightly strengthens the case for it: the
injection point is downstream of every link above, so it is indifferent to how links 5–8 are wired.
It also does **not** resolve open item 30 — whether the ignition-on refusal is a gate or a missing
path still needs the capture described there.

### 8.5 Artifacts

| Script | Purpose |
|---|---|
| `188_rke_chain_audit.py` | first link-by-link audit (found the gap; its d7 verdict was later corrected) |
| `189_rke_gap_locate.py` | corrected 188's framing: image refs vs unpacked signal cells |
| `190_rke_dual_bus.py` | HS-vs-MS hypothesis — **refuted** (and refuted again by domain constraint) |
| `191_rke_d7_get16.py` | raw-flash scan + primitive-width test → **found the get16 on d6:d7** |
| `192_rke_chain_close.py` | the validator/committer pair and the destination cell |
| `193_rke_code_consumers.py` | readers of the RKE code |
| `194_rke_button_decode.py` | button-decode classifier (**its negative verdict was a bug**) |
| `195_rke_decoder_link.py` | corrected 194; located the `& 0xF == 1` enum decode |
| `196_rke_true_entries.py` | backwards walk → `0x0992B2` reaches `APP_feature_periodic` |
| `197_rke_demux.py` | the one-hot demux and its ~116 consumers; bounded the open hop |
| `198_annotate_l31_rke.py` | annotation (3 functions, 4 data cells) |

`184_verify_l29.py` now covers all three layers: **32 items, 11 prior anchors, 10 caveat strings,
3 bookmark counts — all passed**; 1,123 user-defined symbols.

---

## 9. Layer 32 — the hop, bounded to one byte ~~which nothing writes~~

> ## ⚠⚠ THIS SECTION'S CENTRAL CONCLUSION IS RETRACTED — see §10 (layer 33)
>
> §9.2 below concluded that `0x40008D2C` has **no writer** and that the lock-request path is
> **inert in this build**. **That is wrong.** The writer is `se_stb r0,0xc(r29)` at **`0x9749A`**,
> fed from `0x40008EF7`. It was invisible to all four methods below because the instruction sits in
> an **unswept block** — Ghidra never created a function there, therefore never created a reference,
> and reference scans / base-register walks / indexed-store scans are all blind in such blocks.
> Decompiler **p-code** found it immediately.
>
> The four measurements in §9.2 were each *correct*; the **inference** from them was not. Everything
> below is kept verbatim as the record of how a well-controlled negative can still be false.


Scripts `199`–`209`. **Result: the chain is complete from the lock-request input byte all the way to
DDM/PDM, but that byte has no writer — and the structural evidence says this path is inert in this
build.**

### 9.1 What was found downstream (level a)

Working **backwards** from the request bit rather than forwards from the RKE frame was the move that
worked. `APP_req_word_70` bit 3 has exactly two producers, and they turned out to be *fallthrough
tails*, not functions — the parents test a bit of a **different** request word:

```
APP_lock_request_input 0x40008D2C   (boolean level)
  └─ APP_lock_req_edge_detect_A/B  0x86F90 / 0x8A812
        if (b==1 && !(req74 & bit9))  req74 |= bit10;   // rising edge -> event
        if (b==0 &&  (req74 & bit9))  req74 &= ~bit10;  // falling edge
        req74 = (b&1)<<9 | (req74 & ~bit9);             // bit9 = level memory
  └─ APP_lock_req_gate_A/B  0x894D2 / 0x897B2
        if (*0x40008D2D == 1 || (req74 & bit10))  ─fallthrough─▶
  └─ APP_lock_req_producer_A/B  0x894FE / 0x897DE
        req70 |= bit3;  APP_lock_command = 6;  dirty = 0xFF
  └─ APP_lock_request_dispatch 0x87A0E ─▶ APP_lock_command ─▶ MS 0x3A d3 ─▶ DDM/PDM
```

So `APP_req_word_74` **bit 9 = previous level, bit 10 = edge event** — the bus is used as a
multi-hop event chain, which is why single-hop searches kept coming up empty.

### 9.2 The negative result, at four independent methods (level b)

**No instruction in the image writes `0x40008D2C`.** Each method carried a positive control:

| Method | Result | Control |
|---|---|---|
| instruction-level resolved xrefs (`203`) | 11 READ, **0 WRITE** | `0x40008E74`: 246 R / 160 W |
| base-register-resolved stores, whole image (`204`) | 136 stores into this page, **none** to the cell | resolver found 136 real stores |
| register-**indexed** stores `stbx/sthx/stwx` (`207`) | 241 sites, 146 with a resolved operand, **0** landing in `0x40008C00..0x40009100` | 146/241 resolved |
| raw-flash literal pointer scan (`203`) | 0 pointers | **uninformative** — the control has 0 too (addresses are synthesised `e_lis`+`e_add16i`) |

The cell lies in **`.bss`** (`0x400054A0..0x4001B06B`), which the reset path zeroes on **every** reset
(§12.1). And the controls sit in the *same region*: `APP_req_word_74` has 160 writers, `req_word_70`
has 151. So "0 writers" is not an artifact of the region, the scan, or the sweep.

⇒ **The byte is permanently 0, the edge detectors never fire, and this lock-request path is INERT in
this build.** Same shape as §4.4/§39.5 (the execute strobe has no pack descriptor): code present in
the image but not wired for this part number. The live RKE→lock route is elsewhere.

> **This is level (b), not (a), and the distinction matters.** "No method I tried found a writer" is a
> claim about my methods. One hypothesis is untested: a write through a **pointer held in a struct
> field** (`obj->field = v`), which defeats every address-based method above and needs p-code
> dataflow. The caveat is asserted in the listing by `184` so it cannot quietly disappear.

### 9.3 Refuted hypotheses (recorded so they are not retried)

| Hypothesis | Refuted by |
|---|---|
| The HS-CAN copy of `0x100` carries the button | user's domain constraint + `190` |
| MS `0x100` d7 is never extracted | `191` — it is, via `get16` anchored on d6 |
| The demux output words reach the lock module | `197` — no consumer does |
| The bit-3 producers' input cells come from the RKE subsystem | `200` — zero overlap |
| The neighbouring latch-copy stage feeds `0x40008D2C` | `205` — **12 distinct deltas**, so the src→dst relation is not affine and the source of an unobserved destination cannot be extrapolated |
| An indexed store writes it | `207` — 241 sites resolved, none in range |

§9.2's table plus this one is the actual deliverable: the hop is now a **single named byte** with a
measured, controlled negative, rather than a vague "unexplored region".

### 9.4 Two method notes worth keeping

**A crash was the evidence.** `203` section 3 printed its header and then silently stopped —
`region(None)` raising `TypeError` on a write whose instruction has *no containing function*. The bug
was the finding: such writes exist (unswept blocks), and the guard now reports them as a `NO-FUNC`
class rather than dying.

**Rank by specificity, not by fan-out.** `199`'s forward bridge scan ranked `0x40006408` top with a
score of 158 — it is a generic error latch read by 115 lock-module functions. Classic AGENTS.md rule 9:
coverage is not agreement. The useful constraint was the *narrow* end (two producers reading ~6 cells
each), which is what `200` exploited.

### 9.5 Where this leaves the original question

| Link | Status |
|---|---|
| 1–4 RFA → MS `0x100` → 13-bit code → one-hot demux bits | **PROVEN** (§8) |
| **5 one-hot bits → lock-request input** | **OPEN** — and the input byte is provably unwritten by any visible code |
| 6–9 input → edge → event bit → producer → dispatch → `0x3A` d3 → DDM/PDM | **PROVEN** (§9.1) |

Both ends are now solid and the gap is one byte wide. The two ways to close it:

1. **p-code/dataflow search for `obj->field` writes** whose resolved target is `0x40008D2C` — the only
   untested static hypothesis (H5).
2. **On-vehicle correlation**, which is cheaper: press lock with ignition off (works today) and read
   the body-state block through a DID if one exposes it (`did_readers.json`), watching whether
   `req_word_74` bit 10 ever toggles. ⚠ **Superseded by §10:** the writer was found statically, so
   this capture is no longer needed to settle the question — it would now only confirm §10's chain.

Nothing here changes the shipped `rke-lock`: it injects at the TX mailbox, downstream of every link
above, so it is indifferent to which request bit is live.

### 9.6 Artifacts

| Script | Purpose |
|---|---|
| `199_rke_lock_bridge.py` | forward bridge scan (6 candidates; ranking shown untrustworthy) |
| `200_producer_backtrace.py` | backwards from the two bit-3 producers — the tight constraint |
| `201_parent_bit_trace.py` | the parents and the `req_word_74` bit 10 they test |
| `202_bit10_raisers.py` | decoded the rising-edge detector idiom |
| `203_lock_input_writer.py` | reference census + the `NO-FUNC` write class |
| `204_input_array_writer.py` | base-register-resolved stores across the image |
| `205_latch_copy_stage.py` | the latch stage; **invariant check refused an extrapolation** |
| `206_hop_bounded.py` | hypothesis enumeration H1–H6 |
| `207_indexed_stores.py` | 241 indexed stores resolved — H1 weakened |
| `208_bss_argument.py` | the `.bss` + zero-writers argument, with same-region controls |
| `209_annotate_l32_lockreq.py` | annotation (4 functions, 3 data cells) |

`184_verify_l29.py` now spans layers 29–32: **39 items, 11 prior anchors, 13 caveat strings,
4 bookmark counts — all passed**; 1,130 user-defined symbols. (It caught a real mismatch on first
run: the asserted caveat text did not match the comment's markup.)

---

## 10. Layer 33 — the writer, found by p-code; §9's negative retracted

Scripts `210`–`220`. **Result: link 5 is CLOSED. The chain from RFA to DDM/PDM is now complete
except for one register assignment.**

### 10.1 Three instrument bugs, in order

This layer is mostly a lesson about instruments.

**(i) My own signed-displacement bug (`210`).** Script `204` parsed store displacements as
`int(d,16) if d.startswith("0x") else int(d)`. For `-0xbc` the first test is False, so it fell to
`int("-0xbc")` base-10 → `ValueError` → swallowed by `except (IndexError, ValueError): pass`. The
target sits `-0xBC` from the body-state base, i.e. **exactly the form the scan could not see**.
Re-measured with correct signed parsing: **361 stores had been silently dropped**. The conclusion
nevertheless survived — still no base-resolved store to the cell — which is the good outcome: a fixed
instrument reproducing the same answer *strengthens* it.

**(ii) The p-code STORE walk was structurally blind (`211`→`212`).** My first p-code scan looked for
`STORE` PcodeOps and found **zero** hits on a control cell with 160 known writers. Rule 7: a zero on a
known-non-empty target is a bug. `212` dumped the real op shapes — this language models memory access
as **`CALLOTHER` userops**, not `STORE`:

```
CALLOTHER (const, 0x10000002, 4), (ram, 0x40008d2c, 1), (unique, ...)
                                   ^^^^^^^^^^^^^^^^^^ destination
```

**(iii) `os._exit(0)` in `finally` hides tracebacks (`214`).** Script `214` printed nothing and
exited **0**. An exception had been raised, but the `finally` block's `os._exit(0)` killed the process
before Python could print the traceback — *a crashing pyghidra script looks like a silent success*.
Every script from `215` on wraps the body in `except Exception: traceback.print_exc()`.

### 10.2 The writer, and the control that makes it a fact

```
00097496  e_lbz  r0,0xf(r21)     ; load  0x40008EF7
0009749a  se_stb r0,0xc(r29)     ; store 0x40008D2C   <-- APP_lock_request_input
0009749c  se_lbz r0,0x0(r28)     ; load  0x40008EF8
0009749e  se_stb r0,0xd(r29)     ; store 0x40008D2D
```

Every instruction in that block is **NOREF** — Ghidra attached no reference to any of them, and
`getFunctionContaining(0x9749A)` is `None`.

The ram operand is a **write**, not a read, by a disjoint control (`217`):

| userop | meaning | sites | instructions |
|---|---|---|---|
| `0x10000002` | **STORE** | 199 | all `e_stb`/`se_stb` |
| `0x10000001` | **LOAD** | 285 | all `e_lbz`/`se_lbz` |

The two sets never overlap, and the op at `0x9749A` carries `0x10000002` identically in **four**
independently decompiled host functions.

> **Honest limit:** the register walk could **not** resolve `r29` (`215`/`216`) — it is established
> upstream of the analysed entry, in unswept code. The p-code resolution is the primary evidence,
> corroborated by the neighbouring stores landing on a contiguous ascending run
> (`0x40008D29..0x40008D33`) exactly matching their loads.

### 10.3 The chain, one hop longer

```
APP_lock_src_producer 0x978D2
  ├ 0x97994  e_stb  r6,0xf(r21)  -> APP_lock_src_level   0x40008EF7
  └ 0x9799C  se_stb r6,0x0(r28)  -> APP_lock_src_level_2 0x40008EF8
        │  [unswept latch-copy block]
        ├ 0x9749A -> APP_lock_request_input   0x40008D2C
        └ 0x9749E -> APP_lock_request_input_2 0x40008D2D
              └ edge detect -> req74 bit10 -> gate -> producer -> req70 bit3
                  -> APP_lock_request_dispatch -> APP_lock_command -> 0x3A d3 -> DDM/PDM
```

**What remains open is exactly one thing: what sets `r6` in `APP_lock_src_producer`.** That is where
the RKE demux output must arrive. It is not yet established and is not assumed here.

### 10.4 Vindication of a refusal

`205` declined to extrapolate the latch's source→dest mapping because it measured **12 distinct
deltas**. `218` shows why that was right: the block interleaves **two** copy streams —
`r21`/`r28` → `r29` and `r23` → `r20`. Extrapolating from the first stream's delta would have named
a wrong source cell with total confidence.

### 10.5 What this changes

| Claim | Status |
|---|---|
| §9.2 "`0x40008D2C` has no writer" | **RETRACTED** — writer at `0x9749A` |
| §9.2 "this lock-request path is inert in this build" | **RETRACTED** — the path is live |
| §9's four measurements | each still correct; the *inference* was wrong |
| `rke-lock` mod | unaffected — it injects downstream of all of this |

The retraction is written into the Ghidra listing itself (`APP_lock_request_input`'s plate comment
opens with `*** RETRACTED CLAIM — READ THIS FIRST ***`) and asserted by `184`, so it cannot quietly
disappear.

### 10.6 The transferable lesson

**"No writer found" is only as strong as the analyser's coverage.** Before concluding a cell is never
written, call `getFunctionContaining()` on the neighbourhood of its *readers*: if that returns `None`,
the region is unswept, every reference-based method is blind there, and only p-code (or raw decode)
can see it. This is now golden rule 15 in `AGENTS.md`.

### 10.7 Artifacts

| Script | Purpose |
|---|---|
| `210_signed_disp_audit.py` | found + fixed the signed-displacement bug; re-measured (361 dropped stores) |
| `211_pcode_store_scan.py` | STORE-based p-code scan — **control failed**, correctly discarded |
| `212_pcode_shape_probe.py` | diagnosed the real op shape (`CALLOTHER` + ram varnode) |
| `213_pcode_ram_scan.py` | rebuilt scan; control passed (334 writes); surfaced the 4 unclassified ops |
| `214_writer_found.py` | (crashed silently — the `os._exit` trap) |
| `215_confirm_writer.py` | traceback-safe rewrite; showed `r29` unresolved and the block unswept |
| `216_resolve_r29.py` | extracted the address p-code had already resolved, ×4 hosts |
| `217_userop_control.py` | **the decisive control**: store/load userops are disjoint |
| `218_source_cells.py` | resolved all 16 source→dest pairs; closed link 5 |
| `219_source_writers.py` | found `APP_lock_src_producer` writing both source cells |
| `220_annotate_l33.py` | annotation + retraction into the listing |

`184_verify_l29.py` now spans layers 29–33: **ALL CHECKS PASSED**, 1,133 user-defined symbols,
`OwnerFlash-LOCKSRC` = 9 bookmarks. The two stale layer-32 caveat assertions were **removed**, since
asserting them would now be asserting a falsehood.

---

## 11. Layer 34 — the origin, and three scans with three different blind spots

Scripts `221`–`226`. **Result: the last unknown from §10 is resolved. The chain is LIVE end to end —
but two new, narrower unknowns replace it, and they are named rather than assumed away.**

### 11.1 Resolving `r6`

§10 left one question: what sets `r6` in `APP_lock_src_producer` before `0x97994`. The disassembly
gives the shape at once — `e_lbz r6,0xb(r15)` — so the producer is *itself* another copy stage.
Rather than chase one register, `221` resolved the **entire copy network** of `0x096000..0x098000` by
p-code in a single pass: **4,292 store edges**, control-checked against the two known edges from §10.

```
0x40008D6B --[0x97994]--> APP_lock_src_level 0x40008EF7
           --[0x9749A]--> APP_lock_request_input 0x40008D2C
```

### 11.2 The origin is real logic

`0x40008D6B` has **no copy edge** — it is produced by code. Three writers exist, and the one that
matters is not an initialiser:

```
000959ae  se_lwz r6,0x18(r3) ; se_li r0,0x1 ; e_rlwimi   <- state 1 path
000959b8  se_lwz r6,0x18(r3) ; se_li r0,0x2 ; e_rlwimi   <- state 2 path
000959c0  se_li r0,0x0
000959c2  se_stb r0,0x3(r7)                              <- stores the selection
```

`FUN_00095770` is a 658-byte state machine that *selects* the stored value. So the chain is **live**:

```
APP_lock_src_state_machine 0x95770 -> APP_lock_src_origin 0x40008D6B
  -> APP_lock_src_level 0x40008EF7 -> APP_lock_request_input 0x40008D2C
  -> edge detect -> req74 bit10 -> gate -> producer -> req70 bit3
  -> APP_lock_request_dispatch -> APP_lock_command -> MS 0x3A d3 -> DDM/PDM
```

### 11.3 The methodological core: three scans, three blind spots

Three independent full-image methods gave **three different answers** for "who writes `0x40008D6B`":

| Method | Answer | Blind spot |
|---|---|---|
| p-code `CALLOTHER` scan (13,588 funcs, controls passed) | **1** writer | `FUN_00095770` is 658 bytes but yields only **4** ram-resolved ops — the decompiler routes most accesses through a **pointer parameter**, so no `ram` varnode exists |
| raw signed base+disp sweep (352,906 insns) | **3** writers | right answer, **broken instrument** — its `r7` tracker leaked across a function boundary (see §11.4) |
| **Ghidra's reference manager** | **3** writers, correct | blind in *unswept* blocks — which is exactly where it failed in §10 |

In §10 the reference manager was blind and p-code was right. **Here it is precisely reversed.**
Neither method dominates. The rule is not "trust refs" or "distrust refs" — it is **reconcile them,
and treat a disagreement as the finding**. Had I stopped at the p-code scan (which had passing
controls and a full-image scope) I would have concluded "one writer, an initialiser, therefore the
cell is constant 0, therefore the path is dead" — **the exact layer-32 error, one level deeper.**

### 11.4 A right answer from a broken instrument

`224` was written to adjudicate the disagreement, and caught my sweep being *accidentally* right:
at `0x95758` the sweep reported `0x40008D6B` while a careful per-function re-derivation said
`0x40008DE7`. Ghidra's reference says `0x40008D6B` — the sweep's answer. But the sweep reached it by
carrying `r7 = 0x40008D68` across from `0x9570C` and never seeing `e_addi r7,r4,0x7c` at `0x9573E`.

Two lessons: **per-function scoping is mandatory** for register tracking, and **a correct output does
not validate a method** — the same leak that produced a right answer here would produce silent wrong
ones elsewhere.

### 11.5 What is still NOT established

Both are written into the listing as explicit caveats, not left implicit:

1. **How `APP_lock_src_state_machine` is scheduled.** It has **0 callers**, and its true entry
   (`0x95716`) has none either. It is presumably reached from the unswept region around `0x95716`.
   *Do not assume it runs every tick.*
2. **That this state machine is the RKE path specifically.** It is the origin of the *lock-request
   level*; whether its input is the RKE demux output, a door switch, or something else is **not yet
   traced**. The `(code & 0xF) == 1` decoders of §8 have still not been connected to it.

So: the mechanism from lock-request origin to DDM/PDM is fully resolved, but the claim
"RKE press → this chain" is **not** yet closed — §8 proved links 1–4 and §§10–11 prove links 5–9,
and the join between them is exactly unknown #2.

### 11.6 Artifacts

| Script | Purpose |
|---|---|
| `221_copy_network.py` | full copy network of `0x096000..0x098000` (4,292 edges) → `copy_network.json` |
| `222_d6b_writers.py` | scoped p-code writer scan (1 writer — incomplete, scope too narrow) |
| `223_full_image_d6b.py` | full-image p-code + raw sweep; **the two disagreed** |
| `224_method_disagreement.py` | adjudicated the disagreement; found the sweep's r7 leak |
| `225_chain_live.py` | classified the three writers; confirmed the chain live |
| `226_annotate_l34.py` | annotation (3 functions, 2 cells, 3 sites) |

`184_verify_l29.py` spans layers 29–34: **ALL CHECKS PASSED**, 1,138 user-defined symbols,
`OwnerFlash-LOCKPROD` = 8 bookmarks.

---

> **See also `docs/central_locking_chain.md`** — the consolidated statement of both lock paths.

## 12. Layer 35 — scheduling closed; and the RKE path is a *different* path

Scripts `227`–`236`. **Item 36 CLOSED. Item 37 answered in the negative — which is the substantive
result: the chain proven in §§10–11 is not the RKE path, and the real RKE join site is now located.**

### 12.1 Item 36 — the chain is periodic (another of my own bugs)

I wrote open item 36 on the basis of `225` reporting "`0x95770` true entry `0x95716`, callers=none".
That was **my script's bug**: it used `Function.getCallingFunctions()`, which enumerates *calling
functions* and therefore silently skips a call site that Ghidra never wrapped in a function. The
reference manager had the answer immediately:

```
1 references to 00095716
  from 00097540  UNCONDITIONAL_CALL  in -        <- "in -" = unswept block
```

Climbing with **JUMP + CALL + fallthrough** edges (CALL-only stalls at once) reaches the spine:

```
APP_feature_periodic 0x62848 --CALL--> 0x96B9C -> 0x96B9E -> 0x96BA2 -> 0x96BFC -> 0x96D2C
  -> 0x96D7E -> 0x96DF2 -> 0x96E5E -> 0x9718C -> 0x97250 -> 0x9732E -> 0x97346 -> 0x97362
  -> APP_lock_periodic_chain 0x97382 -> 0x95716 -> APP_lock_src_state_machine
```

One routine, split by the linear sweep into **15 zero-caller blocks**. So the lock-request chain
**is periodic** — and the same block that copies the latch also calls the state machine.

### 12.2 Item 37 — the RKE path does *not* flow through that chain

The state machine's input struct was derived by **control, not assumption**: `0x9576A` stores
`0x5(r7)` → `0x40008D6D` and `0x95764` sets `r7 = r4+0x7c`, therefore `r4 = 0x40008CEC`.

Two independent instruments then agreed, both with passing controls:

| Test | Result |
|---|---|
| blocks reading RKE cells ∩ blocks writing the SM input struct | **EMPTY** |
| blocks reading RKE cells ∩ blocks writing the lock source cells | **EMPTY** |
| flow-edge reachability from the demux (10 blocks, not 2) ∩ struct writers | **NONE** |
| control: 5/5 known latch-stage writer sites found | **PASS** |

⇒ **The RKE demux outputs and the layer-33/34 lock-request input live in disjoint code.** The chain
proven in §§10–11 is a *different* lock actuator (door switch / interior button / autolock), not the
fob path. This is exactly the caveat §11.5 refused to assume away — and it turned out to be the
correct call.

### 12.3 Where the RKE path actually joins

Of the 92 blocks that read RKE cells, **two are inside the lock module** — flagged back in layer 31
and never followed up. They are the join:

```
0008d52a  se_cmpi r7,0x0                  ; gate on 0x40008D3A
0008d532  se_bseti r0,0xf                 ; APP_req_word_74 value bit 16
0008d54a  e_lhz  r0,0x82(r5)              ; <-- APP_rke_command_code 0x40002DA2
0008d556  e_rlwinm r0,r0,0x0,0xd,0x10     ; mask req_word_74
0008d562  se_li  r7,0x3                   ; command 3
0008d56a  se_li  r7,0x1                   ; command 1
0008d56c  e_rlwimi r0,r7,0xb,0x12,0x14    ; -> APP_body_cmd_bus bits 11..13
```

The fob command code selects a **3-bit command enum** written into `APP_body_cmd_bus`
(`0x40008E58`) value bits 11..13 — an enum, not a bitmask (**rule 13** again, third time in this
project). Both writers (`0x88526`, `0x8D566`, plus an unswept `0x8D572`) are inside the lock module.

### 12.4 A broken decoder, reported as broken

`235`'s field scan claimed bits 11..13 are **"3 write, 0 read"**. That is *not* evidence the field is
unconsumed — it is **rule 8**: a write-only field is as suspect as a zero. The decoder ignored the
**rotate amount**, which is what distinguishes an `rlwinm` extract from an `rlwimi` insert, and it
emitted impossible ranges like "bits 17..13" and "bits 24..13". The warning is written into
`APP_body_cmd_bus`'s plate comment so the number is not later quoted as a finding.

### 12.5 State of the two questions

| Item | Status |
|---|---|
| 36 — is the lock-request chain scheduled? | **CLOSED** — periodic, via `APP_feature_periodic` |
| 37 — is it the RKE path? | **ANSWERED: NO** — disjoint code, two agreeing instruments |
| 37b — where does RKE join? | **PROVEN** — `APP_rke_to_body_cmd` `0x8D522`, bits 11..13 of the body bus |
| 37c — from that field to `APP_lock_command`? | **OPEN** — needs a correct rlwinm decoder first |

So the honest summary of the whole RKE question: **RFA → MS `0x100` → 13-bit code → demux → command
enum on the body bus → [one unresolved hop] → lock module → `0x3A` d3 → DDM/PDM.** Every arrow but
one is now proven, and the previously-claimed middle section turned out to belong to a different
feature entirely.

### 12.6 Artifacts

| Script | Purpose |
|---|---|
| `227_sched_by_ref.py` | found the `getCallingFunctions()` bug; callers by reference |
| `228_climb_to_spine.py` | fallthrough climb; **proved the literal-pointer scan uninformative** (control produced 0 too) |
| `229_climb_allflow.py` | JUMP+CALL+fallthrough climb → **reached `APP_feature_periodic`** |
| `230_rke_join_test.py` | p-code join test — null, with its pointer-parameter limit stated |
| `231_sm_input_struct.py` | derived the SM input struct `0x40008CEC` by control |
| `232_struct_rke_join.py` | reference-manager writers of the struct; control 5/5 |
| `233_join_by_refs.py` | refs + flow reachability — both agree: **no join** there |
| `234_rke_lock_join_site.py` | found `0x8D522` / `0x88504` — the real join |
| `235_bus_field_decode.py` | decoded bits 11..13; **decoder found unreliable and reported as such** |
| `236_annotate_l35.py` | annotation (3 functions, 2 cells, 3 sites) |

`184_verify_l29.py` spans layers 29–35: **ALL CHECKS PASSED**, 1,143 user-defined symbols,
`OwnerFlash-RKEJOIN` = 8 bookmarks.
