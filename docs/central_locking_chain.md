# The central-locking chain — consolidated findings (layers 29–35)

**Scope.** Everything established about how a lock command is produced inside this BCM, from the
key-fob radio frame to the CAN frame that drives the door modules. Written as a standing reference:
the per-layer derivations live in `tx_pack_stage.md` §§7–12 and `owner_flash_layers.md` §§39–45; this
file is the *current state of belief*, including what is **not** known.

Image: `backups/owner-backup-20260911T090300Z/cflash.bin` (owner full flash, `JV6T-14C094-AD`).
Ghidra project: `ghidra_proj_fullflash` / `BCM_OwnerFlash`, **1,161 user-defined symbols**.

> 📊 **Visual call-chain diagram:** [`rke_chain_diagram.html`](rke_chain_diagram.html) — both paths,
> colour-coded by evidence status (proven / bench-confirmed / open / refuted), clickable nodes
> carrying the derivation and the caveat for each hop. Open it in a browser.

> **Confidence levels** used throughout:
> **(a)** proven — multiple independent methods agree, controls passed;
> **(b)** strong — one controlled method, no contradicting evidence;
> **(c)** plausible — consistent with evidence, not independently confirmed;
> **(open)** — explicitly not established.

---

## 1. The headline

There are **two separate lock-request paths**, and for most of this investigation they were
mistaken for one:

| | Path A — the periodic lock chain | Path B — the RKE path |
|---|---|---|
| Origin | `APP_lock_src_state_machine` `0x95770` | `APP_rke_command_code` `0x40002DA2` (from MS `0x100`) |
| Entry to lock module | `APP_lock_request_input` `0x40008D2C` | `APP_rke_to_body_cmd` `0x8D522` |
| Mechanism | level → edge detector → `req_word_74` bit 10 | 3-bit command **enum** → `APP_body_cmd_bus` bits 11..13 |
| Scheduled? | **yes**, via `APP_feature_periodic` (a) | **open** — climb stalled at `0x93890`/`0x8F8F2` |
| Which feature? | ~~**open** — *not* RKE (a)~~ **RKE-DRIVEN (a)** — see below | RKE (a) |

> ⚠ **"Path A is *not* RKE" is REFUTED on the bench** (`docs/bench_session_3.md` §4). An RKE lock or
> unlock press raises `APP_lock_request_input` (11 rises over 48 s of presses), while a **bus-matched
> idle window** — the RFA idle stream running, module equally awake, no command bits set — produces
> **0 rises in 24 s**. The static "disjoint in code" result (`233`) still stands as far as it goes;
> what it cannot see is that the two paths meet at runtime. Note also that the *identity* of the
> feature owning Path A remains open: RKE drives it, but so may other inputs.
>
> Ordering is **not** resolved: `APP_lock_request_input` moves **simultaneously with
> `APP_lock_command → 02`** (the triplet's third member) to ±10 ms at two cadences — below this
> instrument's resolution. An earlier "lock_command leads by 510 ms" reading was a pairing artifact
> and is withdrawn (session 3 §5).

They are **disjoint in code** (a): no block that reads an RKE cell writes into Path A's input struct
or source cells, confirmed by two agreeing instruments with passing controls (`233`).

> ⚠ **That is a claim about CODE, and it does not survive promotion to behaviour.** On the bench an
> RKE press drives Path A (§1 note above, `bench_session_3.md` §4). Both results are correct
> measurements of different things: the two paths do not touch *in the code the analyser swept*, and
> they still meet at runtime. The join is therefore either through RAM that `233` did not model, or
> in code Ghidra never swept into a function — and the latter is not hypothetical here: `0x9749A`
> and `0x97474` (§2) are both in unswept blocks invisible to every reference-based method.
> AGENTS.md rule 43.

---

## 2. Path A — the periodic lock chain (fully traced)

```
APP_lock_src_state_machine 0x95770          (658-byte state machine, selects a value)
  └ 0x959C2  se_stb r0,0x3(r7)      ──▶ APP_lock_src_origin      0x40008D6B
  └ 0x97994  e_stb  r6,0xf(r21)     ──▶ APP_lock_src_level       0x40008EF7
  └ 0x97974  e_stb  r6,0xc(r21)     ──▶ APP_lock_src_unk_EF4     0x40008EF4   [p-code only]
  └ 0x9749A  se_stb r0,0xc(r29)     ──▶ APP_lock_request_input   0x40008D2C   [unswept block]
  └ APP_lock_req_edge_detect_A/B  0x86F90 / 0x8A812
        if (b==1 && !(req74 & bit9))  req74 |= bit10;    // rising edge
        if (b==0 &&  (req74 & bit9))  req74 &= ~bit10;   // falling edge
        req74 = (b&1)<<9 | (req74 & ~bit9);              // bit9 = level memory
  └ APP_lock_req_gate_A/B  0x894D2 / 0x897B2   ──fallthrough──▶
  └ APP_lock_req_producer_A/B  0x894FE / 0x897DE
        req70 |= bit3;  APP_lock_command = 6;  dirty = 0xFF
  └ APP_lock_request_dispatch  0x87A0E
  └ APP_lock_command  0x40002E70  ──▶ TX pack ──▶ MS-CAN 0x3A d3 ──▶ DDM / PDM
```

**Scheduling (a).** One routine split by the linear sweep into 15 zero-caller blocks:

```
APP_feature_periodic 0x62848 --CALL--> APP_lock_chain_01 0x96B9C -> ... -> APP_lock_chain_13 0x97362
  -> APP_lock_periodic_chain 0x97382 -> APP_lock_src_sm_entry 0x95716 -> the state machine
```

**Key structures.**

| Symbol | Address | Role |
|---|---|---|
| `APP_lock_sm_input_struct` | `0x40008CEC` | SM base struct (derived by control, §4.2) |
| `APP_lock_src_origin` / `_2` | `0x40008D6B` / `6C` | SM output |
| `APP_lock_src_level` / `_2` | `0x40008EF7` / `F8` | copied by `APP_lock_src_producer` `0x978D2` |
| `APP_lock_src_unk_EF4` | `0x40008EF4` | **sibling byte of `_src_level`**, same producer, same base `r21` (+0xC vs +0xF). Bench-confirmed press-responsive; **meaning open**. Found only by p-code — invisible to the reference manager *and* to a verified struct-field scan (`bench_session_3.md` §8.1) |
| `APP_lock_request_input` / `_2` | `0x40008D2C` / `2D` | edge detector input |
| `APP_req_word_74` | `0x40008E74` | bit 9 = level memory, **bit 10 = edge event** |
| `APP_req_word_70` | `0x40008E70` | **bit 3 = lock request** |
| `APP_lock_command` | `0x40002E70` | `0x01` LOCK / `0x02` UNLOCK → `0x3A` d3 |

**Which feature owns Path A is open.** Candidates: door-switch lock, interior lock button,
autolock-on-drive-away. ~~It is *not* RKE (a).~~ **An RKE press demonstrably drives it** — see the
§1 note and `bench_session_3.md` §4 (11 rises under presses vs 0 in a bus-matched idle window).
Whether RKE is the *only* driver remains open.

---

## 3. Path B — the RKE path

```
RFA (radio receiver)  ──▶ MS-CAN 0x100 d6:d7
  └ VOL_sig_get16, descriptor 0x142FD4 (anchored on d6, mask 0x1F)
  └ APP_rke_command_code  0x40002DA2        (13-bit command code + valid flag 0x40003F53)
  └ APP_rke_command_demux 0x992B2           (code & 0xF) → one-hot bits
        └ APP_rke_cmd_bits_34 / _38   0x40009034 / 0x40009038
  └ APP_rke_to_body_cmd 0x8D522   (and sibling APP_rke_to_body_cmd_b 0x88504)
        0008d54a  e_lhz  r0,0x82(r5)              ; APP_rke_command_code
        0008d562  se_li  r7,0x3                   ; command 3
        0008d56a  se_li  r7,0x1                   ; command 1
        0008d56c  e_rlwimi r0,r7,0xb,0x12,0x14    ; → APP_body_cmd_bus bits 11..13
  └ APP_body_cmd_bus 0x40008E58, value bits 11..13 = 3-bit command enum
  │     └ sole reader 0x8D500 -> APP_body_cmd_timed_feature 0x8D4DA
  │           = a TIMED body feature, NOT the lock actuator  (layer 36, a)
  └ APP_req_word_74 0x40008E74 bits 15..20  <-- the real handoff  (layer 36, a)
  └ ??? one of 9 consumer sites ───────────── UNRESOLVED (open item 41)
  └ lock module ──▶ APP_lock_command ──▶ MS 0x3A d3 ──▶ DDM / PDM
```

⚠ **Layer 36 relocated this hop.** The chain above used to route through
`APP_body_cmd_bus` bits 11..13; that is refuted. See `docs/rke_lock_join.md`:
the field's sole reader emits nothing reaching `APP_lock_command`, and at bit
resolution the RKE chain and the 32 lock-command writers share **no bits**.
The 9 consumers of `req_word_74` bits 15..20 are enumerated there — but
control-flow reachability is **saturated** in this code region, so picking the
right one needs a measurement, not another scan.

Gate byte `APP_rke_join_gate` `0x40008D3A` selects which arm runs; **its meaning is open**.

**The single remaining hop** is blocked on a tooling defect, not on missing evidence — see §5.

---

## 4. Method notes that changed conclusions

These are the reason the chain above reads the way it does. Each is now an `AGENTS.md` golden rule.

### 4.1 Four methods can agree and still be wrong (rule 14)

Layer 32 concluded `0x40008D2C` had **no writer** and the path was **inert**, from four
independently-controlled negatives. The writer was `se_stb r0,0xc(r29)` at `0x9749A`, in an
**unswept block** — `getFunctionContaining()` returns `None`, so Ghidra created no references and
every reference-based method was structurally blind. **Retracted in layer 33.**

### 4.2 Derive by control, not by extrapolation (rules 16–17)

The SM's base struct was pinned by a *control*: `0x9576A` stores `0x5(r7)` → `0x40008D6D` and
`0x95764` sets `r7 = r4+0x7c`, therefore `r4 = 0x40008CEC`. Earlier, `205` **refused** to extrapolate
the latch mapping because it measured 12 distinct deltas — later vindicated when `218` showed the
block interleaves **two** copy streams. Extrapolation would have named the wrong cell confidently.

### 4.3 Three scans, three blind spots (rule 17)

For "who writes `0x40008D6B`":

| Method | Answer | Blind spot |
|---|---|---|
| p-code `CALLOTHER` (full image, controls passed) | 1 | accesses through a **pointer parameter** yield no `ram` varnode |
| raw signed base+disp sweep | 3 | right answer, **broken instrument** (register leaked across a function boundary) |
| Ghidra reference manager | 3, correct | blind in unswept blocks |

In layer 33 the reference manager was blind and p-code right; in layer 34 **exactly reversed**.
Neither dominates — reconcile, and treat disagreement as the finding.

### 4.4 Representation ≠ wire format (rule 13, seen three times)

The fob command is decoded from captures as *bit flags* but consumed in code as a **command enum**
(`(code & 0xF) == 1`; the body-bus field is likewise a 3-bit enum). A classifier looking for a
`0x01`/`0x02` bitmask reported "no button decode exists" while the decoders sat in plain sight.

### 4.5 Instruments that lie quietly (rules 14, 15, 20, 21)

- `os._exit(0)` in a `finally` block **kills the traceback** — a crashing script exits 0, silently.
- `int(d,16) if d.startswith("0x") else int(d)` raises on `-0xbc`; a bare `except` dropped **361**
  stores, and the target sat at `-0xBC` from the base.
- `getCallingFunctions()` skips call sites in unswept blocks — it produced a false "0 callers" that
  became a documented open item.
- A literal-pointer scan is **uninformative** in this image: the control (`APP_main`,
  `APP_feature_periodic`) finds zero pointers too, because addresses are synthesised.

---

## 5. What is NOT established

| # | Question | Status |
|---|---|---|
| 38 | ~~`APP_body_cmd_bus` bits 11..13 → `APP_lock_command`: the last RKE hop~~ | **CLOSED IN LAYER 36 — BY REFUTATION.** The fixed decoder shows the field has 4 writes and **1 read** (not "0 read"), and its sole reader `FUN_0008D4DA` `0x8D4DA` is a *timed* body feature that writes nothing reaching the lock command. At bit resolution the RKE chain and all 32 lock-command writers share **no bits at all**. The real handoff is **`APP_req_word_74` bits 15..20**. See `docs/rke_lock_join.md` |
| 41 | **Which of the 9 `req_word_74` bit-15..20 consumers actuates the lock** | **open — and not answerable statically.** Control-flow reachability is *saturated* in this region: unrelated control sites (RX copier, acc-fix hook sites, DID readers) reach the same lock writes. Two candidate answers were generated and both destroyed by their own controls (`rke_lock_join.md` §5). Needs a bench/vehicle measurement |
| 42 | What `FUN_0008D4DA` actuates | open (c) — timed, duration `DAT_4000588F × 50`; writes `0x40002E44`, which packs into HS `0x380` d4 and MS `0x1A8`/`0x1B0`/`0x290`/`0x370` |
| 39 | Which feature owns Path A | **partly answered** — RKE *drives* it (bench, `bench_session_3.md` §4: 11 rises under presses vs 0 in a bus-matched idle window), which refutes the old "not RKE (a)". Whether RKE is the *only* driver, and which feature *owns* the state machine, remain open. Start from `APP_lock_sm_input_struct` `0x40008CEC` (132 writer blocks) |
| 40 | Scheduling of `APP_rke_to_body_cmd` | open — flow-edge climb stalled at `0x93890` / `0x8F8F2` without reaching a spine symbol |
| — | Meaning of `APP_rke_join_gate` `0x40008D3A` | open — only its *role* as an arm selector is known |
| — | Ignition interaction | **untouched by layers 29–36.** The refusal mechanism remains as layer 30 left it: `APP_lock_request_dispatch` is the only function that both tests `APP_power_mode` and writes `APP_lock_command`, but no branch was observed suppressing a command |

---

## 6. Bearing on the shipped mods

**None of this changes `rke-lock` or `acc-fix`.** Both inject at the FlexCAN TX mailbox, downstream
of every mechanism described here, so they are indifferent to which request bit or command enum is
live. The two absences that make them safe still hold (layer 29): HS `0x030` d5 and MS `0x3A` d1
bit 6 have **no pack setter anywhere in the image**, while the scan resolves 7/8 bytes of that frame.

What *would* change if open item 38 closes: a smaller, more surgical RKE modification becomes
possible — editing the command enum at `0x8D522` rather than injecting a frame at the mailbox.
That is a strictly better mod if and only if the ignition gate (§5, last row) is also located.

---

## 7. Bookmark categories in the Ghidra project

| Category | Count | Layer |
|---|---|---|
| `OwnerFlash-TXPACK` | 16 | 29 — TX pack stage |
| `OwnerFlash-REQBUS` | 9 | 30 — request bus |
| `OwnerFlash-RKE` | 7 | 31 — RKE receive chain |
| `OwnerFlash-LOCKREQ` | 7 | 32 — lock request (contains the retracted claim) |
| `OwnerFlash-LOCKSRC` | 9 | 33 — the found writer |
| `OwnerFlash-LOCKPROD` | 8 | 34 — the origin |
| `OwnerFlash-RKEJOIN` | 8 | 35 — RKE join site |
| `OwnerFlash-RKEJOIN2` | 7 | **36 — item 38 refuted; the hop relocated** |
| `OwnerFlash-LOCKCHAIN` | 28 | consolidation — the 15-block periodic chain |

Read-back verifier: `work/owner/184_verify_l29.py` — spans layers 29–35, asserts every symbol,
every caveat string, and every bookmark count.

---

## 8. Reproducing

```bash
cd BCM/Research && . .venv/bin/activate
python3 work/owner/221_copy_network.py       # copy network (4,292 edges)
python3 work/owner/229_climb_allflow.py      # scheduling proof
python3 work/owner/233_join_by_refs.py       # Path A ≠ Path B
python3 work/owner/234_rke_lock_join_site.py # the RKE join
python3 work/owner/237_consolidation_audit.py # docs ↔ Ghidra sync check
python3 work/owner/184_verify_l29.py         # full read-back (layers 29–35)
python3 work/owner/256_flow_saturation_and_path.py # layer 36 adjudicator
python3 work/owner/258_verify_l36.py         # layer 36 read-back
```
