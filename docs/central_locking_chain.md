# The central-locking chain — consolidated findings (layers 29–35)

**Scope.** Everything established about how a lock command is produced inside this BCM, from the
key-fob radio frame to the CAN frame that drives the door modules. Written as a standing reference:
the per-layer derivations live in `tx_pack_stage.md` §§7–12 and `owner_flash_layers.md` §§39–45; this
file is the *current state of belief*, including what is **not** known.

Image: `backups/owner-backup-20260911T090300Z/cflash.bin` (owner full flash, `JV6T-14C094-AD`).
Ghidra project: `ghidra_proj_fullflash` / `BCM_OwnerFlash`, **1,161 user-defined symbols**.

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
| Which feature? | **open** — *not* RKE (a) | RKE (a) |

They are **disjoint in code** (a): no block that reads an RKE cell writes into Path A's input struct
or source cells, confirmed by two agreeing instruments with passing controls (`233`).

---

## 2. Path A — the periodic lock chain (fully traced)

```
APP_lock_src_state_machine 0x95770          (658-byte state machine, selects a value)
  └ 0x959C2  se_stb r0,0x3(r7)      ──▶ APP_lock_src_origin      0x40008D6B
  └ 0x97994  e_stb  r6,0xf(r21)     ──▶ APP_lock_src_level       0x40008EF7
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
| `APP_lock_request_input` / `_2` | `0x40008D2C` / `2D` | edge detector input |
| `APP_req_word_74` | `0x40008E74` | bit 9 = level memory, **bit 10 = edge event** |
| `APP_req_word_70` | `0x40008E70` | **bit 3 = lock request** |
| `APP_lock_command` | `0x40002E70` | `0x01` LOCK / `0x02` UNLOCK → `0x3A` d3 |

**Which feature owns Path A is open.** Candidates: door-switch lock, interior lock button,
autolock-on-drive-away. It is *not* RKE (a).

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
  └ ??? ────────────────────────────── ONE UNRESOLVED HOP (open item 38)
  └ lock module ──▶ APP_lock_command ──▶ MS 0x3A d3 ──▶ DDM / PDM
```

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
| 38 | `APP_body_cmd_bus` bits 11..13 → `APP_lock_command`: the last RKE hop | **blocked on a broken decoder** — `235` ignored the *rotate amount*, producing impossible ranges ("bits 17..13") and a "3 write, **0 read**" verdict. Per rule 8 that is a decoder bug, not evidence the field is unread. Fix: `value = (x >> (32-sh)) & mask(mb,me)` |
| 39 | Which feature owns Path A | open — start from `APP_lock_sm_input_struct` `0x40008CEC` (132 writer blocks) |
| 40 | Scheduling of `APP_rke_to_body_cmd` | open — flow-edge climb stalled at `0x93890` / `0x8F8F2` without reaching a spine symbol |
| — | Meaning of `APP_rke_join_gate` `0x40008D3A` | open — only its *role* as an arm selector is known |
| — | Ignition interaction | **untouched by layers 29–35.** The refusal mechanism remains as layer 30 left it: `APP_lock_request_dispatch` is the only function that both tests `APP_power_mode` and writes `APP_lock_command`, but no branch was observed suppressing a command |

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
python3 work/owner/184_verify_l29.py         # full read-back
```
