# Bench session 3 — the peek service turned on the RKE chain

**Status:** the `peek` UDS service (docs/peek_tool.md) used for its intended purpose for the first
time. Two documented claims did not survive; one of **this session's own** conclusions did not
survive either, and the way it died is the most useful thing here.

Hardware: bench #1, `JV6T-14C094-AD`, serial `009640039386`, peek-service build.
`can0` = HS-CAN (UDS), `can1` = MS-CAN (RFA simulator + `0x3A` observer).

> **Confidence:** **(a)** proven — multiple independent methods, controls passed;
> **(b)** strong — one controlled method; **(c)** plausible; **(open)** — not established.

---

## 1. Headline

| Claim | Status after session 3 |
|---|---|
| `bench_session_2.md` §4.1: the bench's `req_word_74` `0x600` = "word bits 17 and 18", reviving layer 36's bit-17 lead | **WITHDRAWN (a)** — `0x600` is LSB bits **9\|10**, i.e. Path A's edge detector. Proven from literal instruction constants, §3 |
| `central_locking_chain.md` §1: "Path A ... is **not** RKE (a)" | **REFUTED (a)** — an RKE press raises Path A's input; a bus-matched idle window produces **zero**, §4 |
| *This session's own* "Path A is downstream, `lock_command` leads by 510 ms" | **WITHDRAWN (a)** — pairing artifact against the wrong burst member. Correct answer: **simultaneous to ±10 ms**, §5 |
| Which consumer actuates the lock (item 41) | **still open** — §7 |
| A new cell on Path A: `0x40008EF4` | **found (a)** — invisible to both reference-based methods, resolved by p-code; sibling byte of `APP_lock_src_level`, §8.1 |

---

## 2. The instrument (`work/bench/peeklib.py`)

`peek_read.py` sends a `3E 80` and spends ~120 ms in sleeps/drains per request, capping it near
**8 Hz** — fine for `accept`, useless for a ~40 ms pulse. `peeklib.Peeker` moves the keepalive to a
background thread and reuses one `AF_CAN` socket: **100 Hz** aggregate, measured.

Every run begins with three controls, and no reading is believed until they pass:

| control | what it kills |
|---|---|
| known-truth vs the owner backup at `0x000DE278` | wrong unit / wrong firmware / broken decode |
| out-of-range `0xFFFFFFFF` → `EE EE EE EE` | the range check silently not firing |
| **self-referential** `peek 0x4000A9E5 → 4000A9E5` | a frozen snapshot or an address-ignoring decode |

Responses are matched on the `62 DE AD` DID echo, so a stale multi-frame reply cannot be read as the
answer to the current question (`peek_tool.md` §4.2).

---

## 3. 🔑 The bit-numbering correction (a) — `work/owner/277_bitnum_adjudicate.py`

Session 2 §4.1 saw `APP_req_word_74` go `0x02100000 → 0x02100600` under a press, read the novel mask
`0x600` as "word bits 17 and 18", and on that basis put layer 36's withdrawn `0x8B3D6` (bit 17) lead
back in play. **Two documents in this repo describe bits of this one word in two different
conventions**, and the interpretation of `0x600` flips between them:

| source | convention | `0x600` means |
|---|---|---|
| `central_locking_chain.md` §2 (from the decompiler) | LSB-numbered | bits 9, 10 |
| `rke_lock_join.md` §4 (from an `mb`/`me` decode) | MSB-numbered | bits 21, 22 |

Settled without appealing to either convention, by reading the **literal constants**:

```c
APP_lock_req_edge_detect_A  0x86F90      // and _B at 0x8A812
  if (b==1 && (req74 >> 9 & 1)==0)  req74 = req74 | 0x400;        // rising edge
  if (b==0 && (req74 >> 9 & 1)!=0)  req74 = req74 & 0xfffffbff;   // falling edge
  req74 = (b & 1) << 9 | req74 & 0xfffffdff;                      // bit9 = level memory
```

`0x200 | 0x400 = 0x600` **exactly**. The RKE writer sites, decoded wrap-aware from `sh`/`mb`/`me`:

| site | instruction | LSB mask |
|---|---|---|
| `0x8D556` | `e_rlwinm r0,r0,0x0,0xd,0x10` | `0x00078000` |
| `0x8B3EE` | `e_rlwimi r7,r0,0xe,0xf,0x11` | `0x0001C000` |

= LSB bits 14..18, layer 36's "bits 15..20" in MSB numbering. **These do not intersect `0x600`.**

⇒ The cell session 2 watched move is **Path A's edge detector, not the RKE handoff field**. Layer
36's bit-level negative is *not* refuted by that observation, and the bit-17 lead stays withdrawn.

Decoder control (rke_lock_join.md §2's C2 pair, a complementary insert/extract on one field):
`0x874A6` → `0x000E0000`, `0x87496` → `0x00000007` — the same 3-bit field, one in place, one
extracted. Passes.

---

## 4. ✅ Path A **is** RKE-driven — `work/bench/278_patha_rke_test.py` (a)

`central_locking_chain.md` §1 states Path A and Path B are disjoint and Path A is "*not* RKE (a)".
The differential scan (§6) showed `APP_lock_request_input` rising on every press, so that was tested
directly, with predictions stated first and conditions **randomised**:

| condition | duration | `lock_request_input` rises | `req74` bits 9\|10 | `lock_command` edges |
|---|---|---|---|---|
| lock presses | 24.0 s | **6** | 56 | 8 |
| unlock presses | 24.0 s | **5** | 31 | 0 |
| **idle stream only** | 23.9 s | **0** | **0** | **0** |

The idle condition is the whole test: the RFA idle stream runs, so the bus is **equally busy and the
module equally awake**, but no command bits are ever set. Without it, "it moved while I pressed" is
exactly the saturated reasoning of rule 23. **11 rises under command, 0 in 24 s of matched idle.**

⇒ An RKE command raises Path A's input. The "Path A is not RKE" claim does not survive.

> Note what this does *not* say: it does not say the RKE chain reaches the lock via Path A, nor that
> Path A's input is *caused* by the command rather than by a shared parent. §5 attacks that and
> fails to resolve it.

---

## 5. ⚠ The session's own wrong answer, and why the standard falsifier missed it

`279_order_gapsweep.py` asked whether Path A is upstream or downstream of `APP_lock_command`. First
version paired `lock_request_input` rises against `lock_command → 01`, ran at two inter-press gaps
per rule 26, and reported:

```
gap 1.20 s -> mean offset -0.479 s
gap 0.70 s -> mean offset -0.517 s     drift 39 ms, floor 23 ms
=> H_DOWN SURVIVES: lock_command precedes the input
```

**The gap sweep passed and the conclusion was still wrong.** `-0.510` is the spacing of the
**LOCK, LOCK (+0.51 s), UNLOCK (+0.52 s) triplet** of `bench_session_1.md` §5.3 — and a burst's
*internal* spacing is invariant to the inter-press gap, so varying `--gap` cannot falsify a pairing
to the wrong **member** of the burst. Paired against every destination value instead:

| gap | vs `→ 01` | vs `→ 02` |
|---|---|---|
| 1.20 s | n=6, mean **−0.463 s**, spread 0.320 | n=8, mean **+0.005 s**, spread 0.020 |
| 0.70 s | n=6, mean **−0.513 s**, spread 0.020 | n=7, mean **+0.004 s**, spread 0.020 |

15 of 15 pairs land within **±10 ms** — one round-robin poll period — at both cadences, drift 1 ms.

⇒ `APP_lock_request_input` rises **simultaneously with `lock_command → 02`**, the third member of
the triplet, at the limit of this instrument. **They are one event; no ordering is claimable**, and
the 510 ms "lag" was the triplet's own shape.

> **New rule (AGENTS.md 41).** When the stimulus produces a multi-event burst, pair against **every**
> destination value and report which one wins. A stable offset to the wrong partner is
> indistinguishable from a lag, and the gap sweep — the standard rule-26 falsifier — **cannot detect
> it**, because the burst's internal spacing does not move with the cadence.

This is the third time in this project that a clean, cadence-checked offset turned out to be a
pairing artifact (`bench_session_2.md` §6.1, §6.2, and now here).

---

## 6. The differential RAM scan — `work/bench/275_ram_diff_scan.py`

The peek service removes the constraint that made the 17-cell probe bank hard: addresses no longer
have to be chosen before a flash. So instead of guessing which cells matter, sweep **1,216 words**
(`0x40008C00..0x40009100` = the body-control struct, `0x40002D00..0x40002F00` = RKE + lock command)
in three phases — quiet, stimulus, quiet again.

Q2 exists because session 2 §8.1's null control ran *first*, for 10 s, and was structurally blind to
a mechanism armed by a press that then free-runs.

Candidates (constant across all 10 quiet passes; novel value in ≥2 of 12 stimulus passes):

| address | name | quiet | under stimulus | passes |
|---|---|---|---|---|
| `0x40002E6C` | — | `0x00030000` | `0x1F000000` | 12/12 |
| `0x40008D68` | — | `0x0` | `0x1` | 10/12 |
| `0x40008D2C` | `APP_lock_request_input` | `0x0` | `0x01000000` | 9/12 |
| `0x40008E74` | `APP_req_word_74` | `0x02100000` | `0x02100600` | 9/12 |
| `0x40008EF4` | — | `0x01000100` | `0x01000101` | 8/12 |
| `0x40009034` | `APP_rke_cmd_bits_34` | `0x41976800` | `0x4D576800` | 4/12 |
| `0x40002E70` | `APP_lock_command` | `0x02001F00` | `0x01001F00` | 2/12 |

Session 2's two live observations (`req_word_74` b2 → `0x06`, `lock_request_input` → `01`) reproduce
independently here, on a different instrument.

### 6.1 ⚠ The scan's first run failed its own positive control — and that was the useful part

Run 1 (6 stimulus passes) reported **28 stimulus-driven cells** and `C1 FAIL` on
`APP_lock_command`. The stimulus log showed 17 strobes with `d3` taking `01` and `02`, so the
presses had plainly fired. Two defects, both fixed:

- **Under-powered sampling.** Each cell is read **once per pass** (~5 s apart). A high-rate watch
  measured `APP_lock_command`'s duty at **38%**, so 6 passes miss it ~6% of the time — and did. The
  script now computes **empirical detection power from the positive control itself** and prints it,
  so a null is explicitly a claim only about cells of comparable duty.
- **11 of the 28 "hits" were free-running cells** — a cell that wanders on its own always shows some
  value "not seen in quiet". That is coverage, not agreement (rule 9). Candidates now require
  **constant in every quiet pass** *and* a novel value **recurring** across stimulus passes.

Free-running cells are reported separately and never as a result; errored reads are excluded rather
than folded into the value sets, where a transport hiccup would have masqueraded as a change.

---

## 7. What is NOT established

| # | Question | Status |
|---|---|---|
| 41 | Which consumer performs the lock actuation | **still open.** §4 puts Path A on the RKE stimulus, but §5 cannot order it against the command, and nothing here names an actuating consumer |
| — | Is Path A's input a *cause* or an *effect* of `lock_command → 02` | **open, narrowed.** §9 improves resolution 23 → 11 ms and confirms the partner is `d3→02` at both cadences, but the offset's value and sign are not established (uncalibrated channel skew, and that script's own wire-only control fails in 3 of 4 conditions) |
| — | Why `lock_command → 02` (the triplet's UNLOCK) and not `→ 01` | **open**, and now the most concrete question in the chain |
| — | `0x40002E6C`, `0x40008D68` | **traced — neither is on the lock path**, see §8 |
| — | `0x40008EF4` | **traced — IS on Path A** (sibling byte of `APP_lock_src_level`, written by `APP_lock_src_producer`); its *meaning* is open, §8.1 |
| 43 | Meaning of the RKE bits (LSB 14..18) | open — untouched by this session |
| 30 | Ignition gate | untouched |

**The ±10 ms floor is the binding constraint.** Ordering two cells inside one round-robin period
needs either a single-cell watch triggered on the other's transition, or a patched probe that
records a timestamp itself.

---

## 8. The three unnamed cells, traced — a useful negative (`work/owner/280_unnamed_cells.py`)

The scan's top candidates fire *more* reliably under an RKE press than `APP_lock_command` does, so
they were the obvious next lead. **None of them is on the lock-actuation path**, and saying so
narrows item 41 rather than leaving three phantom leads open.

| cell | accessors | what it is |
|---|---|---|
| `0x40002E6C` | 45 refs, all in `FUN_00084148` / `FUN_000842B0` | an **up/down counter pair**: incremented on code `0x19`, decremented on `0x1A`, clamped at 20 and 12/18, mirrored into `DAT_40001A02/03/04`. A user-adjustable setting, not a command |
| `0x40008D68` | 21 refs in `FUN_00095C66` / `_FC2` / `_FFC` | a **command-enum dispatcher with timers** (`… * 0x32`, `… * 0x28` — the same counter-vs-limit idiom as `0x8D4DA`), writing switch/lamp bits `DAT_40003B83`, `DAT_40003B95`, `APP_switch_bits_3B93` |
| `0x40008EF4` | 2 sites, **p-code only** (`0x97474` load / `0x97974` store) | **`APP_lock_src_producer`'s sibling byte of `APP_lock_src_level`** — it *is* on Path A. See §8.1 |

That all three are RKE-*responsive* is expected: one fob press starts many body features (lamps,
timers, switch states) in parallel with the lock command. Two of the three are unrelated to locking.
**The third is not** — see §8.1.

### 8.1 🔑 `0x40008EF4` IS on the lock chain — found only by p-code (`281`, `282`)

The §8 table first recorded this cell as "none found by any method", with an explicit warning that
this is what an **unswept block** looks like and must not be read as "unwritten" (rule 14). Running
the method that does not depend on references at all vindicated that caution.

`281_ef4_pcode.py` swept all 13,588 functions with the decompiler, matching **`CALLOTHER` userops**
(`0x10000002` store / `0x10000001` load — this language does not model memory access as `STORE`
ops, so a `STORE`-only walk finds nothing). Controls both pass: C1 rediscovers the notorious
`0x40008D2C` writer that defeated four reference-based negatives (31 hits), C2 finds 827 accessors
of `APP_req_word_74`. Blindness reported honestly: **2,050 of 13,588 functions yielded no
address-resolved memory op** (accesses through pointer parameters), which is exactly why p-code
complements rather than dominates the reference manager.

**Target: 2 sites, both invisible to the reference manager and to the struct-field scan.**

`282_ef4_instructions.py` then settled what they are at the encoding level, because two readings
were possible and only one is a new cell:

```
0x97474  e_lbz r0,0xc(r21)     <- LOAD    [unswept block, no function]
0x97974  e_stb r6,0xc(r21)     <- STORE   [APP_lock_src_producer]   34 D5 00 0C
0x97994  e_stb r6,0xf(r21)     <- APP_lock_src_level 0x40008EF7     34 D5 00 0F
```

Both target accesses are **byte** ops, not word ops — so this is a distinct cell, not a wide access
spanning into `_src_level` (the alternative hypothesis, which the bench's *low-byte* change
`0x01000100 → 0x01000101` made genuinely plausible). The raw encodings confirm the mnemonics
independently: `0x34` = `e_stb`, identical register field `D5` (r6, base r21), displacements
differing only in the last nibble — `0x0C` vs `0x0F`.

The base is pinned **by control**, the method of `central_locking_chain.md` §4.2: the documented
`0x97994 → 0x40008EF7` mapping forces `r21 = 0x40008EE8`, and therefore `r21 + 0xC = 0x40008EF4`. ✔

⇒ **`0x40008EF4` is a sibling byte of `APP_lock_src_level`, written by `APP_lock_src_producer`** —
the same routine, from the same base register, four bytes apart. It is on **Path A**, and the bench
shows it responding to an RKE press in 8 of 12 passes. Combined with §4, this is a second,
independent line of evidence that the RKE stimulus reaches Path A.

> ⚠ **Instrument defect, found and fixed:** `282`'s raw-byte column initially printed `00 00` for
> every instruction — `mem.getBytes(addr, bytearray)` marshals to a Jython array that returns
> all-zero. A constant reading across every input is an instrument failure, not a measurement
> (rule 8), and it would have been easy to write up as "this region reads as erased". Replaced with
> per-byte `mem.getByte()`; the encodings above are from the fixed version and corroborate the
> listing's mnemonics independently.

> **Not established:** what this byte *means*. Its neighbours (`_src_origin`, `_src_level`) are
> outputs of the lock source state machine, so a sibling is plausibly another such output — but
> "plausibly" is not a finding, and the copy loop at `0x97474`/`0x97974` interleaves several streams
> (`central_locking_chain.md` §4.2 records that `218` found two interleaved copy streams here, and
> that `205` correctly *refused* to extrapolate the mapping for that reason).

### 8.2 ⚠ Two instrument bugs in this script, both caught by controls

- **A displacement literal is not a struct access.** The first version matched the *displacement
  text* against any base register and reported `e_stwu r1,-0x80(r1)` — a **stack-frame allocation** —
  as a field access on `0x40008D68`. The fix constant-folds the base register backwards (`e_lis` +
  `e_add16i`), **scoped to the enclosing function** per rule 17, and rejects any site whose base is
  not provably the struct. Result: 49 verified vs **499 rejected** on the control.
- **The struct-field scan needed its own positive control.** Added: it must rediscover the
  documented `0x8c(r4/r5/r6/r7/r31)` accesses to `APP_req_word_74` (`bench_session_2.md` §9.2). It
  finds 49 and reproduces the exact registers recorded there — so the zeros above are meaningful.

### 8.3 ⚠ `work/gw_dec.py` opens the WRONG PROJECT for this work (rule 5)

Decompiling these addresses with `gw_dec.py` printed `no func at 0x84148` for **every** address —
which reads exactly like "unswept block, no function", a plausible and completely false finding.
Cause: `gw_dec.py` opens `ghidra_proj` / `flash_merged.bin`, the acc-fix/rke-lock **build-and-verify**
project, which contains nothing below `0xC000` and whose addresses are not interchangeable with
`ghidra_proj_fullflash`.

Fixed two ways: **`work/owner/gw_dec_owner.py`** now exists for full-flash addresses and names the
project in its "no function" message, and `gw_dec.py` carries a header warning pointing at it.

---

## 9. Beating the ordering floor — partial, and honestly partial (`283_onecell_vs_wire.py`)

§5 left the ordering "simultaneous at the limit of this instrument", where the limit was the 23 ms
round-robin period. That limit is removable: `APP_lock_command` is on the wire as MS `0x3A` d3, so
it need not be peeked at all — poll **one** cell (no round-robin division, ~93 Hz → **11 ms**) and
take the other channel from candump timestamps, which are independent of our polling entirely.

| run | partner | gap 1.2 | gap 0.7 | verdict |
|---|---|---|---|---|
| 1 (raw reply timestamps) | `d3→02` | +0.0365 s, SE 0.0042 | +0.0252 s, SE 0.0057 | stable, 5.4σ from zero |
| 2 (de-biased) | `d3→02` | +0.0781 s, SE 0.0372 | +0.0429 s, SE 0.0067 | stable, consistent with zero |

**What is robust across both runs:** the nearest partner is `d3→02` at **both** cadences, and the
offset is small (25–78 ms) against the 510 ms alternative. §5's qualitative conclusion holds and is
now established at ~3× finer resolution.

**What is NOT established: the offset's value, or its sign.** Two independent reasons, both
disclosed rather than tuned away:

1. **Channel skew is uncalibrated.** A peek transition is timestamped when the UDS reply arrives; a
   `0x3A` edge when candump sees it. Any *constant* skew between those paths is indistinguishable
   from a real lag. Run 2 attempts to remove the known part — the measured RTT is **10.0 ms mean,
   10.4 ms max**, and the transition instant is bracketed by send/reply and estimated at the
   midpoint of consecutive midpoints, which cancels both the RTT and the sample-interval bias. The
   *residual* skew (candump's own path) is not calibrated.
2. **⚠ I changed two variables at once, so run 2 does not supersede run 1.** Run 2 added the
   midpoint de-biasing *and* fixed a real bug (`last = b` sat inside the `if b == 1` branch, so a
   transition to any other value never updated the state). The standard deviation rose **10×**
   (0.011 → 0.098 s) and the wire-only control degraded from sd 0.024 to sd 0.448. Something got
   noisier and **I cannot attribute which change did it** — AGENTS.md rule 34's corollary, violated
   by me here. The correct next step is to re-run with the bug fix alone, then add de-biasing.

The **wire-only control** is the useful diagnostic and needs no peek at all: `d3→01` to `d3→02`
should be the triplet's 0.51 s. Run 1 @gap 0.7 gives `+0.5143 s, sd 0.024` ✔ — but run 1 @gap 1.2
gives `+0.0818 s, sd 0.510` and run 2 gives `+0.275`/`+0.608` with sd 0.19–0.45. **That control is
failing in three of four conditions**, which means the nearest-neighbour pairing is picking wrong
partners when events are dense — exactly the §5 failure mode, one level down. Until that control
passes in every condition, no offset from this script should be quoted.

⇒ Item 41's ordering question is **narrowed, not closed**. Reported as a bound: the two cells move
within ~±80 ms, partner `d3→02`, at two cadences.

---

## 10. Reproducing

```bash
cd BCM/Research && . .venv/bin/activate
python3 work/bench/peek_read.py accept              # mandatory, every session
python3 work/bench/peeklib.py                       # controls + rate

python3 work/owner/277_bitnum_adjudicate.py         # §3 the bit-numbering proof
python3 work/bench/275_ram_diff_scan.py --passes 5 --stim-passes 12 --presses 40
python3 work/bench/276_peek_wire_watch.py --cells 40002E70,40008D2C --presses 8
python3 work/bench/278_patha_rke_test.py --repeats 2     # §4 idle-matched
python3 work/bench/279_order_gapsweep.py --presses 30    # §5 all-partner pairing
python3 work/bench/283_onecell_vs_wire.py --presses 30   # §9 ⚠ read §9 before quoting

python3 work/owner/280_unnamed_cells.py                  # §8 trace the candidates
python3 work/owner/281_ef4_pcode.py                      # §8.1 p-code (the one that works)
python3 work/owner/282_ef4_instructions.py               # §8.1 instruction-level confirm
python3 work/owner/gw_dec_owner.py 0x84148 0x95c66       # ⚠ NOT work/gw_dec.py
```

Every bench script writes a timestamped JSON under `work/bench/logs/`.
