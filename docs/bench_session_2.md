# Bench session 2 — the probe bank, flashed and read live

**Status:** probe-bank VBF flashed to the bench BCM, module boots normally, positive control passes,
9 of 17 probes move under an RKE lock press. First live RAM observation of the RKE chain.

Artifact: `work/probe-bank/JV6T-14C094-AD_probe-bank.VBF`
sha256 `6f1d1982ec5a06b2916d607cf085ab9bd29c428a6b37f64b342db6e0b548be07`
Flash log: `work/flash/logs/run1.log`

---

## 1. The flash

`bcmflash.py flash ... --execute` — first real use of the tool (`docs/bcmflash_tool.md`).

```
SBL DV6T-14C097-AB -> RAM, 6 blocks, started at 0x40002000   OK
erase 11 regions 0x010000..0x140000                          OK  (all 7101FF0010)
app download 1.2 MiB @ ~29 KiB/s                             OK
   blk0 37 -> 77 9CE3      <- matches the VBF's own CRC-16
   blk1 37 -> 77 52E7      <- matches
11 01 ECUReset
*** FLASH COMPLETE ***
```

The ECU echoed **exactly the CRC-16 values the VBF declares** for both blocks — an independent
end-to-end confirmation that what landed in flash is what we built.

**The module came back on its own**, no power cycle, no safe mode: `F188` reads `JV6T-14C094-AD`,
and every identity DID answers normally.

Total elapsed: ~70 s. Erase of a 128 KiB region completed well inside the 60 s timeout (the
`responsePending` handling in §3 of the tool doc was never stressed, but was correct).

## 2. The probes took

`probe_read.py idle`, compared against the pre-flash OEM baseline (`live_debug_uds.md` §8.5):

| DID | watches | OEM value (pre-flash) | now | |
|---|---|---|---|---|
| `0x4125` | MS `0x1E0` d0 image | `14` | **`42`** | matches the `0x1E0` d0 idle seen in bench session 1 |
| `0x412D` | MS `0x1E0` d1 image | `00`/`01` | **`80`** | matches `0x1E0` d1 idle |
| `0x412E` | `0x40003FD7` | `86` | `00` | |
| `0x40A9` | `APP_body_cmd_bus` b2 | `01` | `0C` | |
| `0x4099` | `req_word_74` b2 | `09` | `00` | |

`0x4125`/`0x412D` are the decisive pair: `42` and `80` are **precisely the MS `0x1E0` d0/d1 idle
values measured on the wire in session 1** (§5.7), and nothing like the OEM DID values. The probes
are reading the cells we aimed them at.

## 3. ✅ The acceptance test passes

```
lock    770 samples | probe saw 01,02 | bus 0x3A d3 saw 01,02
unlock  770 samples | probe saw 02    | bus 0x3A d3 saw 02
   lock    probe∩bus: YES
   unlock  probe∩bus: YES
   ✓ CONTROL PASSES
```

`0x0631` watches `APP_lock_command`; MS `0x3A` d3 is that same cell on the wire. They agree on both
commands. **The live-debug channel is validated against an independent observable.**

### ⚠ 3.1 The first run said FAIL — and the tool was fine

The first control run printed `✗ CONTROL FAILS`, with `probe saw 00,01,02` but `bus 0x3A d3 saw -`.
The probe side was already perfect; the **bus observer captured nothing**.

Cause: `candump` has two output formats and they are not interchangeable.

```
candump -L   ->  (ts) can1 03A#A040000100000000        '#'-joined
candump -ta  ->  (ts)  can1  03A   [8]  A0 40 00 01    spaced columns
```

`probe_read.py` launches `-ta` but parsed with a `03A#` regex — so `bus` was always empty, and
`probe ∩ bus = ∅` was reported as *the probe disagreeing with the bus*. A verified-good 1.2 MiB
flash was one careless reading away from being condemned by a broken instrument.

Two fixes, both structural:
- parse **both** candump formats;
- **an empty observer is now INCONCLUSIVE, never FAIL.** If the bus capture is empty the tool says
  so explicitly and refuses to render a verdict, because a dead instrument is not evidence about
  the thing being measured (`AGENTS.md` rule 8).

## 4. 🔑 The RKE chain, observed live

`probe_read.py watch --cmd lock`, 884 reads in 9.0 s (98 Hz aggregate, 5.8 Hz per probe).
**9 of 17 probes moved.** Ordered by first change:

| t | DID | cell | name | transition |
|---|---|---|---|---|
| 2.479 s | `0x40BE/C0` | `0x40002DA2/A3` | `APP_rke_command_code` | `0000` → **`1801`** |
| 2.639 s | `0x0631` | `0x40002E70` | `APP_lock_command` | `02` → **`01`** |
| 2.640 s | `0x40A9` | `0x40008E5A` | `APP_body_cmd_bus` b2 | `0A` ↔ **`0C`** |
| 3.539 s | `0x411F` | `0x40008D2C` | `APP_lock_request_input` | `00` → **`01`** |
| 4.899 s | `0x4099` | `0x40008E76` | `req_word_74` b2 | `00` → **`06`** |

Plus `0x4125`/`0x412D` (the `0x1E0` images) cycling `42`↔`00` and `80`↔`00`.

### 4.1 `req_word_74` is NOT inert — correcting layer 36

> ## ⚠⚠ THE BIT IDENTIFICATION BELOW IS WRONG — see `docs/bench_session_3.md` §3
>
> `0x06` in b2 is **LSB bits 9|10**, not "word bits 17 and 18". Those are Path A's **edge
> detector** bits (`APP_lock_req_edge_detect_A/B` contain the literal constants `| 0x400`,
> `& 0xFFFFFDFF`, `& 0xFFFFFBFF`), *not* the RKE handoff field, whose writer sites decode to LSB
> bits 14..18 and **do not intersect** `0x600`.
>
> Consequences, both retracted: this section does **not** refute layer 36's bit-level negative, and
> the revival of the `0x8B3D6` "bit 17" lead in the last paragraph is **withdrawn**. The cause was
> two documents in this repo numbering bits of the same word in two different conventions
> (LSB from the decompiler, MSB from an `mb`/`me` decode) and this section silently picking one.
>
> What survives: **the cell is not inert at runtime.** That much is correct, and session 3 §4
> strengthens it — the press-driven mechanism here is Path A, and Path A *is* RKE-driven.

Layer 36 (`docs/rke_lock_join.md`) identified `APP_req_word_74` bits 15..20 as the relocated RKE
handoff, then found the bit-level join to the lock chain **empty** — recorded as a clean controlled
negative.

**At runtime it is not empty.** `0x40008E76`, the byte carrying bits 15..20, takes **`0x06`** during
a lock press and returns to `00`. The static negative was a limit of the static method, not a fact
about the firmware — exactly the gap the probe bank was built to close.

`0x06` = `0b110`, i.e. **word bits 17 and 18**. Note `0x8B3D6` (`se_btsti r0,0xe`) tests **bit 17** —
the lead withdrawn in layer 36 for failing the saturation control. It is now back in play as a
*candidate*, but the saturation objection has not been answered and reachability still proves nothing.

### 4.2 An unexplained coincidence, flagged not concluded

`0x06` is also the value of the **non-actuating `d3=06` command** from the nibble sweep
(`bench_session_1.md` §5.5). Same byte value, two very different contexts. This may be
meaningful or may be two unrelated small integers; **nothing here establishes a link.**

### 4.3 What the ordering does and does not show

The 2.479 s → 4.899 s spread is consistent with a chain, but the per-probe sample rate is **5.8 Hz**
(~170 ms between looks at any one probe), so **ordering within ~200 ms is not resolved** and these
timings must not be read as a causal sequence. `APP_lock_command` and `APP_body_cmd_bus` changing
1 ms apart is an artifact of adjacent polls, not simultaneity.

To order them properly, watch **two or three** probes at a time (≈33–50 Hz each) rather than 17.

## 5. ✅ Acoustic re-check — the flash did not change actuation

`quiet_trial.py --nibble 1 --presses 3` on the **flashed** module (attempt 1 auto-rejected as
contaminated; attempt 2 clean):

```
CAN  : 6 execute strobes; d3 seen 0x1, 0x2
AUDIO: 6 actuation clicks, class split at 22x amplitude gap
```

| strobe | d3 | click | Δ | centroid | class |
|---|---|---|---|---|---|
| 3.050 | `0x1` | 3.078 | +28 ms | 7529 Hz | `0x1` ✓ |
| 3.550 | `0x1` | 3.588 | +38 ms | 7572 Hz | `0x1` ✓ |
| 4.100 | `0x2` | 4.108 | +8 ms | 7079 Hz | `0x2` ✓ |
| 5.300 | `0x1` | 5.298 | −2 ms | 7639 Hz | `0x1` ✓ |
| 5.800 | `0x1` | 5.808 | +8 ms | 7611 Hz | `0x1` ✓ |
| 6.300 | `0x2` | 6.328 | +28 ms | 7106 Hz | `0x2` ✓ |

**6/6 CAN class = acoustic class**, mean latency +18 ms. The **lock,lock,unlock triplet is
preserved** at +0.50 / +0.55 s — identical to the stock measurement in session 1 §5.

⇒ The probe-bank firmware actuates the relays exactly as stock. Every timing measurement taken
after the flash is against the same physical behaviour as session 1.

One caveat recorded honestly: the **lock** centroids ran 258–368 Hz above the stored reference
(7529–7639 vs 7271.8) while **unlock** matched to 14–42 Hz. Classification is unaffected because the
classes stay far apart, but the absolute lock centroid moved. Most likely mic/gain/position drift
between sessions — **not established**, and not a claim about the firmware.

## 6. Narrow watch — and two wrong readings of my own

Added `--only` to `probe_read.py`: watching 3 probes instead of 17 gives **32.4 Hz per probe**
(~31 ms resolution) instead of 5.8 Hz.

### 6.1 ❌ First reading: "ordering resolved" — WITHDRAWN (phase artifact)

At `--gap 1.5` the trace showed `APP_lock_command → 01` at 2.499/4.299/6.099 and
`body_cmd_bus b2 → 0C` at 3.539/5.339/6.629 — a beautiful **constant +1040 ms** offset, twice.

It is not evidence. Both signals repeat at the **press cadence** (1.800 s deltas = the simulator's
inter-press period). Two square waves sharing a period will show a *constant* offset at any
arbitrary phase. A fixed lag between two press-locked signals proves nothing unless the press
timing is varied.

### 6.2 ❌ Second reading: the pairing itself was wrong

Re-running at `--gap 0.8` — the falsification test, since a causal lag stays constant while a phase
artifact moves — produced the decisive trace:

```
t=2.479  bus_b2    0A       t=3.629  lock_cmd  01
t=2.489  lock_cmd  01       t=3.639  bus_b2    0A
t=3.509  lock_cmd  02       t=4.660  bus_b2    0C
t=3.519  bus_b2    0C       t=4.669  lock_cmd  02
```

Pairing each transition with its **nearest** neighbour rather than the next *rising* one:

| lock_cmd | bus b2 | Δ |
|---|---|---|
| `02` @0.009 | `0C` @0.019 | +10 ms |
| `01` @2.489 | `0A` @2.479 | −10 ms |
| `02` @3.509 | `0C` @3.519 | +10 ms |
| `01` @3.629 | `0A` @3.639 | +10 ms |
| `02` @4.669 | `0C` @4.660 | −9 ms |
| `01` @4.769 | `0A` @4.779 | +10 ms |

**The two cells move together within ±10 ms at every single transition**, with an exact
correspondence `lock_cmd 01 ↔ bus 0A`, `lock_cmd 02 ↔ bus 0C`.

The 1040 ms "lag" came from pairing `01` with the *next* `0C` — the wrong partner. `01`'s partner is
`0A`. ±10 ms is the round-robin interval between the two probes, i.e. **they are simultaneous at the
limit of this instrument**.

⇒ `APP_body_cmd_bus` bits 11..13 and `APP_lock_command` are **one event, not two pipeline stages**.
No ~1 s propagation delay exists.

Both errors are the same family as `AGENTS.md` rules 8/9/23: a clean-looking number from an
instrument or an analysis rule that was never itself tested. The fix is now in the tool —
`--gap` is documented as *the* way to separate a causal lag from a cadence coincidence.

### 6.3 `req_word_74` b2 — investigated properly (§8)

`0x40008E76 → 0x06` fired **once** at t=6.620 s in the 3-probe run, and **once** at t=4.899 s in the
17-probe run, despite three lock presses each. That per-burst behaviour prompted a dedicated
hypothesis test — see §8, which **corrects the §4.1 reading**.

## 8. What triggers `req_word_74` b2 → `0x06`

Three scripts: `r74_trigger.py` (hypothesis sweep), `r74_freerun.py` (free-running control),
`r74_sustained.py` (warm-up test). Hypotheses were stated with distinct predictions *before*
measuring.

### ⚠ 8.1 The first sweep produced a verdict its own data refutes

`r74_trigger.py` printed **"consistent with H3 (needs ≥ 3 presses)"**. That verdict is void — three
independent defects:

- **State leaked between trials.** Conditions ran back-to-back with no reset, and the trace records
  the *first* sample as a "change" (there is no previous value). A cell still holding `06` from the
  previous condition was counted as a fresh firing at t=0.006. Every `fired` count was inflated.
- **The edges are not stimulus-locked — and I never checked.** `3.510` appears at `gap=0.6` **and**
  `gap=2.5`; `2.995` at `gap=1.5` **and** `gap=0.6`. Press times move with the gap
  (`2.0 + k·(0.3+gap)`); those edge times do not. A trivial check that would have voided the verdict
  immediately.
- **The free-running control was blind by construction** — 10 s, run *first*, before any press. If
  the mechanism is armed by a press and then free-runs, that control cannot see it.

### 8.2 ✅ H4 (free-running) — REFUTED, with an adequate control

`r74_freerun.py`: 30 s quiet **before** any press + 40 s quiet **after** a confirmed 3-press burst.
**0 edges in 70 s of quiet.** The cell does not move without a stimulus.

That run also produced a genuine surprise: **zero `06` even during its 3 confirmed presses** —
prompting H5.

### 8.3 ❌ H5 (needs sustained activity) — REFUTED

Every run that saw `06` had been continuously active for minutes; the one that saw none opened with
30 s of quiet. Plausible — and wrong.

`r74_sustained.py`, 8 identical bursts back-to-back (3 presses, gap 1.5 s), stimulus confirmed in
every one:

| burst | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | after 45 s quiet |
|---|---|---|---|---|---|---|---|---|---|
| new `06` | no | **YES** | **YES** | **YES** | **YES** | **YES** | **YES** | **YES** | **YES** |

`06` appears from **burst 2**, and the post-quiet burst fired at 6.61 s. **45 s of idle resets
nothing**, so no warm-up is required.

### 8.4 What is now established

- **`0x06` is stimulus-driven** — 0 edges in 70 s of quiet across two independent windows.
- **It is reproducible** — 7 of 8 identical bursts, plus the post-quiet burst.
- **Its rising edges are press-locked in two tight clusters:** `3.00–3.80 s` (n=7) and
  `6.609–6.620 s` (n=4, spread **11 ms**). Presses begin at 2.0, 3.8, 5.6 s.
- **H4 and H5 are both refuted** by direct measurement, not argument.

### 8.5 Still not established

- **Why burst 1 (and the `r74_freerun` burst) produced nothing.** Both had `locks=3`; so did the
  post-quiet burst, which *did* fire. Neither activity level nor press count predicts it.
- **Which press each cluster belongs to.** The poller aliases the lock counter (bursts 2–8 report
  1–2 lock edges for 3 actual presses), so presses cannot be aligned reliably at this rate.
- **Whether `0x06` is on the RKE path at all.** Press-locked timing shows correlation with the
  stimulus, not membership in the lock chain. §4.1's "runtime refutation of layer 36" should be read
  as *"the cell is not inert"* — nothing more.
- An earlier note in this session claimed the clusters were "all within 0.8 s"; the list spanned
  3.0–6.62 s. Two clusters, not one — corrected above.

## 9. Who reads `0x40008E76`? (script `273`)

With a runtime fact to explain (§8.4), a reader search finally has something real to account for.
Three methods, reconciled per rule 17; rule 12 honoured by searching every primitive whose span
**covers** the byte (`word@0x8E74`, `half@0x8E76`, `byte@0x8E76`), not just the byte's own address.

### 9.1 The methods disagree by 8×

| method | sites |
|---|---|
| reference manager | 406 |
| decompiler p-code (`CALLOTHER`) | 267 |
| raw linear sweep (352,906 instructions) | 49 |

**sweep-only = 0** — the sweep is a strict *subset* of the other two, because it only counts
accesses whose base register it can constant-fold **within one function** (rule 17 scoping). The
other two also count accesses through a base it cannot resolve. So here the sweep is the
conservative instrument, and its blindness is explained — which is what rule 17 demands.

**33 of the resolved accesses are reads** covering our byte.

### 9.2 🔑 The structural finding: it is a struct field, not a standalone global

Every single access has the same shape:

```
e_lwz rX,0x8c(r4/r5/r6/r7/r31)
```

Not an absolute load. Sampling four sites in different functions, the base is defined identically in
each:

```
0x86ca2  e_add16i r6,r6,-0x7218      (paired with e_lis rX,0x4001)
0x8d118  e_add16i r6,r6,-0x7218
0x8a28c  e_add16i r7,r7,-0x7218
0x88744  e_add16i r5,r5,-0x7218
```

`0x40010000 − 0x7218 = 0x40008DE8`, and `+0x8C` = `0x40008E74`. So **`APP_req_word_74` is field
`+0x8C` of a global struct based at `0x40008DE8`** — the label is misleading, it is not a dedicated
word.

**Self-correction:** on first seeing the `0x8c(rX)` pattern I wrote that the 33 sites might be
reading *other instances* of the same struct type, making the result rule-9 saturation. That was
wrong — the base is a **compile-time constant, identical at every site sampled**. There is one
instance. The 33 reads are genuine reads of this word.

### 9.3 What this does and does not settle

**Does:** item 41's consumer set is now **closed and enumerated** — 33 read sites, listed in
`work/owner/r74_readers.json`, all in the `0x86xxx`–`0x8Fxxx` body-control region. That is a
different epistemic state from layer 36's empty bit-level join.

**Does not:** 33 is still far too many to name *the* consumer, and nothing here places any of them
on the actuation path. The reads are of the whole 32-bit word, so most may care about entirely
different bits than the `0x06` the bench observed in b2.

**The discriminator now exists, though:** `0x06` is press-locked to two tight windows (§8.4), so a
reader on the actuation path must execute inside them. That is a bench-answerable question, not a
static one.

### 9.4 🔑 The struct reframes several earlier findings

Expressing the project's already-named cells relative to base `0x40008DE8`:

| address | project name | offset |
|---|---|---|
| `0x40008D2C` | `APP_lock_request_input` | **base − 0xBC** |
| `0x40008D3A` | `APP_rke_join_gate` | base − 0xAE |
| `0x40008E58` | `APP_body_cmd_bus` | base + 0x70 |
| `0x40008E70` | `APP_req_word_70` | base + 0x88 |
| `0x40008E74` | `APP_req_word_74` | base + 0x8C |

`AGENTS.md` rule 16 was written after a scan lost 361 stores to a signed-displacement parse bug, and
records that *"the target sat at **−0xBC** from the block base"*. That is exactly
`APP_lock_request_input` relative to `0x40008DE8` — **the same struct base was already implicated,
unrecognised, back then.**

This also gives the long-standing saturation problem a structural explanation. `APP_body_cmd_bus`'s
**226 references** (layers 35/36) are not 226 uses of one global; they are accesses to **one shared
body-control struct**. Treating its fields as independent globals is what made every reference-based
join look saturated — the "shared bus" intuition in layer 36 was directionally right and
structurally wrong.

**Not established:** the struct's extent or element size, and whether the negative offsets
(−0xBC, −0xAE) belong to this struct or a preceding one. Base `0x40008DE8` is confirmed only for the
`+0x8C` accesses sampled here — four sites, all identical, which is suggestive but not exhaustive.

## 10. What is NOT established (updated)

- **Item 41 still open**, but narrowed: `req_word_74` b2 → `0x06` is stimulus-driven, reproducible
  and press-locked (§8.4), and its readers are now a **closed set of 33** (§9). None is shown to be
  on the actuation path.
- **No causal ordering anywhere in the chain has been demonstrated.** §6.1/§6.2 withdrew the only
  candidate; `lock_command` and `body_cmd_bus` are simultaneous to ±10 ms.
- Why burst 1 / the `r74_freerun` burst did not fire (§8.5).
- The `0x06` / `d3=06` coincidence remains unexplained.
- Why the lock relay's spectral centroid shifted ~300 Hz between sessions (§5).
- 8 of 17 probes still unmoved under this stimulus.
- Item 30 (ignition gate) untouched.

> **Note on §4.1.** Read it with §8.5: the runtime observation shows `req_word_74` b2 is *not inert*,
> which is a real correction to layer 36's static negative. It does **not** establish that the cell
> is part of the RKE→lock handoff.
