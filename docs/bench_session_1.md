# Bench session 1 — results, and two corrections to my own method

**Rig.** Local SocketCAN, `can0` = HS 500k, `can1` = MS 125k, bench BCM on stock
`JV6T-14C094-AD`. Scripts `work/bench/rfa_sim.py`, `work/bench/ign_gate.sh`; logs in
`work/bench/logs/` (gitignored).

---

## 1. Rig brought up, and the BCM proven alive (a)

The BCM and **each bus sleep independently**. Sequence that works:

1. `can0` tester-present `726#023E00…` — the **first** request is dropped, later ones answered
   `72E ▸ 02 7E 00` (the sleep/retry behaviour `docs/sbl-upload-patch.md` §67 predicted).
2. MS wakes on **any** `can1` traffic; our own 60 ms `0x100` stream keeps it awake for a whole trial.

Once awake: HS carries `0x030`, `0x0C8`, `0x150`, `0x260`… and MS carries `0x020`, `0x03A`,
`0x040`, `0x060`, `0x3A0`, `0x1A4`, `0x1A8`, `0x1B0` — every frame the experiment needs.

---

## 2. ⚠ CORRECTION 1 — `0x3A0` is a BCM **output**, not an input (a)

`docs/bench_rfa_test_plan.md` §1 listed `0x3A0` as a *stimulus* to synthesise, because `rke-lock`
reads ignition from the raw mailbox `0xFFFC42C8`. **That was backwards.** The BCM **transmits**
`0x3A0` itself: 3042 frames appeared in `/tmp/ms_wake.log` during a window in which the only thing
I transmitted on `can1` was a `7FF` wake frame.

Consequence for the ignition-gate trial: flooding `3A0#41…` did not *set* the ignition state — it
merely put a second, conflicting source on the bus. The log proves both were present at once:

```
664 frames  41 00 …   (mine)
242 frames  11 00 …   (the BCM's own, ignition off)
```

**The `ignRUN` trial is therefore VOID.** Its result (`d3` still reaches `01`, strobes still fire)
measures nothing about the ignition gate: the BCM's own ignition state never changed, so that trial
is simply a *duplicate of the ignition-off control*, which is exactly what it looks like:

| trial | d3=01 | lock strobes |
|---|---|---|
| `ignOFFctl` (control) | 51 | 5 |
| `ignRUN` (void) | 42 | 4 |

Statistically identical — because they were the **same experiment run twice**. Reporting that as
"no ignition gate exists" would have been a textbook rule-8 error: a result constant across every
input, caused by an input that never actually varied.

**And the ignition cannot be turned on at the bench** (user-confirmed). So **open item 30 is NOT
answerable on this rig** as currently wired. Options, in order of preference:
- find the BCM's ignition/run **hard-wire input pin** and energise it (see `BCM_CAN_Pins`);
- source the state from whatever the BCM samples to *build* `0x3A0` — it is an output, so the real
  input is a pin or another frame, and that must be identified first;
- accept that the gate question stays open and spend the rig on §4–§6 below, which it *can* answer.

---

## 3. ~~CORRECTION 2 — an RFA is on the bus~~ → **RETRACTED, the frames were mine** (a)

I briefly concluded that a real RFA was contending on `0x100`, because `/tmp/ms_wake.log` held 752
`0x100` frames I believed I had not sent. **That was wrong, and the error was mine.**

The `ms_wake.log` capture process was **still running** (file mtime 12:13:54) while my own
`rfa_sim.py press` trials executed (12:09–12:11). It therefore recorded *my own* transmissions. The
three payloads I read as "a real RFA sending lock and unlock" are exactly what `rfa_sim.py` emits.

**Controlled re-test** — capture `can1` for 10 s while transmitting *only* `7FF` wake frames:

```
captured 3784 frames ; 0x100 frames: 0
```

⇒ **There is no RFA on the bus.** The original plan's assumption was right, my "correction" was a
self-inflicted artifact, and §6's top priority (unplug the RFA) is deleted.

**The lesson is the rule-8/rule-23 family again:** I compared a capture against my memory of what I
had transmitted, instead of against a *controlled* window in which I transmitted nothing. Whenever a
capture appears to contain traffic from an unknown source, re-capture with the stimulus **off**
before theorising about the source. A passive control costs ten seconds.

One observation survives the retraction and is worth keeping: the idle payload my simulator sends
(`02 17 …`) differs from the doc's reference idle in `d1` by `0x80` — the **key-outside** bit — which
is simply my `--key-outside` flag doing its job, and confirms the flag reaches the wire.

---

## 4. What the rig DID establish (a)

Despite the two corrections, the session produced solid results — all with a passing positive
control (P1: unlock with ignition off must move `d3`, and it did).

**The stimulus→response link is real and reproducible.** A synthesised `0x100` press produces a
lock command on `0x3A`:

| command | `0x3A` d3 | strobe |
|---|---|---|
| UNLOCK | `02` | `d1` bit6 |
| LOCK | `01` | `d1` bit6 |

Baseline (no press): `A0 00 00 00 00 00 00 00`.

**Three previously static-only claims are now confirmed on the wire:**

1. **`d3` is a level, `d1` bit6 is a one-shot strobe.** In the unlock trial `d3=02` persisted for 96
   frames while only 12 frames carried bit6. This is the v1/v2 "rapid clicking" lesson of
   `docs/rke-lock.md` §4, now observed directly rather than inferred.
2. **The rolling code gates the first press.** Press 1 (t=2.047) produced **no** strobe; presses
   2–4 did (t=3.891, 5.691, 7.491). Exactly the UB/validation lag documented in
   `rke_0x100_lock.md` §1 — and the reason `rke-lock` does **not** gate on UB.
3. **`0x3A` d3 = `APP_lock_command` `0x40002E70`** — the value the static chain predicted,
   observed at the predicted byte, on the predicted bus.

---

## 4b. 🆕 NEW RESULT — the command enum, and a third lock command `d3 = 06` (a)

`rfa_sim.py sweep` drove all 16 values of the `d7` low nibble; `one_nibble.sh` then re-ran the
interesting ones **in isolation from a settled bus**, because `d3` is a *level* that persists into
the next sweep slice and confounds per-slice attribution. The **execute strobe** (`d1` bit6) is the
unambiguous marker — it is a one-shot emitted at the moment of actuation — so the table is built
from strobed frames only.

| `d7` nibble | strobed `0x3A` payload | `d3` | meaning |
|---|---|---|---|
| **1** | `A0 40 00 01` (6×) + `A0 40 00 02` (3×) | `01` | **LOCK** (see the triplet note below) |
| **2** | `A0 4C 00 02`, `A1 4C 00 02` | `02` | **UNLOCK** |
| **3** | `A0 40 00 06` (10× / 3 presses) | **`06`** | **a third command — new** |
| 0, 4–15 | no strobe | — | no actuation |

**Only nibbles 1, 2 and 3 actuate anything.** That refutes the bitmask model outright (which
predicted LOCK on all 8 odd nibbles) and confirms **rule 13**: the command is consumed as an
**enum**, exactly as the static analysis claimed — now proven on the wire rather than inferred.

> **The nibble-1 triplet is a pattern, not noise.** Each LOCK press produces the *same* strobe
> sequence — `01`, `01` (+0.50 s), `02` (+0.55 s) — repeated identically across all three presses
> (press starts 2.56 s / 4.61 s / 6.66 s). Two lock strobes then an unlock strobe, at a fixed ~0.5 s
> cadence. That is precisely the shape `docs/rke-lock.md` §7 describes as the BCM's **own follow-up
> re-strobe** (the v3 double-click), now reproduced on the bench on *stock* firmware and with a
> trailing `02` the vehicle captures did not isolate. Worth a dedicated trial: it may be an
> auto-relock/anti-lockout behaviour, and it is exactly the mechanism `rke-lock`'s `L3` suppression
> window exists to neutralise.

### Why `d3 = 06` matters — it is Path A, and it cross-validates layer 36

`d3 = 06` had **never been observed on any capture** in this project. But it is not new to the
*static* analysis: `work/owner/lockcmd_writers.json` shows **six** of the 32 `APP_lock_command`
writer sites write exactly `0x6` — and two of them are **`APP_lock_req_producer_A` `0x8950A`** and
**`APP_lock_req_producer_B` `0x897EA`**, the terminus of **Path A**, the periodic lock chain of
layers 33–35 (`central_locking_chain.md` §2).

So the bench has just **made Path A fire on demand**, from an RKE stimulus. Two consequences:

1. **A prediction confirmed that the decode did not know** (rule 11): the static writer table said
   `0x6` must be reachable and the wire now shows `0x6`, strobed, reproducibly.
2. **Open item 39 ("which feature owns Path A") is newly attackable.** Path A was believed *not* to
   be RKE (layer 35 proved the two are disjoint in code). Nibble 3 reaching a `0x6` producer does
   **not** overturn that — the RKE path may simply *request* a feature Path A also serves — but it
   gives the first controllable trigger for Path A, which is precisely what item 39 lacked.

⚠ Not yet established: **which** of the six `0x6` writers ran. That is open item 41 in a new guise,
and it is what the §5 patch-probe (now with the relay as observable) is for. Do not assume it was a
producer just because producers write `0x6`.

---

## 5. 🔑 The relay clicks — now a MEASURED channel, and it proves two relays (a)

**User observations, mid-session:** (1) the BCM's lock relays click audibly, because with no
DDM/PDM present it falls back to driving the lock motors over its **hard-wired outputs**; (2) *"the
first two clicks have a different pitch from the last — like different relays."*

Both are now instrumented. The laptop mic sits near the BCM; `work/bench/click_detect.py` records
and onset-detects, `bench_ab.py` runs CAN + audio simultaneously and aligns them,
`click_spectra.py` fingerprints each click. No extra hardware was needed.

### 5.1 The strobe→click correspondence is exact (a)

LOCK trial, 3 presses. After fitting the audio/CAN start offset by cross-correlation
(**+0.989 s**, the recorder's device-open latency):

| CAN strobe (s) | d3 | acoustic click, aligned (s) | residual |
|---|---|---|---|
| 2.500 | `01` | 2.510 | +10 ms |
| 3.000 | `01` | 3.020 | +20 ms |
| 3.550 | `02` | 3.540 | −10 ms |
| 4.950 | `01` | 4.971 | +21 ms |
| 5.500 | `01` | 5.480 | −20 ms |
| 6.000 | `02` | 6.000 | 0 ms |
| 7.450 | `01` | 7.430 | −20 ms |
| 7.950 | `01` | 7.940 | −10 ms |
| 8.450 | `02` | 8.460 | +10 ms |

**9 strobes, 9 loud clicks, every residual ≤ 21 ms.** The `d1` bit6 execute strobe corresponds
**1:1 with a physical actuation** — the strongest possible confirmation that it is the actuation
command, and it is now *physical* evidence rather than a claim about a byte.

### 5.2 The pitch difference is real — and it tracks the COMMAND (a)

Spectral centroid of each click, labelled by the `d3` value of its matched strobe:

| command | n | centroid mean | sd | range |
|---|---|---|---|---|
| `d3=01` LOCK | 6 | **7307.6 Hz** | 51.2 | 7226.6 – 7360.7 |
| `d3=02` UNLOCK | 3 | **7132.5 Hz** | 22.6 | 7109.1 – 7163.1 |

The classes are **perfectly separable**: lowest LOCK (7226.6) sits 63.5 Hz above highest UNLOCK
(7163.1), so a single threshold at ~7195 Hz classifies **9/9 clicks with zero errors**.

Acceptance test (rule 9 — two groups always differ *a bit*; the question is whether they differ more
than members of the same group): on the normalised band profile, between-class distance is **0.168**
versus within-class **0.025 / 0.007** — a ratio of **10.6**, against a label-shuffled null of mean
1.05 / 95th-pct 1.53, **p = 0.005**.

⇒ **The user's ear was right: these are two physically distinct relays** — a lock relay and an
unlock relay — and the acoustic signature alone identifies which one fired.

**This is a genuinely new capability.** The acoustic channel can now distinguish *which actuator*
ran, independently of CAN. That is exactly the observable open item 41 needs, and it is finer than
anything the CAN bus exposes.

### 5.3 The nibble-1 triplet, explained

The fixed triplet from §4b is now fully resolved: each LOCK press produces **LOCK, LOCK (+0.51 s),
UNLOCK (+0.52 s)** — identical across all three presses, and confirmed acoustically on two distinct
relays. So the BCM really does drive the unlock actuator ~1 s after a lock press on this bench
configuration. Whether that is anti-lockout, a DDM-absent fallback, or the re-strobe behaviour of
`rke-lock.md` §7 is **not yet established** and deserves a dedicated trial.

### 5.4 ⚠ Two instrument bugs found and fixed (both would have produced false results)

1. **Amplitude classes must be separated before matching.** Two acoustic classes are present: relay
   actuations at snr ≈ 300–410, and a quiet class at snr ≈ 9. Matching against *all* events forced
   the tolerance from ~20 ms out to 250 ms and made the fit **indistinguishable from shuffled
   noise**. Matching the loud class only gives 9/9 at ≤21 ms. `--snr-min` now defaults to 100 and
   `--tol` to 50 ms.
2. **MAD collapse.** With `median + k·MAD` thresholding, a recording whose envelope is more than
   half (near-)constant yields `mad ≈ 0`, the threshold collapses to ~0, and **every** sample
   qualifies: one contaminated take reported **74 events with snr ≈ 10⁸**. That is a broken
   instrument, not a loud room. Fixed with a degeneracy flag, a std fallback, and an absolute floor
   at 2 % of envelope peak. **Regression:** the good trial still yields its 9 clicks; the bad one now
   yields **0** instead of 74.

A **contamination guard** was added to `bench_ab.py`: a trial with a degenerate threshold, or with
more than 3× as many loud events as strobes, is **rejected outright** rather than analysed. The
`nibble 3` acoustic trial was discarded under this rule (room noise, user-confirmed) — so
**whether `d3=06` actuates a relay is still unmeasured**, and must be re-run in a quiet room.

---

## 5.5 🆕 `d3 = 06` is a NON-ACTUATING command (a) — and a fixed-threshold bug

Two short quiet trials (`work/bench/quiet_trial.py`, user kept the room silent on request).

**Trial A — nibble 3 (`d3 = 06`):**

```
CAN  : 206 0x3A frames, 10 execute strobes, all d3 = 06
AUDIO: clean (degenerate=False, median 2.8e-4, mad 4.0e-5), 0 actuation clicks
```

**Trial B — nibble 1, same session, as the positive control** (proving the mic still hears relays):

```
CAN  : 8 execute strobes (5x d3=01, 3x d3=02)
AUDIO: 8 clicks, every one within +-35 ms of a strobe
```

⇒ **The third command strobes on CAN but actuates no lock relay.** The control rules out a broken
audio path, and the audio in trial A was measurably clean rather than silent, so this is a **valid
negative**, not a failed take.

That is a genuinely new fact about the firmware: `APP_lock_command` carries at least one value that
is *not* a door-lock actuation. It also explains why `0x6` never appeared in any vehicle capture
while being written by **six** static sites — the feature it belongs to does not move the locks. The
six `0x6` writers include `APP_lock_req_producer_A`/`_B` (Path A), so **Path A's mystery feature is
non-actuating on this bench configuration** — a real constraint on open item 39.

⚠ Still open: what `06` *does* actuate (if anything) — it may drive an output the bench cannot
express (no DDM/PDM, no ignition), or be a pure status/request code.

### The instrument bug this nearly caused (rules 8 / 23)

Trial B first reported **3 clicks for 8 strobes**, split perfectly along `d3`: all 3 unlock strobes
clicked, all 5 lock strobes appeared silent. That looked like a *finding* — "lock strobes don't
actuate" — and it was **entirely an artifact**.

Cause: a hardcoded `snr >= 100` cut. `snr` is normalised by each recording's own noise floor, so the
same physical relay scores **~410 in a quiet take and ~77 in a slightly noisier one**. Five real lock
clicks (peak 0.039–0.044, indistinguishable in amplitude from the unlock clicks at 0.052) fell below
the fixed cut.

Fix: split the classes **adaptively** at the largest *ratio gap* in peak amplitude — a property of
the signal, not of the noise floor. The observed gap is **22×** (quiet class 0.0017 vs actuations
0.039+), so the split is unambiguous. Plus an `edge_guard`: `parecord` emits a start-up transient at
t ≈ 0.009 s that survives any threshold but precedes every stimulus.

**Regression (all pass):** nib1-quiet 8/8, nib3-quiet 0/0, nib1-ab 9/9.

> The lesson generalises beyond audio: **never threshold on a quantity normalised by the noise
> floor when comparing across recordings.** Compare on the physical quantity (peak amplitude) and
> let the data define the boundary.

---

## 5.6 🔬 Item 42 — the static prediction FAILED, and that is a real result

`item42_timed.sh` + `item42_report.py`, CAN-only (both buses, 4 s baseline, one nibble-3 press,
12 s observation).

**Prediction under test** (from layer-36 script `250`): `FUN_0008D4DA` case 3 sets
`DAT_40002E44 |= 0x40`, which `250` resolved through the decoded TX tables to five frame bytes —
HS `0x380` d4, MS `0x1A8` d0, `0x1B0` d2, `0x290` d0, `0x370` d4 — so a nibble-3 press should change
those bytes, for a duration of `DAT_4000588F × 50` ticks.

**Result: 0 of 5 predicted bytes changed.** What did change:

| frame | byte | change | duration | reading |
|---|---|---|---|---|
| MS `0x03A` | d1 | `00` → `40` | 0.25 s | the execute strobe — expected, not evidence |
| MS `0x03A` | d3 | `02` → `06` | held | the command itself — expected |
| MS `0x1E0` | d0 | `42` → `62` | 0.30 s | **bit 5 set** — no packer claims it (§5.7) |
| MS `0x1E0` | d1 | `A0` → `C0` | 0.10 s | **2-bit field `0x60`, value 1 → 2** (§5.7) |
| MS `0x230` | d6 | `26` → `27` | 2.70 s | delayed (starts t+8.2 s) |
| MS `0x250` | d6 | `26` → `27` | 2.60 s | delayed (starts t+8.2 s) |

⇒ **Script `250`'s cell→frame mapping for `0x40002E44` is wrong, or that cell is not written on this
path.** Either way the static resolution cannot stand as-is, and this is exactly the falsifiable
test rule 11 asks for — it was designed so it *could* fail, and it did.

`0x1E0` d0/d1 are the interesting find: two transient bit-sets, ~0.1–0.3 s, coincident with the
press. That is the signature of the timed feature the static analysis was hunting — on a frame
nobody predicted. **Next step: re-derive what writes `0x1E0` d0 bit5 / d1 bit6 and work back to the
feature**, rather than trusting the `0x40002E44` route.

### ⚠ The diff itself was broken first — three artifacts, 25 false positives

The first run of this analysis reported **25 changed bytes** and a confident "prediction failed".
Most of those were artifacts of my own diff:

1. **Self-transmitted frames.** `0x100` is *our* stimulus; of course its bytes "changed".
2. **Counters / free-running values.** Baselines like `['0x2f','0x30','0x31','0x32','0x33']` →
   `['0x34'…'0x3b']` are rolling counters: a 4 s baseline cannot observe every value, so any later
   value looks new. This produced most of the noise (`0x400`, `0x405`, `0x40A`, `0x230` d7, `0x250` d7).
3. **Non-reverting changes.** A byte that differs for the entire 10.9 s post-window is free-running,
   not a timed feature.

Fixed by excluding self-TX ids, requiring a **stable** baseline (≤3 distinct values over ≥5 frames),
and reporting whether the value **returns** to baseline. 360 byte-channels seen → 311 testable → **6**
real changes. The conclusion survived the fix, but the evidence for it is now honest.

> Same lesson as §5.5 and as `AGENTS.md` rules 8/9: **when a diff returns a large answer, suspect the
> diff.** A stimulus/response experiment needs a stability model for every channel it compares.

---

## 5.7 🔗 Following the `0x1E0` lead back into the firmware (a/b)

Script `261`. MS `0x1E0` is a **BCM TX** frame (CAN1 MB13, image base `0x40000A57`), so both changed
bytes are things the BCM *emits* — the right place to look for the feature's output.

### ⚠ First, a correction to my own reading (rule 13, again)

I initially recorded the d1 change as "bit 6 set". **Wrong.** `0xA0 → 0xC0` flips bits 5 *and* 6
together:

```
d1 0xA0 = 1010_0000   field 0x60 = 0b01 = 1
d1 0xC0 = 1100_0000   field 0x60 = 0b10 = 2
```

It is a **2-bit field taking an enum value 1 → 2**, not a bit being set — the same wire-vs-
representation trap as `AGENTS.md` rule 13, now caught in my own notes rather than in someone
else's. The corrected reading matches a real packer *exactly*, which the wrong one did not.

### The d1 enum is fully resolved (a)

`tx_signal_dict.json`: image `0x40000A58` mask `0x60` shift 5 ← src **`0x40002EEC`** (site `0x4CA94`).
That cell has **7 writers**, and the constant each stores gives the enum's whole vocabulary:

| value | writer sites |
|---|---|
| **1** | `0x99612`, `0x996BC`, `0x9A0B8` |
| **2** | `0x9A428`, `0x9A398`, `0x9B0DE` |
| 3 | `0x9B10C` (unswept block) |

The bench transition **1 → 2** therefore runs through statically-known writers — a clean
static↔dynamic agreement, and the first time this project has tied a `0x99xxx`–`0x9Bxxx` routine to
an observable bus event. Value **3 exists in flash but was never reached** by the nibble-3 path:
untested, *not* absent.

⚠ The writers are one-line setter stubs (`DAT_40002EEC = r0; DAT_40003FD7 = 0xFF`) and the reference
manager resolves **no callers** for them — the familiar unswept-block blindness (rule 19). The
feature that *decides* the value is one climb further up and is **not yet identified**.

### The d0 bit-5 gap is a real hole in the extraction (b)

| image byte | packer mask coverage | uncovered |
|---|---|---|
| d0 `0x40000A57` | `0x81` (two packers: `0x80`, `0x01`) | **`0x7E`** — includes the observed bit 5 |
| d1 `0x40000A58` | `0x7F` (three packers) | `0x80` |

So **no packer in the 384-entry extraction writes d0 bit 5**, yet the bench shows it being set and
cleared. Rule 12's escape hatch (a 16-bit primitive anchored on the previous byte also writing this
one) does **not** apply: `0x40000A56` has no packer either.

⇒ Either `tx_signal_dict.json` is incomplete for this frame, or d0 bit 5 is written by a path
outside the pack stage entirely. Both are findings; neither is yet resolved.

---

## 5.8 🎯 The climb succeeded: the `0x99xxx–0x9Bxxx` region is the RKE subsystem (a)

Script `262`. The reference manager found **0 callers** for the setter stubs; the rule-19 walk
(JUMP + CALL + byte-adjacency fallthrough, refs taken against *every* address in the block) found
them immediately. Controls: C1 reproduced layer 35's known 14-hop climb; C2 confirmed an unrelated
leaf (the RX copier) does **not** wander into this region.

**All 7 writers of `0x40002EEC` reach `APP_feature_periodic`**, converging on a shared spine:

```
APP_feature_periodic 0x62848
  -> FUN_0009BAD0 -> FUN_0009B41C / FUN_0009B456
     -> FUN_00099ED0 / FUN_00099A60 / FUN_0009A2EC ...
        -> the 7 setter stubs -> 0x40002EEC -> MS 0x1E0 d1 field 0x60
```

⚠ Reaching a spine symbol proves **scheduling, not identity** — `APP_feature_periodic` is an
ancestor of most of the body layer. The identification below rests on the *content* of the blocks,
not on the climb.

### `FUN_0009B41C` is the RKE feature dispatcher (a)

The decompilation is decisive — it calls the RKE demux by name and manipulates the RKE command bits:

```c
FUN_0009B41C:
    ...
    APP_rke_cmd_bits_38 &= 0xfff7ffff;
    FUN_0009AC0C(); FUN_0009AE2C();
    APP_rke_command_demux();          // <-- the layer-31 RKE decoder
    FUN_00099ED0(); FUN_0009AF2C(); FUN_0009A44E();
    FUN_0009B15C(); FUN_0009A84C();
    uVar6 = APP_rke_cmd_bits_34 >> 0x16 & 3;   // 2-bit mode switch
    ...
```

⇒ **The whole `0x99xxx–0x9Bxxx` region is the RKE subsystem**, dispatched once per periodic tick,
and our `0x1E0` enum is one of its outputs. This is the first time this project has attributed that
address range to a function.

### The enum's decision rule (a)

Both enum writes are guarded by the **same predicate**, confirmed in the raw listing and by the
decompiler independently:

```
0x9a0ae  se_lbz r0,0x0(r29)      ; load a mode/state byte
0x9a0b0  se_cmpi r0,0x3          ; == 3 ?
0x9a0b2  e_bne  cr0,0x0009a30e   ; skip unless it is
0x9a0b6  se_li  r0,0x1           ; the enum value
0x9a0b8  se_stb r0,0x0(r27)      ; -> 0x40002EEC
```

decompiled as `if (*unaff_r29 == 3) { *unaff_r27 = 2; DAT_40003FD7 = 0xFF; }`, with
`r27 → 0x40002EEC` and `DAT_40003FD7` the pack-stage dirty flag.

`FUN_0009A2EC` carries the timing: `if (*(p+0x40) < *(p+0x14)) *(p+0x40) += 10;` — a **counter vs
limit incremented by 10 per tick**, exactly the idiom of the `0x8D4DA` timer
(`DAT_40008DF0 += 10`, limit `DAT_40008E46`). So the ~0.10–0.30 s pulses the bench measured are this
counter expiring.

### What is NOT established

- **The meaning of `[r29] == 3`** — the mode byte that enables the enum. Its address is not resolved
  (it arrives in a register from a caller frame).
- **Which physical feature** the `0x1E0` field drives. "RKE subsystem output" is as far as the
  evidence goes; the frame is a BCM TX, so the consumer is another module.
- **`0x1E0` d0 bit 5** — still unexplained (§5.7); no packer claims it.
- **Why value 3** (`0x9B10C`) was never reached on the bench.

---

## 5x. 🔑 Why the relay channel matters

**User observation, mid-session: the BCM's lock relays click audibly during these trials.** With no
DDM/PDM present, the BCM falls back to driving the lock motors over its **hard-wired outputs**.

This is more valuable than it first appears:

- It is **physical ground truth**, independent of the CAN interpretation. "d3 went to 01" is a
  claim about a byte; "the relay fired" is the actuation itself.
- It means the bench reproduces the **whole** chain — RF command → decode → request bus → lock
  module → *actuator* — not just the part visible on MS-CAN.
- It gives a **clean binary observable for the patch-probe of §5 in the test plan**: instrument a
  candidate consumer site, press, and listen. No frame decoding required.
- It also explains the multiple strobes as real re-actuations, and makes the double-click/5-click
  failure modes of `rke-lock` v3/v4 directly audible on the bench rather than needing a car.

**Worth adding:** a current-clamp or a simple opto/ADC tap on a lock output would turn the click
into a *logged* signal with timestamps, correlatable against the candump — turning a subjective
"I hear clicking" into a measurement. That is the single highest-value rig upgrade.

---

## 6. Revised priorities for session 2

0. ~~Re-run the `d3=06` acoustic trial~~ — **done (§5.5): `06` strobes but actuates nothing.**
1. ~~Instrument the relay~~ — **done**, via the laptop mic (§5). No hardware needed.
2. ~~Command-enum sweep~~ — **done** for `d3`; the actuating set is `{01 lock, 02 unlock}` and
   `06` is non-actuating.
3. **The triplet's cause (§5.3)** — each LOCK press drives LOCK, LOCK, UNLOCK on two relays. Vary
   press duration / inter-press gap, and test whether an intervening UNLOCK suppresses it.
   Directly relevant to `rke-lock`'s `L3` suppression window. ~15 s of quiet per trial.
4. ~~The timed feature (item 42)~~ — **done (§5.6): the prediction FAILED.** Script `250`'s
   `0x40002E44` → frame-byte mapping does not hold on the wire. Followed up in §5.7: the MS `0x1E0`
   d1 change is a **2-bit enum 1→2** whose source `0x40002EEC` has 7 known writers (values 1/2/3).
   **Still open:** who *calls* those setter stubs (unswept blocks — rule 19), and what writes
   `0x1E0` d0 bit 5, which **no packer in the extraction claims**.
5. **Item 30 (ignition gate)** — blocked until an ignition input can be asserted; see §2.
6. **Item 41 (which consumer actuates)** — the patch-probe, now with a **relay-discriminating**
   observable: the acoustic signature identifies *which* relay fired, so a probe no longer needs to
   encode its marker into a CAN byte at all.

---

## 7. Method notes earned this session

- **`0x3A0` is an output.** Before synthesising any frame, check whether the DUT already transmits
  it; spoofing an output creates a two-source bus and a void experiment (§2).
- **A capture is only "unknown traffic" if the stimulus was off.** Verify with a passive control
  window before theorising about a second source (§3). Both of this session's corrections were
  caught this way, and one of them was a correction *to a correction*.
- **Each bus sleeps independently**, and the first tester-present is always dropped.
- **The relay fallback is a feature of the bench, not a defect** — no DDM/PDM means the BCM drives
  the locks directly, giving a physical observable the vehicle would hide behind the door modules.
