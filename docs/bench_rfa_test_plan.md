# Bench test plan — RFA stimulus → lock-command response

**Rig.** A bench BCM we can (a) transmit MS-CAN `0x100` to, impersonating the RFA, and (b) observe
MS-CAN `0x3A` from, the frame that drives the DDM/PDM door modules.

**Why this matters.** Layer 36 ended with every *static* instrument in this region exhausted:
control-flow reachability is saturated (unrelated code reaches the same lock writes) and bit-level
data flow is empty. `AGENTS.md` golden rule 7 — "the final proof is a candump on the car" — and the
layer-36 conclusion both name a measurement as the required next step. This rig is that measurement,
and it is **better than a vehicle capture** because we control the stimulus rather than waiting for
it.

> **The rig closes a loop that is otherwise open.** We control the *entire* input side: the command
> code **and** the key-outside bit both live in `0x100`, which we synthesise, and the ignition state
> lives in `0x3A0`, which we also synthesise. The observable is `0x3A`. That is a full factorial
> experiment, not a passive capture.

---

## 1. The signals (all previously established — addresses for reference only)

**Stimulus — MS-CAN `0x100`**, 60 ms periodic, 8 bytes, idle payload `0217000002000000`
(`docs/rke_0x100_lock.md` §1):

| field | position | meaning |
|---|---|---|
| command code | `d6[7:3] ∥ d7[7:0]` | 13-bit code; low nibble of `d7` is the **command enum** |
| — `d7` bit0 | `0x01` | LOCK |
| — `d7` bit1 | `0x02` | UNLOCK |
| rolling counter | `d7` bit4, `d6` bit5 | toggles; ignore for identity |
| UB / valid | `d6` bit2 (`0x04`) | RFA asserts after rolling-code validation (lags presses) |
| **key outside** | `d1` bit7 | the `rke-lock` gate input |

**Second stimulus — MS-CAN `0x3A0`** d0 hi-nibble: `4` = ignition Run (the `rke-lock` gate reads
raw mailbox `0xFFFC42C8`).

**Observable — MS-CAN `0x3A`** (CAN1 MB1, CS `0xFFFC4090`, image `0x40000A0F`):

| byte | meaning |
|---|---|
| **d3** | `APP_lock_command` `0x40002E70` — `01` LOCK, `02` UNLOCK |
| **d1 bit6** | **execute strobe** — a *one-shot*, not a level (the v1/v2 rapid-clicking lesson) |
| d1 bit1 | UB |

⚠ The vehicle databases mislabel `d1` bit6 as a vehicle-speed quality field. The capture wins
(`AGENTS.md` rule 9); we are re-confirming that here from the BCM's own output.

---

## 2. What this rig can and cannot answer

Stated up front so no one over-reads the results (rules 8, 9, 23).

| # | Question | Answerable here? |
|---|---|---|
| **30** | **The ignition gate.** At the refusal condition, does `APP_lock_command` change at all (⇒ a gate exists to patch) or does `d3` reach `01` while `d1` bit6 never strobes (⇒ no path, injection is *necessary*)? | **YES — directly.** This is README §8 item 1, the project's top-listed next step |
| **42** | What `APP_body_cmd_timed_feature` `0x8D4DA` actuates, and its duration | **YES** — via a falsifiable duration prediction (§4.3) |
| — | The full `d3` command vocabulary (writers use `1,2,3,4,6,8,0x1F,0x3F,0xCF` — only `01`/`02` are decoded) | **YES** — new result |
| — | Does the BCM validate the rolling code, and how does it treat replays? | **YES** — and it is a prerequisite for everything else (§4.0) |
| **41** | *Which of the 9 `req_word_74` bit-15..20 consumer sites* actuates the lock | **NOT directly.** Black-box CAN observes the boundary, not which code site ran. It **narrows** 41 by correlation; closing it needs the patch-probe of §5 |

---

## 3. Instrument validation — run this FIRST, and stop if it fails

Golden rule 8: *a result that is constant across every input is as suspect as one that is zero.*
Before any conclusion, prove the rig can make the BCM change its output at all.

**P1 — positive control.** Ignition OFF, key-outside set, send a well-formed **UNLOCK**
(`d7` bit1). **Expect `0x3A` d3 → `02` with a `d1` bit6 strobe.** Unlock-with-ignition-off is the
one case the stock BCM is known to honour unconditionally.

If P1 produces nothing, **stop and debug the rig** — one of: wrong bus/bitrate, the BCM is asleep
(no network-management/wakeup traffic), a real RFA is contending on `0x100`, the rolling code is
being rejected, or missing prerequisite frames. **Do not interpret any null result until P1 passes.**

**P2 — negative control.** Send `0x100` with the command nibble `0` (idle payload) for 10 s.
**Expect no `d3`/strobe activity.** If idle traffic alone produces lock commands, the observable is
not driven by our stimulus and every positive below is worthless.

**P3 — discrimination control.** LOCK and UNLOCK must produce *different* `d3` values. If both
produce the same byte, we are watching something other than the lock command.

---

## 4. The experiment

### 4.0 Rolling code — establish the acceptance rule first

The BCM has its own validator (`APP_rke_code_commit` `0x058538`, validator `0x0584A4`). A replayed
static code may be accepted once and then rejected, which would silently poison every later trial.

Sweep: (a) same code repeated 10×; (b) counter incrementing per press; (c) counter jumped forward;
(d) counter rolled backward. Record which are honoured. **Everything after this uses whichever
scheme the BCM accepts repeatably.**

### 4.1 The ignition gate — open item 30 (highest value)

Full factorial, each cell ≥5 presses, each press = burst then release (release matters: the press
latch re-arms on `d7` bit0 clearing):

| ignition (`0x3A0` d0 hi-nibble) | key outside (`0x100` d1 bit7) | command | expected if a **gate** exists | expected if **no path** exists |
|---|---|---|---|---|
| OFF | outside | LOCK | d3=`01` + strobe | d3=`01` + strobe |
| OFF | inside | LOCK | d3=`01` + strobe | same |
| **Run (4)** | **outside** | **LOCK** | **no d3 change** | **d3=`01`, strobe never asserts** |
| Run (4) | inside | LOCK | no d3 change | d3=`01`, no strobe |
| OFF / Run | either | UNLOCK | d3=`02` + strobe | d3=`02` + strobe |

**This is the discriminating measurement.** The two hypotheses differ in an observable way:
*does `d3` reach `01` at all?* If `d3` never changes, a gate exists upstream and is patchable — a
smaller, more surgical mod than the shipped mailbox injection. If `d3` reaches `01` but `d1` bit6
never strobes, the layer-29 finding stands (`0x3A` d1 bit6 has **no pack setter anywhere in the
image**) and TX-mailbox injection is *necessary*, which retroactively justifies `rke-lock`'s design.

### 4.2 Command-enum sweep — the `d3` vocabulary

Sweep the low nibble of `d7` across `0x0..0xF` (and the 13-bit code's upper bits at a few values),
logging every `0x3A` byte plus the other frames the timed feature touches. Builds the
enum → `d3` table, and tests the static claim that `(code & 0xF) == 1` is LOCK
(`AGENTS.md` rule 13 — a command *enum*, not a bitmask).

### 4.3 The timed feature — open item 42, as a falsifiable prediction

`FUN_0008D4DA` case 3 starts a timer: `DAT_40008E46 = DAT_4000588F × 0x32`, accumulator
`DAT_40008DF0 += 10` per tick. It also sets `DAT_40002E44 |= 0x40`, and `250` resolved that cell to
**five** frames: HS `0x380` d4, MS `0x1A8` d0, MS `0x1B0` d2, MS `0x290` d0, MS `0x370` d4.

**Prediction (rule 11 — derive a consequence the decode does not already know):** whichever command
maps to enum 3 must produce a *timed* change in exactly those five bytes, with a duration that is an
integer multiple of 50 ticks. Measure the duration on the wire; it yields `DAT_4000588F` directly.
If the changed bytes are **not** in that set, the static resolution is wrong and `250` needs redoing.

### 4.4 `APP_rke_join_gate` `0x40008D3A`

Its *role* as an arm selector is known, its meaning is not. If any trial shows the same command
producing two different outcomes under otherwise identical inputs, that non-determinism is the gate,
and the differing precondition identifies it.

---

## 5. Closing item 41 — the patch-probe (phase 4, only if §4 doesn't settle it)

Black-box observation cannot name a code site. But the project has a **proven flash-patch pipeline**
and a proven-unused scratch band. So make the internal state observable:

For each of the 9 candidate consumer sites of `req_word_74` bits 15..20, add a few bytes in the
existing code caves that write a **distinct marker** into a spare `0x3A` byte (or a scratch cell
mirrored into an unused frame byte) when that site executes. Press the fob; read the marker off the
bus. One flash per candidate, or several markers per flash using distinct bit positions.

This converts an unanswerable static question into a direct measurement, using infrastructure that
is already on-vehicle proven. **All three integrity layers must be repaired per `AGENTS.md` §5, and
the worst realistic failure remains a no-op, not a brick.**

---

## 6. Logging and hygiene

- Capture **both** buses for the whole session, timestamped, one log per numbered trial; never
  interpret from a live terminal.
- Log `0x3A` **and** the five frames of §4.3 **and** the raw stimulus, so a negative can be
  distinguished from "we never actually transmitted".
- Keep logs out of the repo (`*.log` is gitignored) and run `work/owner/leak_check.py` before any
  frame/signal names are written into docs — the vehicle databases are confidential.
- ⚠ **Bench only.** Injecting `0x100` on a vehicle bus contends with the real RFA and is not a clean
  experiment. On the bench, confirm no RFA is present or disconnect it.
