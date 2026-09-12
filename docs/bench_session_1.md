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

## 5. 🔑 The relay clicks — a better observable than CAN

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

1. **Instrument the relay** (clamp/opto → a logged channel). Converts the best observable in the
   rig from audible to recorded, and is the acceptance test for everything below.
2. **Command-enum sweep** (`rfa_sim.py sweep`) — build the full enum → `d3` table, and test the
   static claim that `(code & 0xF) == 1` is LOCK. This the rig can do *today*, uncontended.
3. **The timed feature (item 42)** — predict and measure: enum 3 should produce a timed change in
   HS `0x380` d4 / MS `0x1A8` d0 / `0x1B0` d2 / `0x290` d0 / `0x370` d4, of duration
   `DAT_4000588F × 50` ticks. A falsifiable prediction the decode does not already know.
4. **Item 30 (ignition gate)** — blocked until an ignition input can be asserted; see §2.
5. **Item 41 (which consumer actuates)** — the patch-probe, now with the relay as the observable.

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
