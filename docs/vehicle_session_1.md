# Vehicle session 1 — the remote-start blocker identified

**Unit: the VEHICLE** (identity read, not assumed — AGENTS.md rule 32):
`F188 = JV6T-14C094-AD` (matches the cave's addresses), `F124 = JV6T-14C095-AB`,
`F111 = F1DT-14F119-EC`, PBL **V014**, serial `000690014659`, VIN `WF0AXXWPMAEL32600`.
**Different module from bench #1** (`009640039386`, PBL V013, `DV6T-14C245-FF`) — same application
part, different hardware and calibration. Config differences between the two are therefore expected
and are *not* evidence of anything the flash did.

Build flashed: `JV6T-14C094-AD_peek-rstrigger.VBF`
sha256 `1148017e9cc9d6c12c6d18fca47d824d182f703edd4e9331b360c9d22826ace8` (peek + 3 trigger depths).
Acceptance after flash: **ALL PASS** (stock DIDs served, peek known-truth `70E8E000`).

---

## 1. ⚠ RETRACTED HEADLINE — `0x40009680` bit 27 is an RF-RECEPTION indicator, not a gate

> **User observation on the vehicle (decisive, 2026-09-13):** *"if I hold any button on RKE even
> when not locked and ignition on, your scripts says gate3=7 GATE OPEN. So it reacts on every button
> on keyfob in any mode."*

This refutes the original §1 headline ("bit 27 is the sole blocking term"). Bits 28/29 are always
set, so `((word >> 0x1B) & 7) == 7` reduces to **bit 27 alone**, and bit 27 is high whenever *any*
fob button is transmitting — lock, unlock, panic, in any vehicle state. It is a **receiver-active
flag**, not a remote-start condition.

Consequences, all of which invalidate earlier reasoning in this document:

- **Bit 27 was never "the blocker".** It opens dozens of times a day without a remote start.
  §8's whole premise — that satisfying bit 27 is what unlocks remote start — is wrong.
- **Depth 4 targets the wrong thing.** Driving a receiver-active flag cannot make the BCM believe a
  *remote-start command* arrived; at best it forges "a fob is talking".
- **The real discriminator must be the COMMAND CODE** (RKE enum 8, `(code & 0xF) == 8`), which is
  what actually separates remote-start from lock/unlock. Bit 27 merely says a code is being
  delivered; enum 8 says *which*.
- **The 1.686 s / 3.402 s totals measure fob transmission time**, not a remote-start window. Both
  earlier write-ups over-interpreted them.

⇒ This is AGENTS.md rule 22 in action: a one-line domain constraint from the user outranked a
chain of clean-looking static and bench measurements, all of which were individually correct and
collectively pointed the wrong way. The measurements were never wrong; the *interpretation* of what
bit 27 means was, and nothing in the static analysis could have corrected it.

⇒ **The right experiment needs no reflash:** hold a fob button (bit 27 open, receiver live) and fire
**depth 2** — which writes RKE enum 8 — inside that window. That combines the two halves the
firmware normally sees together. `336_fire_in_window.py` does exactly this.

---

## 1b. (superseded) The original bit-27 headline

`FUN_000ADADA`'s guard needs `(req94 >> 0x1B) & 7 == 7`. Watching that word at **50 Hz per cell**
while the operator performed a **real fob remote start** (LOCK, then RemoteStart ×2):

| value | gate3 | bit 27 |
|---|---|---|
| `0x34007FFF` | 6 | **0** |
| `0x3C007FFF` | **7** | **1** |
| `0x35807FFF` | 6 | 0 |
| `0x3D807FFF` | **7** | **1** |

**Bits 28 and 29 are always set; bit 27 (`0x08000000`) is the only dynamic bit.** Every null in this
investigation — 7 bench conditions, 2 vehicle depths — reduces to this one bit being 0.

### 1.1 It tracks the PRESS, not the running engine

Windows where `gate3 == 7`, in a 90 s capture:

| window | duration |
|---|---|
| 6.244 – 6.564 s | 0.320 s |
| 6.604 – 7.765 s | 1.161 s |
| 7.805 – 8.004 s | 0.199 s |
| **total** | **1.68 s of 90 s** |

Three bursts, matching **LOCK + RemoteStart ×2**. After 8.0 s bit 27 stayed 0 **for the rest of the
capture — while the remote start was actually running.**

⇒ Bit 27 is **not** a "remote start is active" flag. It is high only while the fob transmission is
being received/authenticated. This is why depth 2 failed: the command code was written correctly
and held, but bit 27 was 0, so the guard never evaluated it.

> ⚠ **Mechanism corrected in §7.5.** The *observation* above stands, but bit 27 is **not** an
> externally-driven input line. `FUN_000AD97C` sets it internally when a sub-state field equals 1
> **and** a flag byte at `0x400095E1` equals 1, then clears it after a 200-count hold. Read §7.5
> before building anything on the "RFA-sourced input" reading.

> ⚠ **Instrument note.** The first pass of the window analysis printed **3.36 s** across six
> windows. That was a regex matching both the live change-lines *and* the summary block, i.e. every
> window counted twice. Real figure: **1.68 s, three windows**. Caught before it was written down
> as fact — but it is exactly the class of error that becomes a "measurement" if unchecked.

### 1.2 The §8.1 base ambiguity is SETTLED (a)

`docs/bench_session_4.md` §8.1 left two candidate bases, preferring `0x400095EC` on weak grounds and
explicitly recording that a vehicle capture must peek **both**. Result over 8,996 samples:

| base | cell watched | distinct values | ever `gate3 == 7`? |
|---|---|---|---|
| **`0x400095EC`** (preferred) | `0x40009680` | **7** | **YES** |
| `0x400095D4` (alternative) |  `0x40009668` | 2 (`00000002`, `01010102`) | never — `gate3 = 0` throughout |

**`0x400095EC` is the correct base.** The alternative never reaches the value its own guard would
require, on the one occasion the feature genuinely fires.

---

## 2. Depth-by-depth results

| depth | wrote | landed? | effect |
|---|---|---|---|
| **1** arm | `lock_request_input=1`, `DAT_40008D75=1` | **YES** — `0x40008D74` reads `00010000` | none |
| **2** synthesise | `rke_command_code=0x1808`, valid | **YES** — held `20001808` ≥30 s | none |
| **3** force | not fired | — | — |

### 2.1 Depth 2 answers the §4.1 persistence question (a)

The design doc flagged as **unresolved** whether a written `APP_rke_command_code` would survive the
RKE decode path's next tick (option A) or need a second hook (option B). Measured: `0x40002DA0` held
`20001808` across four reads spanning ~30 s, then self-cleared to `20000000` some minutes later.
**Option A works; no second hook is needed.**

### 2.2 Depth 3 is pointless on this vehicle — do not fire it

`APP_power_mode` was observed at **4 while the car is merely LOCKED** and `0` when unlocked (§3).
Depth 3 writes 4. Firing it would write a value the cell already holds in the test condition, with
no observable and no interpretation.

---

## 3. ⚠ `APP_power_mode == 4` is NOT a remote-start discriminator on this vehicle

> **Superseded in part by §5.4** — a 120 s watch during a *running* remote start shows this cell
> constant at `0x04` throughout, so the lock-state story below is **one observation over-read as a
> rule**. What is solid: the value is not unique to remote start and does not move when it runs.

`docs/remote_start.md` §3 treats `APP_power_mode == 4` as *the* discriminator. On this vehicle:

| condition | `0x40001D85` |
|---|---|
| unlocked | `0x00` |
| **locked** | **`0x04`** |
| unlocked again | `0x00` |
| shortly after a real remote start was stopped | `0x00` |

The value follows **lock state**, reverses on unlock, and was `0` right after a genuine remote
start. A near-miss: `04` first appeared between two depth-1 fires, and the obvious reading was
"depth 1 worked". The lock/unlock falsifier refuted it in one step. **Value 4 is not unique to
remote start**, and §3's premise needs revisiting.

⚠ Not established: what `power_mode` reads *during* the active phase — the `--gate` run did not
watch it, and `0x80` never transmits while the car is locked and asleep (0 frames in two attempts),
so the wire could not corroborate. **This is the main gap left.**

---

## 4. Two instrument defects found on the vehicle

### 4.1 `293_did_read.py` ran `main()` on import (fixed)

It called `main()` unguarded at module level, so importing it for `read_did()` executed a full DID
probe **and parsed the importer's `sys.argv` as hex DIDs** — `305_rs_trigger.py state` died with
`invalid literal for int() with base 16: 'state'`. Fixed with `if __name__ == "__main__":`.

The symptom had been visible earlier: `302_stock_did_probe.py`'s output began with stray
`EEFA/EEFB/EEFD` rows — an unintended bus probe on every import. It was noticed and not chased.

### 4.2 ⚠ The trigger cave's DID echo was CORRUPT — `r5` is volatile (FIXED in §8.1)

```
726  03 22 DE 13        request
72E  04 62 DE 29 00     positive response -- echo should be DE 13
```

The cave carries the MAGIC in **`r5`** across `e_bl` calls to the response-append accessor. `r5` is a
**volatile** register (PPC EABI `r3`–`r12`), so the callee clobbers it: the first echo byte (`0xDE`,
computed before any call) survives, the second is garbage. **peek avoided this by holding its value
in a scratch RAM cell, not a register.**

`307_reg_safety.py`/`308_path_liveness.py` asked the right question of the wrong scope: they proved
`r5` is dead **in the enclosing DID-dispatch function**, which is true and irrelevant — the clobber
is by `FUN_00109916`, a *callee*, and neither scan looked inside calls. A third instance of
AGENTS.md rule 45: both controls passed while the subject sat outside the swept region.

**Consequence:** `read_did()` rejects replies whose echoed DID ≠ requested DID, so a **working
trigger reported "no response"** and nearly caused a deeper, more dangerous depth to be fired to
chase a failure that never happened. Worked around in `305_rs_trigger.py` with `raw_22()` (no echo
check). **The cave itself still needs the fix: keep the MAGIC in scratch RAM, e.g. `0x40011020`.**

---

## 4.3 ⚠ A cross-log TIMING claim that was not supported

The active-phase run started `candump` and the peek watcher as **two independently launched
processes**, so their clocks have an unknown offset. bit 27 fired at watcher-t≈3.2–5.2 s and the
`0x80` d5 activity sat at candump-t≈15.7–17.8 s; I initially read that as a ~12 s separation. **It
is not supportable** — the offset between the two logs is unknown. Each log's *internal*
conclusions stand (power_mode constant on peek; d2 constant on the wire); any *relative* timing
between them does not. `310_rs_diff.py` drives everything from one process for this reason.

---

## 5. DIFFERENTIAL SCAN — the real remote-start signature (a)

`310_rs_diff.py`, 71 cells over the `0x400095EC` state block, **4 passes per condition**, with
quiet **before and after** (rule 29/40), free-running cells rejected (rule 9) and `ERR` excluded.
0 transport errors in 16 passes.

| | |
|---|---|
| cells scanned | 71 |
| rejected free-running | 7 |
| rejected errored | 0 |
| **candidates** | **10** |

### 5.1 Three RUN TIMERS, all at the same rate

The cells first flagged "once only" are not sampling artifacts — they are **counters**:

| cell | offset | active sequence | delta/pass |
|---|---|---|---|
| `0x40009620` | **base+0x34** | `5334 → 55FA → 58C0 → 5B86` | **+710** |
| `0x40009658` | **base+0x6C** | `53B6 → 567C → 5942 → 5C08` | **+710** |
| `0x400095DC` | base−0x10 | `D6916 → D6650 → D638A → D60C4` | **−710** |

Two up, one down, identical rate, and **`00000000` in every quiet pass on both sides**.

This ties directly to the static analysis. `FUN_000AD97C` computes `(r31[0xc] − elapsed) / 60000`
— a **millisecond accumulator divided into minutes** — and `base+0x30` holds `0x1B7740` =
**30 minutes** (`bench_session_4.md` §8.1). `base+0x6C` is that accumulator, running only while the
engine runs, against a 30-minute cap: a **remote-start run-duration timer**.

⚠ **Not measured:** the tick frequency. The cells were sampled **once per pass**, so any rate here
is a figure *between* passes, not a verified tick rate. 710 counts per ~11.8 s pass = **60 counts/s**;
at 10 counts per tick that is **6 ticks/s ≈ 166 ms/tick**.

> ⚠ **Correction:** an earlier revision of this section read "710 counts per ~11.8 s implies ~60 Hz
> (~16.6 ms/tick)". That was an arithmetic error — 60 is **counts** per second, not ticks; dividing
> by the 10-per-tick step gives 6 Hz / 166 ms, a factor of 10 out.

### 5.1.1 ⚠ The units say milliseconds; the RATE says otherwise — unresolved

Two solid measurements that do not fit together, recorded rather than reconciled by assumption:

- **Value side (agrees).** `FUN_000AD97C` computes `remaining / 60000` into a byte. Measured
  `0x400095DC` = `0x0D6916` = **878,870**; `878870 / 60000` = **14**. The differential scan
  independently measured the byte at `0x400095E0` going `0x00 → 0x0E` = **14**. Exact match from
  two instruments sharing no assumptions — this is what confirms the struct layout (§5.1.2).
- **Rate side (contradicts).** The same cell fell by only **710 units per ~11.8 s of real time**
  (~2.1 "seconds" of countdown across 47 s of wall clock). A real-time millisecond counter would
  fall by ~11,800 per pass. It is **~17× too slow**.

Candidate explanations, **none tested**: a reduced-rate task while parked; the counter advancing
only under a condition not met throughout; or peek polling perturbing task scheduling. Until one is
demonstrated, **do not describe this struct as a wall-clock countdown** — the unit interpretation
rests on the `/60000` arithmetic and the matching minutes byte, not on observed elapsed time.

### 5.2 base+0x70 — a DEBOUNCE COUNTER, not a state enum (corrected)

| cell | offset | quiet | active |
|---|---|---|---|
| `0x400095E0` | base−0x0C | `00000001` | **`0E000001`** (held, all 4 passes) |
| **`0x4000965C`** | **base+0x70** | `00000000` | `0x0A` / `0` alternating |
| `0x40009678` | base+0x8C | `4A87E2E4` | `4B07E4E4` |

> ⚠ **I first called `base+0x70` a "state enum" and the best remote-start-active
> indicator. That was wrong, and the static trace refutes it.** `312_enum_values.py` walked back
> from all 6 writers (controls 2/2 PASS): five store a literal `0`, and the sole producer of the
> non-zero value is `0x0AD6FE se_addi r0,0xa` — **`+= 10`, not `= 10`**. It is a counter, and
> `0x0A` was merely its value at my sampling instants. The vehicle data said so too: it read
> `0x0A / 0 / 0x0A / 0` across four passes, which is increment-and-reset, not a latched state.
> I read a *plausible label* onto two samples instead of checking what wrote them.

`FUN_000AD6C6` is the only producer:

```c
if (DAT_40002F3C == 3) {                      // outer state gate
    if ((DAT_40009680 >> 0x17 & 9) == 1) {    // gate word, bits 23 and 26
        if (DAT_4000965C < DAT_400095F0)      // counter < limit (base+0x04)
            DAT_4000965C += 10;               // 10 per tick
        else { DAT_40003D04 = 0; DAT_40003B04 = 0; }   // expiry
    } else if ((DAT_40009680 >> 0x1A) & 1) {
        ... DAT_4000965C = 0;                 // reset
    }
}
```

`base+0x04` reads `0x50` = 80, so the limit is **8 ticks** — a short debounce, *not* the 30-minute
run limit at `base+0x30`.

**Two new gate terms fall out of this**, both in the same word as bit 27:
`(gate >> 0x17) & 9 == 1` (bits 23 and 26) and bit 26 for the reset arm — and an outer gate
`DAT_40002F3C == 3` that is not in the `0x400095EC` struct at all.

⚠ The run-timers of §5.1 remain the strongest *active* indicator; they are `0` in every quiet pass
and count monotonically only while the engine runs.

### 5.2.1 ⚠ TWO WRITER SCANS DISAGREED ON THE SAME CELL — both controls passed

`311_state_enum_writers.py` found **6** writers of `0x4000965C`
(`0x0AD700 0x0AD738 0x0AD762 0x0AE8D4 0x0AEB88 0x0AEBE0`).
`313_outer_gate.py`, run later on the same cell as its own control, found **3**
(missing `0x0AD738`, `0x0AEB88`, `0x0AEBE0`).

**Both scripts reported a PASSING positive control.** This is the fourth instance in this project
of AGENTS.md rule 17 — and the sharpest, because here a passing control did not merely fail to
protect against the blindness, it actively certified a scan that was missing **half** the writers.

Consequence, stated before any conclusion is drawn from it: `313`'s finding that `DAT_40002F3C`
has **2 writers storing literals 4 and 5** is a **LOWER BOUND**, not a census. The tempting
headline — *"the gate value 3 is never stored, so `FUN_000AD6C6`'s outer gate is unreachable"* —
**is not supported** by that scan and must not be recorded as a result.

What `313` does establish about `DAT_40002F3C`, independently of the writer count:

- it is accessed as a **struct field** at `+0x21C` and `+0xC` off several base registers, never as
  a bare absolute — so any absolute-reference scan is structurally blind to it (rule 30);
- it has **16 readers** spanning `0x04E…`–`0x0AD…`, i.e. it is a **shared mode byte** consumed
  across the whole application, not a private flag of the remote-start module.

Adjudication of the two scans, a complete writer/value census for `DAT_40002F3C`, and a bit-level
map of the gate word were delegated to three parallel subagents; results in
`work/rs-trigger/logs/subagent_*.md`, **independently re-verified** by
`330_verify_subagents.py` / `331_verify_writer3.py` (§7).

---

### 5.3 This confirms the base a THIRD time

`bench_session_4.md` §8.1 could not choose between `0x400095EC` and `0x400095D4`. Now settled three
independent ways: (1) only `0x400095EC`'s gate field ever reached 7; (2) the alternative never left
`gate3 = 0`; (3) its `+0x6C`/`+0x34` fields behave exactly as `FUN_000AD97C`'s decompile predicts,
against the `+0x30` = 30-minute limit.

### 5.4 ⇒ `remote_start.md` §3 needs revising

The whole investigation targeted `APP_power_mode == 4`. On this vehicle that cell is **constant
`0x04` before, during and after** a real remote start, and `0x80` d2 is constant `0x7D` on the wire
(5,915 frames). It is **not** the discriminator. The real signature is in the `0x400095EC` block:
a state enum at `+0x70` and run-timers at `+0x34`/`+0x6C`.

---

## 6. Next — a depth 4, derived from ground truth

The capture says the guard needs **bit 27 of `0x40009680` set** *simultaneously* with
`rke_command_code = 0x1808`. That is a new trigger candidate, derived from an observed success
rather than inferred:

```
depth 4:  *(u32*)0x40009680 |= 0x08000000     # the missing term
          *(u16*)0x40002DA2  = 0x1808         # enum 8
          *(u8 *)0x40003F53  = 1              # valid
```

⚠ Open questions before building it:
- bit 27 is held for **~1.2 s** by the real thing; a single write may be cleared by its producer
  before the periodic task samples it. May need to re-assert, or to write it from a periodic hook.
- **Who writes bit 27?** If it is a hardware/RFA-driven input, forcing it in RAM may be overwritten
  immediately. Trace its writers statically first — the same p-code/reference-manager pair used in
  `bench_session_3.md` §9.3.
- Fix the `r5` echo defect in the same rebuild.

**Cheapest next measurement (no rebuild):** one more fob remote start watching
`power_mode` + `0x40009680` + the hold timer `0x40009648`, with a `candump` running and the car
woken, to capture what the *active* phase looks like. §3's gap is the main unknown left.

---

## 7. Delegated analysis — verified, with one summary corrected

Three subagents ran in parallel. Their summaries are **self-reports**, so each load-bearing claim
was re-derived from the program before being accepted. Two confirmed, one refuted as stated.

| claim | source | verdict |
|---|---|---|
| `0x0ADA3E` sets bit 27 via `se_bseti r0,0x4` | sa-2 | ✅ confirmed — mask decodes to exactly `0x08000000` |
| the gate word has **44** store sites, not 33 | sa-2 | ✅ confirmed — my brief was short by 11 (`0x0AE9xx` block) |
| `0x113594` stores literal 3 to `DAT_40002F3C` | sa-1 **JSON** | ❌ **false** — `0x113594` is `e_lis r29,0x4000`, not a store |

### 7.1 ⚠ A subagent's SUMMARY contradicted its own REPORT — the report was right

sa-1's JSON named `0x113594`. Its markdown report named a completely different, and correct,
mechanism. **Verify the evidence, not the abstract.** The real writer:

```
0x1136D0  e_add16i r5,r30,0x21c   ; r30 = 0x40002D20  ->  r5 = 0x40002F3C
0x1136DA  e_bl 0x00113EA8         ; the POINTER is passed as an argument
   ... inside FUN_00113EA8 ...
0x113F4C  se_lbz r5,0xb(r7)       ; load a source byte
0x113F58  e_andi r7,r5,0x3        ; mask to 0..3
0x113F5E  se_stb r7,0x0(r6)       ; store THROUGH the pointer
```

`0x40002D20 + 0x21C` = **`0x40002F3C`** ✓, and the stored value is `src_byte & 3` — range **0..3**.

### 7.2 ⇒ **Value 3 IS reachable; the outer gate is NOT dead** (a)

This **reverses** what `313` implied. §5.2.1's caveat — that `313`'s "2 writers storing 4 and 5"
was a lower bound and must not be written up as "state 3 unreachable" — was correct, and this is
why that caveat mattered.

### 7.3 Four agreeing methods were all wrong — the sharpest rule-17 case yet

sa-1 ran five methods. **A (reference manager), B (base+disp sweep), C (p-code) and D (raw-binary
VLE decoder) all returned exactly 2 writers. All four were wrong.** Only **E**, a pointer-escape
census, found the third — and E *explains* the others' blindness rather than merely outvoting them:

| method | why it is blind here |
|---|---|
| reference manager | the store has **no absolute reference** |
| base+disp sweep | base `r6` is a **live-in argument**, unresolvable |
| p-code | pointer is a **function parameter** ⇒ no ram varnode (rule 44) |
| raw VLE decoder | the value is **computed**, not a literal |

> **Agreement is not corroboration when the methods share a failure mode.** Four independent
> instruments concurring on a null is exactly as suspect as one — if none of them models
> *address-taken, stored-through-a-parameter*. Add a pointer-escape pass before any "no writer"
> claim about a cell whose address could be passed to a callee.

sa-0 separately found that `313` was **not an independent instrument at all**: `311` reported the
**union** of a reference-manager pass and a sweep pass, while `313` implements only the sweep.
So the "two scans disagree" framing in §5.2.1 was wrong — it was one instrument versus its own
weaker arm. Its blindness is exact: `0x0AEB88` is in an unswept block (never visited);
`0x0AD738`'s base `r31` is defined 30 instructions *before* its 16-byte function body;
`0x0AEBE0`'s base is defined before its function starts.

**And the control passed anyway** — because it OR'd across arms and asserted only `> 0`. On the
control cell the sweep arm found **1 of 5** stores and still printed PASS. ⇒ evaluate a control
**per arm**, assert an **expected count** not `> 0`, and include a control site in an unswept block.

### 7.4 Two precise trigger targets (unvalidated)

| bit | sole bit-specific setter | guard |
|---|---|---|
| **27** (`0x08000000`) | `0x0ADA3E` in `FUN_000AD97C` | `((DAT_4000967C >> 0x1A) & 3) == 1` **and** `DAT_400095E1 == 1` |
| **23** (`0x00800000`) | `0x0AE948` in `FUN_000AE922` | `((DAT_40009678 >> 9) & 3) == 1` **and** `VOL_test_and_clear_dirty(&DAT_40003FF1, 2) == 1` |

Bit 27's clearer is `0x0ADA78` in the same function, firing when the `+0x90` sub-state ≠ 1 and a
~200 ms hold counter at `base+0x86` reaches 200 — consistent with the **1.686 s** observed window.

### 7.5 `FUN_000AD97C` decompiled — bit 27 is INTERNAL, and the lever is two RAM cells (a)

The decisive result. `r31 = 0x400095EC`, `r31[0x24]` = `+0x90` = `0x4000967C`,
`r31[0x25]` = `+0x94` = `0x40009680`:

```c
sub = (*0x4000967C >> 0x1A) & 3;          // 2-bit sub-state
if (sub == 1) {
    if (*(char *)(param_1 + 5) == 1) {    // <<< THE INPUT FLAG
        *0x4000967C = (*0x4000967C & 0xF3FFFFFF) | 0x08000000;   // sub -> 2
        *0x40009680 |= 0x08000000;        // *** SET BIT 27 ***
    }
    counter@+0x86 += 10;
} else {
    if (sub == 2 && counter@+0x86 < 200) goto keep_counting;
    *0x4000967C = (*0x4000967C & 0xF3FFFFFF) | 0x04000000;       // sub -> 1
    *0x40009680 &= 0xF7FFFFFF;            // CLEAR BIT 27
    *0x40009648 = 0;  counter@+0x86 = 0;
}
```

**Bit 27 is not an external/RFA input written from outside.** It is set by *this* function when two
plain-RAM conditions hold:

1. sub-state `(*0x4000967C >> 0x1A) & 3 == 1`
2. flag byte `*(param_1 + 5) == 1`

That corrects the §1.1 reading ("an input asserted only while the fob transmission is received").
The *observation* stands — bit 27 really is high for only ~1.7 s — but the **mechanism** is an
internal two-state machine with a 200-count hold, not a directly-driven input line.

### 7.5.1 `param_1` resolved to `0x400095DC` by cross-instrument agreement (a)

The decompile says `param_1` is a small struct: `+0` = remaining ms, `+4` = remaining **minutes**
(`= *param_1 / 60000`), `+5` = the bit-27 flag. If `param_1 = 0x400095DC` then `+4` = `0x400095E0`
and `+5` = `0x400095E1`.

| | |
|---|---|
| `0x400095DC` measured (§5.1) | `0x0D6916` = 878,870 → `/60000` = **14** |
| `0x400095E0` byte measured (§5.2) | `0x00` → **`0x0E` = 14** |

**Exact match.** The differential scan knew nothing of this decompile and vice versa, so
`param_1 = 0x400095DC` is *derived*, not assumed — and `0x400095E1` is the flag gating bit 27.

**And now PROVEN from the call path** (`333_param1_fallthrough.py`). `param_1` is a genuine
function parameter, so the arithmetic match alone was suggestive rather than conclusive. A first
attempt (`332`) asked the reference manager for callers and got **zero** — which is the documented
*signature of a sweep-split block*, not a negative (rules 19/44), exactly as for `0x0ADADA` /
`0x0ADB1E` / `0x0ADE12`. Walking backward by **byte-adjacency** instead:

```
0x0AD888  e_lis    r3,0x4001
0x0AD88C  e_add16i r3,r3,-0x6A24      ->  r3 = 0x400095DC
   ... fallthrough ...
0x0AD97C  FUN_000AD97C entry          ->  param_1 = r3 = 0x400095DC   ✓
```

**Control PASS:** the same walker reproduced the documented `r7 = 0x40002D20` binding at `0x0ADE12`
(`remote_start.md` §7.0.3), so its positive result here is trustworthy and its method is the one
that works on this module.

⇒ `param_1 = 0x400095DC` is established **three independent ways**: the `/60000` arithmetic, the
measured minutes byte, and the caller's register setup. `0x400095E1` = `param_1 + 5` is the
bit-27 flag.

Consistency check: `0x400095E1` read `0x00` during the active phase, which is **correct** — bit 27
was also 0 then, since it only fires in the ~1.7 s press window. The flag is transient, like the bit.

⚠ Timing is only **coherent, not proven**: 200 counts at 10/tick = 20 ticks, and the observed
1.686 s window over 20 ticks gives ~84 ms/tick. That is the same order as §5.1.1's independently
derived ~166 ms/tick but **not equal to it**, and §5.1.1's rate anomaly is unresolved. Do not treat
either figure as the task period.

### 7.6 ⇒ The depth-4 target, restated

Forcing bit 27 directly means fighting 44 writers including this function's own clear arm. The
better lever is the pair this function itself reads:

```
*(u32*)0x4000967C = (*0x4000967C & 0xF3FFFFFF) | 0x04000000   // sub-state = 1
*(u8 *)0x400095E1 = 1                                          // the flag
```

`FUN_000AD97C` then sets bit 27 **itself**, through the legitimate path, and clears it on its own
schedule — no fighting, no desynchronisation of the other bits sharing the word.

⚠ Untested. Both cells have their own producers that may overwrite within a tick; the write must
land in the window where this function next runs. This is a hypothesis to test, not a design to
trust.

⚠ `base+0x88` cycled `1414 / 0A0A / 0000 / 1E14` with no clean pattern — **unresolved**, recorded
rather than explained.

---

## 8. Depth 4 — built and verified (not yet flashed)

| | |
|---|---|
| artifact | `work/rs-trigger/JV6T-14C094-AD_peek-rstrigger.VBF` |
| sha256 | `3682bae78a0a381949da291ea5ef3dd0d3b84c78da9c31a4348ccbb063c44291` |
| DID | **`0xDE38`** (probed free on hardware alongside the other three) |
| cave | `0x119000`, now **416** bytes, 108 instructions |

Depth 4 implements §7.6: set the two preconditions `FUN_000AD97C` itself reads, and let the
firmware raise bit 27 through its own legitimate path.

```asm
e_lwz  r3,0x0(r4)   ; r4 = 0x4000967C
se_and r3,r5        ; & 0xF3FFFFFF      <- the firmware's own KEEP mask
se_or  r3,r5        ; | 0x04000000      <- sub-state = 1
e_stw  r3,0x0(r4)
e_stb  r3,0x0(r4)   ; r4 = 0x400095E1   <- flag = 1
```

**Simulation against the measured vehicle value:** `0x30007FFF → 0x34007FFF`, which is a value
**actually observed on the car**, with `(>>26)&3 = 1` — exactly what the guard requires. Bit 27 is
never written by us.

### 8.1 The `r5` echo defect is fixed

The MAGIC now lives in scratch RAM `0x40011020` instead of a volatile register, so replies echo
correctly (§4.2) and `read_did()` no longer reports "no response" for a working trigger.

### 8.2 ⚠ Three checkers went stale in one build — see AGENTS.md rule 50

Adding one depth broke three checks, all by hand-copied expectations:

| checker | stale thing | failure mode |
|---|---|---|
| `304` V1 | 5 hard-coded target names | **loud** — 3 correct stores flagged undeclared |
| `304` V3 | `FREE_MAGICS` missing `0xDE38` | **loud** |
| `306` | `(0x119000, **298**)` vs the real **416** | ⚠ **SILENT** — checked 298 bytes, printed CLEAN, left 118 unexamined |

All three now derive from the build's own JSON. V1 was additionally fixed **upward** with **V1b**,
which asserts the depth-4 cells are genuinely written — so a build that silently drops them fails.

### 8.3 Final gate status

| check | result |
|---|---|
| CRC-16 ×2, CRC-32, internal sum8 | PASS |
| diff vs OEM: 4 clusters, exact spans | PASS (834 bytes) |
| V1 / **V1b** / V2 / V3 / V4 | PASS (19 stores, 0 undeclared) |
| `306` project clean, full 416 bytes | PASS |
| `bcmflash verify` | ALL CRCs OK |

Flash with the commands in `rs_trigger_design.md` §6.2, then on the vehicle:

```bash
python3 work/rs-trigger/305_rs_trigger.py accept
python3 work/rs-trigger/305_rs_trigger.py fire 4
```

**What to watch:** `0x40009680` — if bit 27 goes high *on its own* after the trigger, the lever
works and the guard's blocking term is satisfiable from CAN. `fire` prints the state at
+0.2 / 1 / 3 s automatically; the `0x4000967C` and `0x400095E0` cells are now in the default watch
set so the write itself is visible.

### 8.4 ⚠ VEHICLE TEST — depth 4 does NOT work, and it killed my own claim (a)

Fired on the vehicle. The cave **ran** (scratch `0x40011020` = `0000DE38`, and the reply was
served), so execution is not in doubt. Result:

| cell | depth 4 writes | reads back after |
|---|---|---|
| `0x4000967C` sub-state | bits[26:27] = 1 | `(>>26)&3 = 1` |
| `0x400095E1` flag | 1 | **`0x00`** within 10 ms |
| `0x40009672` hold counter | — | **`0x00`** |
| `0x40009680` bit 27 | — | **0** |

**First reading (WRONG, recorded per the retraction rule): "the sub-state write works, only the
flag loses a race."** A falsifier refuted it immediately — sampling `0x4000967C` 60× over 6 s with
**no trigger fired** gives `sub = 1` in **60/60** samples. The cell is *permanently* 1. Writing 1 to
a cell that is always 1 is a **no-op that reads back as success** — AGENTS.md rule 8, and I had
taken no pre-fire baseline, which is the only thing that would have caught it.

**What the same measurement actually proves — `FUN_000AD97C` IS NOT EXECUTING.** The decompiled body
is:

```c
if (sub == 1) { if (flag == 1) { ...set bit 27... }  counter += 10; }
```

`sub == 1` is true *right now*. So if the function ran at all, `counter` would climb **regardless of
the flag**. It is pinned at `0x00`. Therefore the function is not being called.

This independently corroborates §5's observation that the hold timer `0x40009648` never ticked
during a genuine fob remote start — same conclusion (this code region is dormant), reached from a
different direction, on a different cell.

⇒ **The planned fix — set the flag from a periodic hook so it is fresh when the guard reads it —
would also have failed.** A fresh flag is worthless if nothing reads it. The falsifier cost one
command and saved a full rebuild-and-reflash cycle.

### 8.5 ⚠⚠ §8.4 IS REFUTED — the function DOES run; it is dormant only when IDLE (a)

`309_rs_watch.py --falsify` during a **real fob remote start** (log
`work/rs-trigger/logs/rs_falsify.log`, 40.7 s, 1,488 events) overturns §8.4 completely.

| cell | §8.4 said (idle car) | real fob start |
|---|---|---|
| counter `0x40009670` +0x86 | pinned `0` | **120 changes, 15 values** |
| flag `0x400095E1` | never 1 | **reaches `0x01` twice** (t=11.971, t=12.213) |
| bit 27 | 0 | **7 windows, 3.402 s total** |

**The counter behaves exactly as the decompile predicts.** It advances in steps of **10** —
`10, 40, 70, 100, 130, 160, 190` — which is `counter += 10` sampled at ~9 Hz against a faster tick,
and it **wraps at exactly 200**:

```
t=12.144  counter=170
t=12.171  counter=200      <- the hold limit in the decompile
t=12.206  counter=  0      <- reset
```

A stronger confirmation than the guard analysis itself: the *value*, the *step*, and the *limit* all
match the disassembly independently.

⇒ **My §8.4 conclusion "the function is never called" was wrong, and the error was the scope of the
measurement, not the reasoning.** The inference ("if it ran, the counter would tick regardless of the
flag") is valid. It was applied to an **idle** car, where the path is genuinely dormant, and then
stated as an unqualified property of the firmware. This is AGENTS.md rule 43 — a measurement in one
condition promoted to a behavioural claim about all conditions.

⇒ **Depth 4 has therefore never had a fair test.** It was fired while the path was dormant, so
flag=0 / bit27=0 afterwards says nothing about whether the mechanism works. `335_fire_when_live.py`
retests it properly: it requires the counter to be *moving* (positive control) before it fires, and
reports INCONCLUSIVE rather than a negative if the path is asleep.

⚠ Note also: **7 windows / 3.402 s here vs 3–4 windows / 1.686 s previously.** The earlier figure
was called "reproduced to the millisecond"; it is now clear that total is **a property of the
particular fob sequence**, not a constant of the mechanism. Treat the 1.686 s as one observation,
not a signature.

**The flag reaching `0x01` on its own is the other key result** — `0x400095E1` has a real producer,
active during a fob start. Depth 4 writes the same cell, so the question is purely whether our write
lands inside the window where the function next reads it.

---

## 9. `336` — enum 8 injected inside a held-button window: NO START, and why (a)

Per §1, the fob supplies the half we cannot forge (bit 27) while depth 2 supplies enum 8. Run with
the **lock** button held. Control passed — bit 27 open at t=2.940.

```
t=0.051  rke=00001808   <- OUR depth-2 write, enum 8
t=0.191  rke=00001D31   <- the FOB's own lock code, enum 1
t=0.680  rke=00001D51
t=1.100  rke=00001D91   ... continuing for the full 10 s
```

**The write landed and was overwritten after ~140 ms.** Our value was *correct* —
`remote_start.md` §1 confirms enum 8 arrives as `0x1808`/`0x1818` in real captures, and low nibble
8 vs the fob's 1 is exactly the documented encoding. The failure is **timing**, not content.

⇒ **The experiment was self-defeating by construction.** Holding a button is what opens bit 27, but
the *same* transmission floods `APP_rke_command_code` at ~7 Hz, erasing enum 8 long before
`FUN_000ADADA` next reads it. The two halves the firmware sees together are delivered by **one
channel**, and that channel overwrites us. A held button can never be the carrier.

⇒ Two things this run *did* settle, both for free:
- **bit 27 stayed 1 for the entire 10 s of holding**, and the counter kept advancing — independently
  re-confirming §8.5 and burying §8.4's "never called" for the second time.
- **`power_mode` is a dead observable**: constant `0x04` throughout, as §3 found during a *genuine*
  start. Success must be measured on the **run timers** (§5.1), which advance only while the engine
  actually runs.

### 9.2 `338` — the lifetime measurement, and THREE retractions (a)

Run with a single-cell poll (9 ms resolution instead of 145 ms). Result: **enum 8 is resident in
40/40 samples in all three trials**, trials 2 and 3 began with `pre=00001808` (our value from the
*previous* trial still there), and a follow-up read minutes later still shows `0x00001808`.

**Retraction 1 — the "140 ms lifetime" was my sampler.** `336` and `337` both reported the write
"gone after 140 ms", identical to the millisecond, because `snap()` read **five** cells per loop
(5 × ~25 ms UDS round trip + 20 ms sleep ≈ 145 ms). I published my own loop period as a firmware
property. AGENTS.md rule 26: a suspiciously round, repeated delta is a shared cadence until proven
otherwise — and I had just written that rule.

**Retraction 2 — there is no "periodic clearer".** §9.1 inferred one from `337`'s
`rke → 0x00000000` with nothing transmitting. The cell in fact holds our value **indefinitely**;
that zero was fob-driven, not a periodic sweep. The inference came from two samples of a
145 ms-resolution instrument.

**Retraction 3 — "the fob overwrites us" is not the obstacle either.** It happens (§9), but it is
irrelevant: with no fob activity the value persists for minutes and **still nothing starts**.

⇒ **The real finding: the consumer is EDGE-triggered, not level-triggered.** `APP_rke_command_code`
holds enum 8 permanently, `0x40003F53` reads valid, and no remote start occurs. A level in the cell
is not what the firmware acts on — it acts on the *arrival* of a command. This is precisely the
lesson `rke-lock` learned on the wire (`docs/key_outside_gate.md`, AGENTS.md §0: *"a command bit can
be a one-shot strobe not a level"*), now reproduced from the RAM side.

⇒ The missing piece is the **dirty/new-command flag** that the codec sets when a frame arrives and
the consumer test-and-clears. §7's bit-23 analysis already surfaced the mechanism by name:
`VOL_test_and_clear_dirty(&DAT_40003FF1, 2) == 1`. Depth 2 writes the *value* but never announces
it, so no consumer ever looks.

⇒ **Next: depth 5** — write the code **and** set its dirty flag, so the arrival is signalled. That
needs the flag's address and bit derived first (`339`), then a cave rebuild and reflash.

---

## 10. THE ANSWER — the announce byte, verified 7/7 from the artifact (a)

Two subagents (`deleg_36d92c6f`) converged on the same mechanism from different directions. Per
rule 47 (*agreement is corroboration only if the methods fail independently* — and these two shared
a brief and a codebase), every load-bearing claim was re-derived locally by `352_verify_dirty.py`.

### 10.1 The announce pair in `APP_rke_code_commit`

```asm
0x058564  e_bl 0x000fbb38      ; VOL_sig_get16 -> r3 = the command code
0x058568  se_bmaski r0,0x8     ; r0 = 0xFF
0x05856A  e_stb r0,0x51(r30)   ; 0x40003F53 = 0xFF   <-- ANNOUNCE
0x05856E  e_sth r3,0x82(r31)   ; 0x40002DA2 = code   <-- VALUE
```

`r30 = 0x40003F02` (`e_lis`+`e_add16i` at `0x058542`/`0x05854A`), so `+0x51` = **`0x40003F53`**;
`r31 = 0x40002D20`, so `+0x82` = **`0x40002DA2`**. Both bases are built inside the same function —
no cross-function register leak.

### 10.2 The consumer reads a bit our write never set

```asm
0x0AEECC  e_lis    r29,0x4000
0x0AEED0  e_add16i r29,r29,0x3f02
0x0AEED4  e_addi   r3,r29,0x51     ; -> 0x40003F53
0x0AEED8  se_li    r4,0x2          ; n=2
0x0AEEDA  e_bl     VOL_test_and_clear_dirty
```

`VOL_test_and_clear_dirty(p, n)` tests mask `0x80 >> n` (the helper's `se_srw`/`e_rlwinm` pair at
`0x031366`/`0x031378` was confirmed present). So the remote-start consumer tests **mask `0x20`**.
The only other consumer image-wide is `0x099308` with `n=1` (mask `0x40`), an RKE one-hot demux.

**Depth 2 wrote `0x01` = bit index 7. `0x01 & 0x20 == 0`.** No consumer reads that bit — which is
exactly why §9.2 saw the command code persist for minutes with nothing happening. The value was
right, the *announcement* was to a bit nobody listens on.

| verification (`352`) | result |
|---|---|
| C1 `0x05856A` is a byte store | PASS |
| C1b/C1c value is `se_bmaski r0,0x8` = **`0xFF`** | PASS |
| C2 `0x05856E` stores the 16-bit code | PASS |
| C3 helper builds a shifted mask | PASS |
| C4 `0x0AEEDA` passes **n=2** | PASS |
| C5 `0x099308` passes n=1 (not RS) | PASS |
| C6 `0x0ADA3C` `se_bseti` regression | PASS |

⚠ `352`'s first run reported **C1b FAIL** — my hard-coded guess `0x058566` has no instruction
boundary there (the value load is at `0x058568`). The *checker* was wrong, not the claim: fixed by
walking real instruction boundaries instead of guessing an address (rule 50 again, fourth instance).

### 10.3 Depth 5 — built, verified, awaiting a bench flash

| | |
|---|---|
| artifact | `JV6T-14C094-AD_peek-rstrigger.VBF` |
| sha256 | `0867e7008ee74830904e76ae7a0b6d3e0e0ebc54bf655414971c9e2bea34f8ab` |
| DID | **`0xDE4A`** (in the hardware-probed free set; `0xDE44`, the first pick, was **not**) |
| cave | `0x119000`, **482** bytes, 125 instructions |

Writes `0x40003F53 = 0xFF` **then** `0x40002DA2 = 0x1808`, in the receive path's own order.

**Depth 2 is deliberately left broken** as the contrast arm: identical command code, wrong announce.
One experiment then distinguishes "the code is wrong" from "the announce is wrong".

New check **V1c** asserts the announce writes `0xFF` — reported `values stored to 0x40003f53:
[1, 255]`, i.e. depth 2's `1` and depth 5's `255`, both present as designed. Without it a regression
to `1` would pass V1 silently.

⚠ **Not proven: sufficiency.** `0x0ADA24` is only reached when `(0x4000967C >> 26) & 3 == 1` and the
enum-8 test also holds. The flag is a demonstrated **necessary** piece; whether it is **sufficient**
is what the bench run decides.

⚠ **Bench scope (rule 43, and the user's own earlier correction):** bench #1 cannot reach
ignition-ON, so it can confirm the RAM chain `0x0AEEDA → 0x4000968B → 0x400095E1 → 0x0ADA24 →
0x0ADA3E → bit 27` advances, and **cannot** show an engine crank. A null on the chain is
informative; a null on cranking would not be.

---

## 11. BENCH RESULT — the announce byte is CONFIRMED, 2/2 vs 0/2 (a)

Bench #1 (`ident`: serial `009640039386`, HW `DV6T-14C245-FF`, PBL V013, app `JV6T-14C094-AD`),
flashed with the depth-5 build. `accept` ALL PASS. `354_depth5_vs_depth2.py --both-orders`:

| arm | announce written | bit 27 high | flag `0x400095E1` | chain |
|---|---|---|---|---|
| depth 2 (pass 1) | `0x01` | 0 samples | `0x00` | did not advance |
| depth 5 (pass 1) | `0xFF` | **10 samples** | **`0x01`** | **ADVANCED** |
| depth 5 (pass 2) | `0xFF` | **10 samples** | **`0x01`** | **ADVANCED** |
| depth 2 (pass 2) | `0x01` | 0 samples | `0x00` | did not advance |

**depth 5: 2/2. depth 2: 0/2.** Both orders run, so this is not an ordering or leftover-state
artifact. Both arms write the **identical** command code `0x1808`; the *only* varied factor is the
announce byte. The command code is therefore exonerated and the announce is the mechanism.

### 11.1 The read-back proves CONSUMPTION, not merely a write

Depth 5 writes `0xFF`; reading the byte straight afterwards gives **`0x9F`**:

```
wrote   0xFF = 1111 1111
read    0x9F = 1001 1111
cleared 0x60 = 0110 0000   -> Volcano indices 1 and 2
```

Exactly two bits were cleared, and they are exactly the two consumers the static analysis predicted:
`n=1` (mask `0x40`, the RKE one-hot demux at `0x099308`) and **`n=2` (mask `0x20`, the remote-start
consumer at `0x0AEEDA`)**. Each test-and-cleared its own bit. That is a far stronger result than
"the chain moved" — the firmware *told us* which call sites read our announcement, and they match
the prediction with no extras. Depth 2's `0x01` is returned untouched (`0x01 → 0x01`), because
nobody listens on index 7.

This closes §9.2's question completely: the code persisted for minutes and nothing fired because
**no consumer was ever told it had arrived**.

### 11.2 What is now proven, and what is not

**Proven (a):** the announce byte `0x40003F53` with mask `0x20` is necessary, is consumed by
`0x0AEEDA`, drives `0x400095E1 → 0x01`, and raises **bit 27 of `0x40009680`** — the full static
chain of §7 and §10, reproduced on hardware by injection alone, with a matched negative control.

**Not proven:** that this produces an engine start. Bench #1 cannot reach ignition-ON (§6.4), so the
chain is confirmed and the *outcome* is not. `0x4000968B` stayed `0x00` in all four arms, which on a
bench with no ignition is expected rather than contradictory — but it is an open item, not a detail
to wave through.

⇒ **Next on the vehicle:** flash this same build and fire depth 5. Success criterion is the **run
timers** (§5.1), not `power_mode` (§3 refuted it). The bench cannot answer it.
