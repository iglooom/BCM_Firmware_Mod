# `rs-trigger` — firmware mod to trigger remote-start from CAN, by DID

**Status: BUILT AND VERIFIED. Not yet flashed, not yet tested on a vehicle.**

| | |
|---|---|
| artifact | `work/rs-trigger/JV6T-14C094-AD_peek-rstrigger.VBF` |
| sha256 | `1148017e9cc9d6c12c6d18fca47d824d182f703edd4e9331b360c9d22826ace8` |
| contents | stock app + `peek` (read-only debug) + `rs-trigger` (3 depths) |
| verification | `304_verify.py` — **all checks pass** (§6) |

Every address here is derived from this repo's evidence and re-asserted at build time; nothing is
assumed.

Purpose: enter the remote-start mode (`APP_power_mode = 4`) on demand from a diagnostic tool, on a
**real vehicle**, where the bench's structural blockers (no ignition-ON, no PCM, no
vehicle context — `bench_session_4.md` §6.4) do not apply.

Operator decisions taken (recorded so they are not silently revisited):

| decision | choice |
|---|---|
| trigger depth | **all three, on separate DIDs**, used shallow→deep on the car |
| abort DID | **not built** — ignition/key-off ends a remote start |
| include `peek` | **yes** — live readback is what makes a null interpretable |

---

## 1. ⚠ Safety — read before flashing

This mod **starts an engine from a CAN message**. That is its purpose, and it is genuinely
dangerous in a way none of this project's previous mods were (`acc-fix` rewrote a TX byte;
`peek` is read-only).

- **Vehicle in open air, in PARK, parking brake set, nobody under the bonnet.** A remote start
  cranks the engine and may spin cooling fans.
- **Depth 3 deliberately bypasses the firmware's own interlocks.** `FUN_00087486` normally reaches
  the mode-4 store only after its guards; depth 3 writes the cell directly. If the PCM's own
  interlocks (gear position, brake, immobiliser) are the only remaining protection, depth 3 leans
  entirely on them. **Use depth 1 first, then 2, and only use 3 if both are refuted.**
- There is **no abort DID** by operator choice. Ending a remote start is: turn ignition on, or
  key-off/exit. Confirm you can do that *before* you send a trigger.
- Worst realistic failure remains a no-op (a guard we do not know about refuses), **provided all
  three integrity layers are repaired** (AGENTS.md rule 2). A missed integrity layer bricks the
  BCM into safe mode — that risk is unchanged from every other mod here and is handled by
  `build_vbf.py`/`verify.py`.
- **Do not leave this build on a customer/daily vehicle.** It is a test instrument: any tool that
  can send `0x22` on HS-CAN can start the engine.

---

## 2. The three candidates, and why these

From `docs/remote_start.md` and `docs/bench_session_4.md`. Each depth targets a different point on
the one chain, so a failure at one depth *localises* the blocker rather than just failing.

```
 RKE enum 8  ──►  FUN_000ADADA guard  ──►  ...  ──►  FUN_00087486  ──►  APP_power_mode = 4
 (depth 2)        (req94 state==7)              (lock_request_input==1,   (depth 3)
                                                 DAT_40008D75 != 0)
                                                      ▲
                                                  (depth 1)
```

### Depth 1 — arm the state machine's inputs (safest, most informative)

`FUN_00087486`'s mode-4 arm requires **both**:

```c
if (DAT_40008D75 != 0) {                    // arming flag
    if (APP_lock_request_input == 1) {      // 0x40008D2C
        ... APP_power_mode = 4 ...
```

Depth 1 writes `APP_lock_request_input = 1` and `DAT_40008D75 = 1`, then **lets the stock periodic
state machine run its own checks**. Every interlock the firmware has still applies.

This is also the cell with the most history in this project: `0x40008D2C` is the lock-chain input
(`tx_pack_stage.md` §9), it has a documented writer at `0x9749A` found only by p-code (rule 14),
and `bench_session_3.md` §4 measured it rising 11× under RKE stimulus against 0 in a matched idle
window. It is on the path on the *real* vehicle, by measurement.

> ⚠ Depth 1 is a **hypothesis test**, not a guarantee. `DAT_40008D75`'s role as the arming latch is
> confidence **(c)** in `remote_start.md` §6 — "most likely 'two presses required' latch" — and has
> never been confirmed. If depth 1 does nothing, that is a real result about this cell.

### Depth 2 — synthesise the RKE command (the honest reproduction)

Writes `APP_rke_command_code` (`0x40002DA2`, halfword) = `0x1808` — the exact value the bench
measured when a real enum-8 frame arrived (`bench_session_4.md` §4.2) — plus the validity flag
`0x40003F53`, and holds it for a few periodic ticks so `FUN_000ADADA`'s **debounce timer**
(`+10` per 10 ms tick against the `+0x20` limit) can accumulate.

This is the closest thing to "press the button" that does not involve RF. Every downstream guard —
including the `(req94 >> 27) & 7 == 7` state term that blocks on the bench — still runs.

> ⚠ **Depth 2 is the one most likely to expose the bench-vs-vehicle difference**, because that
> state term is exactly what reads 6 on the bench and must read 7 for the guard to pass
> (`bench_session_4.md` §8.2). If depth 2 works on the car and not on the bench, that term is
> confirmed as the vehicle-context gate.

### Depth 3 — force the mode (most forceful, least informative)

Writes `APP_power_mode` (`0x40001D85`) = 4 and sets the three dirty flags
`0x40003EB6/B7/B8 = 0xFF`, reproducing `FUN_00087486`'s own epilogue so `APP_tx_compose` emits the
new mode on `0x80` d2 at the next tick.

This will make the **BCM announce remote-start on the bus** regardless of whether the BCM's own
preconditions hold. Whether the *engine* starts then depends on the PCM believing the announcement.

> ⚠ Depth 3 proves the least: a success means "the BCM's TX path works", which we already know. Its
> value is as a **positive control for depths 1 and 2** — if 3 announces mode 4 on `0x80` d2 and
> 1/2 do not, the blocker is upstream in the BCM, not in the announcement path.

---

## 3. Wire format

Reuses `peek`'s proven carrier (`peek_tool.md` §7 step 2 — the address-as-two-synthetic-DIDs form,
because the stock handler **loops** over DID pairs and rejects trailing bytes with `0x31`).

```
request :  22 <MAGIC>            (3 bytes, one CAN frame)
response:  62 <MAGIC> <status>   status: 00 = applied, EE = refused
```

| DID | depth | action |
|---|---|---|
| `0xDE13` | 1 | `APP_lock_request_input = 1`, `DAT_40008D75 = 1` |
| `0xDE16` | 2 | `APP_rke_command_code = 0x1808`, valid flag set, hold N ticks |
| `0xDE2C` | 3 | `APP_power_mode = 4`, dirty flags `0xFF` |

MAGIC selection (`300_prereq.py` P1): each candidate occurs **0 times** as a 2-byte pattern in the
whole 1.4 MB image, against a **control** (`0x0631`, a DID known present) that occurs 22 times —
so "absent" is a real measurement, not a vacuous one (rule 9).

**Step 2 (rule 35) is DONE and PASSED on hardware** — `302_stock_did_probe.py`, bench #1:

| probe | result |
|---|---|
| C1 `F188` | `JV6T-14C094-AD` → **PASS** (transport alive; without this every refusal below is inconclusive) |
| C2 `22 DEAD 000D E278` | `70E8E000` → **peek build present** |
| `0xDE13` `0xDE16` `0xDE2C` `0xDE38` `0xDE4A` `0xDE4C` | all `NRC 0x31` → **all FREE** |

> ⚠ **The C2 control caught a bug in itself, and it is worth recording.** The first version probed
> a bare `22 DEAD` and got `NRC 0x31`, which it reported as *"not served (stock unit)"* — a
> plausible, wrong conclusion about the **BCM**. A bare `22 DEAD` is not peek's wire format: peek
> needs its address as two synthetic DIDs. `peek_read.py read 000DE278` answered correctly the
> whole time. Fixed by probing the **real format against known truth**. This is rule 27 in a new
> place: the instrument was misconfigured, and its output was about the instrument, not the
> subject — and it would have gone in the notes as a fact about the unit.

---

## 4. Structure — one cave, chained onto peek's hook

`peek` already hooks `0x0010B764` (`e_cmpli cr0,r26,0xee00`, OEM bytes `189AA9EE`, re-verified by
`300_prereq.py` P2 as still matching what peek recorded). **We do not add a second hook.** The
trigger cave is entered from peek's `NOTMAGIC` path, so:

```
 0x10B764 ──e_b──► peek cave 0x118000
                     ├─ DID == 0xDEAD ? ──► peek (read 4 bytes)
                     └─ else ──► rs cave 0x119000
                                   ├─ DID == 0xDE13 ? ──► depth 1
                                   ├─ DID == 0xDE16 ? ──► depth 2
                                   ├─ DID == 0xDE2C ? ──► depth 3
                                   └─ else ──► replay e_cmpli, e_b 0x10B768  (stock)
```

One hook, one displaced instruction, one rejoin — the structure `acc-fix` and `rke-lock` already
share (AGENTS.md §7: "layered into the same caves, no new hook").

| resource | value | clear of |
|---|---|---|
| cave | `0x119000` | acc-fix `0x117100`/`0x117300`, peek `0x118000..0x1181B6` |
| scratch | `0x40011020..0x4001102F` | acc-fix `0x40011000`, rke-lock `0x40011001`, peek `0x40011010..13` |

Cave sits inside the `0x1170F3` padding run (167,661 bytes free, `300_prereq.py` P3) so it is
**inside the `sum8`-covered region** (AGENTS.md §7, last bullet).

### 4.1 Depth 2 needs persistence — the tick-hold problem

A single `0x22` request runs once, but `FUN_000ADADA`'s debounce needs the command **present across
several 10 ms ticks**. Two options:

- **(A) Latch + let the periodic task see it.** Write the command code and a scratch counter; the
  stock periodic reader sees the cell on each tick, exactly as it would for a real frame. Requires
  nothing extra **if** no other writer clears the cell between ticks.
- **(B) Second hook on the periodic task** to re-assert for N ticks. More invasive; adds a hook.

⚠ **Start with (A).** `APP_rke_command_code` is written by the RKE decode path; if that path
actively zeroes the cell every tick, (A) silently fails and (B) becomes necessary.

**Measured, and still open:** `0x40002DA0` and the valid flag `0x40003F50` both read `0` three
times running on an idle bench — which is *consistent with either option* and therefore settles
nothing. An idle cell that is never written cannot distinguish "a written value would persist"
from "a written value is cleared next tick"; only a write can, and we have no write yet. **This
stays an open design question** (rule 8: a constant reading is not evidence). Resolve it on the
car by peeking `0x40002DA2` repeatedly right after a depth-2 trigger — needing no new build is
exactly why `peek` is included.

---

## 5. Registers and safety of the cave itself

Per AGENTS.md rule 38, do not assume the EABI volatiles are free — **count references in the
enclosing function** and pick on measurement.

> ⚠ **This section originally claimed `301_build_cave.py` "re-runs that check". It does not**, and
> `300_prereq.py`'s docstring advertises a "P4 free scratch RAM" gate that was **never
> implemented**. Both statements were written as if done. The gap was real: peek measured `r9`,
> but the rs cave introduces **`r5`** (carrying the MAGIC from a depth body into the reply block),
> which was never in peek's measured set. `307_reg_safety.py` closes it.

`307_reg_safety.py` disassembles the whole enclosing function (`FUN_0010B65E`, `0x10B65E..0x10BA83`,
391 instructions) and separates **definitions** from **uses** after the hook:

| reg | uses after hook | defs after hook | verdict |
|---|---|---|---|
| `r0` | 0 | 2 | SAFE |
| `r1` | 47 | 1 | stack pointer — saved/restored via the cave's own frame (contract, not a clobber) |
| `r3` | 18 | 44 | SAFE — redefined at `0x10B76A` before first use |
| `r4` | 0 | 16 | SAFE |
| **`r5`** | **0** | 8 | **SAFE — never used after the hook** |

**Control (rule 9):** `r26`/`r27`/`r28` are known live at the hook (DID, length, index) and come
back with **16 / 5 / 4** uses. The scan can therefore detect a live register, so "0 uses" for `r5`
is a real measurement rather than a scan that finds nothing.

Every store is to a **single named cell** with a build-time address assertion, verified again from
the artifact by `304_verify.py`'s V1 (14 stores, 0 undeclared). There is no computed/indexed store
anywhere in the cave, so a wrong address cannot scribble over a range.

---

## 6. Build & verify pipeline (mirrors `peek`/`acc-fix`)

| step | script | gate |
|---|---|---|
| 1 | `300_prereq.py` | ✅ done — hook matches, MAGICs absent w/ passing control, cave space, cells resolve |
| 2 | `302_stock_did_probe.py` | ✅ **done** — all 6 MAGICs `NRC 0x31`, C1+C2 pass (bench #1) |
| 3 | `301_build_cave.py` | ✅ done — 77 instructions, round-tripped; `setaddr()` self-check 6/6 |
| 4 | `303_build_vbf.py` | ✅ done — 4 guards passed, sum8 `0x7572`→`0x983D`, CRC16 ×2, CRC32 |
| 5 | `304_verify.py` | ✅ **ALL PASS** — see below |
| 5b | `306_project_clean.py` | ✅ **CLEAN** — `ghidra_proj` unmodified by the writable builds |
| 5c | `307_reg_safety.py` | ✅ **r5 SAFE** (0 uses after hook) with a passing liveness control — §5 |
| 6 | flash | ⬜ see §6.2 |
| 7 | `305_rs_trigger.py accept` | ⬜ on-vehicle controls |

### 6.2 Flash commands (verified against `bcmflash.py --help`)

```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate

# 1. offline sanity check of the artifact
python3 work/flash/bcmflash.py verify work/rs-trigger/JV6T-14C094-AD_peek-rstrigger.VBF

# 2. confirm the module identity -- MUST say JV6T-14C094-AD
python3 work/flash/bcmflash.py ident --iface can0

# 3. DRY RUN (default -- transmits nothing)
python3 work/flash/bcmflash.py flash work/rs-trigger/JV6T-14C094-AD_peek-rstrigger.VBF \
  --sbl DV6T-14C097-AB.vbf --iface can0

# 4. real flash
python3 work/flash/bcmflash.py flash work/rs-trigger/JV6T-14C094-AD_peek-rstrigger.VBF \
  --sbl DV6T-14C097-AB.vbf --iface can0 --execute \
  --logfile /tmp/rs_flash_$(date +%Y%m%dT%H%M%S).log

# 4b. ON THE VEHICLE (not the bench): add --quiet-bus to silence the other
#     modules for the duration.  Sends 7DF#02 10 82 x20 before the session and
#     7DF#02 11 81 (resets EVERY module) after.  Unconfirmed by design -- watch
#     an unfiltered candump in a second terminal.  See bcmflash_tool.md §4.
#   ... --execute --quiet-bus

# 5. post-flash acceptance -- BEFORE firing anything
python3 work/rs-trigger/305_rs_trigger.py accept
python3 work/rs-trigger/305_rs_trigger.py config
```

- `--sbl` is **relative to the repo root** (`DV6T-14C097-AB.vbf` lives there, not in `work/flash/`).
- **Do not use `--force`.** It bypasses the identity check; if `ident` disagrees with the image the
  correct action is to stop (rule 32 — bench #2 is a different part number, `GV6T-14C094-AJ`).
- This is a **1.2 MiB application** flash: 11 erase regions, several minutes. The erase step answers
  `7F 31 78` (responsePending) *before* `71 01 FF 00` — that is normal, and a tool that aborts on
  the first negative stops **after erase, before write** (rule 28). Do not interrupt it.
- Keep the `--logfile`; it is the only record if something goes wrong.

> **Why 5b exists.** `301_build_cave.py` and `304_verify.py` both open `ghidra_proj/BCM_C1MCA`
> **writable** and write cave bytes in, relying on `endTransaction(tid, False)` to roll back.
> That is the project the shipped **acc-fix / rke-lock** VBFs are verified against (rule 5), so a
> silently-failed rollback would corrupt the reference image with no visible symptom — and every
> write-path failure documented in AGENTS.md §2.1 *reported success on stdout*. `306` reopens it
> **read-only** and asserts the hook still holds the OEM `189AA9EE` and all three written spans
> (both caves + the `setaddr` self-check scratch at `0x11A000`) are still `0xFF`. All four clean.
> Re-run it after any future build in this directory.

### 6.1 What `304_verify.py` actually checked

Re-derived **from the artifact on disk**, not from the builder's memory:

| check | result |
|---|---|
| CRC-16 both blocks, file CRC-32, internal sum8 | PASS |
| diff vs OEM = exactly 4 clusters, spans matching the plan | PASS (718 bytes) |
| **V1** every store targets a *declared* cell | PASS — 14 stores, **0 undeclared** |
| **V2** no store precedes the first MAGIC compare | PASS (cmp@0, first store@7) |
| **V3** MAGICs == the set proven free on hardware | PASS `DE13 DE16 DE2C` |
| **V4** chain closed: peek tail → rs cave → stock | PASS |

**V1 is the check that matters.** A cave can disassemble cleanly and still store to the wrong
address if an `e_lis`/`e_add16i` pair is mis-built — V1 reconstructs each store's target from the
instruction stream and requires it to be one of the six declared cells.

> ⚠ **The verifier's first run FAILED on a correct artifact** — it asserted 5 diff clusters when
> the truth is 4, because the chain branch at `0x1181B2` lies *inside* the peek-cave span and is
> not a separate cluster. Per AGENTS.md rule 39 the fix was to correct the checker **and make it
> stricter**: it now asserts the exact `(address, length)` of all four spans plus the chain
> branch's containment, rather than a count. Establish whether the artifact or the checker is
> wrong before changing either.

---

## 7. On-vehicle test protocol

Run shallow→deep. At each depth, capture HS-CAN **and** peek the state cells — a null is
uninterpretable without both (`bench_session_4.md` §4.4, where the wire caught 60 ms pulses the
peek sampler missed at 13 Hz).

```bash
candump -ta can0,080:7FF,030:7FF > rs_trigger_<depth>.log &    # 0x80 carries power_mode d2
python3 work/rs-trigger/305_rs_trigger.py accept               # controls FIRST
python3 work/rs-trigger/305_rs_trigger.py config               # are the settings even enabled?
python3 work/rs-trigger/305_rs_trigger.py fire 1               # depth 1
```

`fire` prints the state cells before, and at +0.2 s / +1 s / +3 s after, so the readback is
built in. `state` alone reads them without firing anything.

**Record, for every depth:** `0x80` d2 on the wire, `APP_power_mode`, `0x40009680`/`0x40009668`,
and whether the engine cranked. The gate-field readings settle the §8.1 base ambiguity as a
by-product — whichever of the two moves to 7 is the real base.

**Expected outcomes and what each means:**

| depth 1 | depth 2 | depth 3 | reading |
|---|---|---|---|
| works | — | — | the arming cells are the whole gate; `DAT_40008D75` confirmed as the latch |
| no-op | works | — | the RKE path's own guards matter; state term 7 is vehicle context (confirms §8.2) |
| no-op | no-op | works | BCM announce path fine; blocker is upstream of `FUN_00087486` |
| no-op | no-op | no-op | the mode-4 cell is not what drives remote start, **or** a guard we have not found refuses — re-open `remote_start.md` §8 |

⚠ A depth-3 success with no engine crank is **not a failure** — it means the BCM announced and the
PCM refused, which is a finding about the *PCM*, and would be the first evidence that the BCM is
not the sole authority here.

---

## 8. What is NOT established (carry this into the test)

- **No depth has ever produced `power_mode = 4`.** Seven bench conditions were null, and §6.4
  explains why the bench could not have worked — but that explanation is *not* proof any of these
  depths works on a vehicle.
- **`DAT_40008D75` as the arming latch is (c)**, never confirmed.
- **Depth 2's persistence (§4.1) is unresolved** — option (A) may silently fail.
- **The EEFA/EEFD/EEAB settings are all in their disabled/zero state on the bench unit**
  (`bench_session_4.md` §7). If the test vehicle's BCM has them likewise, remote start may be
  configured off entirely, and **no trigger depth will work** — read them on the car first:
  `305_rs_trigger.py config` dumps EEFA/EEFB/EEFD/EEAB before you fire anything.
- Whether writing those settings requires `0x27` is **untested** by choice.
