# Bench session 4 — remote start on the live BCM (peek + wire)

> Unit: **bench #1**, identity read, not assumed (rule 32):
> `F188 = JV6T-14C094-AD`, `F18C = 009640039386`, PBL V013, VIN `WF0AXXWPMAEL32600`.
> This is the peek-flashed unit the addresses in `docs/remote_start.md` were derived on.
> Buses: `can0` 500 k (HS), `can1` 125 k (MS), both `ERROR-ACTIVE`.
> Script: `work/bench/291_remote_start_peek.py`. Artifacts:
> `work/bench/logs/20260912T202528_rs1.json` + `..._rs1_bus.log` (43,996 frames, 52.6 s).

---

## 1. Instrument acceptance — all controls pass

`peek_read.py accept`, before touching anything:

| control | result |
|---|---|
| known truth `0x0DE278` vs owner backup | `70E8E000` ✅ |
| known truth `0x100000` vs owner backup | `E22A480C` ✅ |
| out-of-range `0xFFFFFFFF` → `EEEEEEEE` | ✅ |
| stock `22 0631` / `22 0631 401B` | ✅ |

Self-referential liveness (rule 36), run **before and after** the trial:

```
0x4000538C -> 4000A9E2      (request data pointer)
0x4000A9E5 -> 4000A9E5      the value IS the address asked for
0x4000A9E6 -> 00A9E600      window slides byte-for-byte
```

Byte-order sanity, checked rather than assumed: `0x40001D84 = 09000049` big-endian ⇒
`APP_power_mode` (`0x40001D85`) = **`0x00`**, matching the predicted idle value (§3 of
`remote_start.md`), and `APP_vehicle_state_mode` (`0x40001D84`) = `0x09`.

---

## 2. The stimulus demonstrably reached the firmware (a)

Not assumed — read back out of the ECU's **own decoded cell**. We transmit `0x100`
`d6=0xF8 d7=0x08`; `VOL_sig_get16` should yield `(0xF8 & 0x1F) << 8 | 0x08 = 0x1808`:

| condition | `APP_rke_command_code` `0x40002DA2` (halfword) |
|---|---|
| `A_start_only` | `0x0000` ×56, **`0x1808` ×18**, **`0x1818` ×16** |
| `B_lock_then_start` | `0x0000` ×68, **`0x1801`/`0x1811` ×3** (LOCK), **`0x1808`/`0x1818` ×36** |
| null before / after | `0x0000` only |

⇒ The enum-8 code lands in the firmware's RKE cell exactly as the static decode predicts.
135 of our enum-8 `0x100` frames are in the bus capture. **Any null below is a real
negative, not a dead stimulus** — the failure mode `live_debug_uds.md` §8.6 warns about.

### 2.1 Positive control: the rig drives the BCM end-to-end

The LOCK arm works, which proves the whole path (our TX → RFA decode → lock module → wire):

| | |
|---|---|
| `APP_lock_command` `0x40002E70` | `0x00` idle → **`0x01` (LOCK)** → `0x02` |
| MS `0x3A` d3 on the wire | **`0x01` emitted 73 frames**, transitions at 18.52, 26.97, 27.52, 35.22, 35.77, 36.32 s |

A rig that can make the BCM emit a lock command can be trusted to have *presented* a
remote-start command.

---

## 3. RESULT: enum 8 does NOT reach `APP_power_mode = 4` on this bench (a)

`APP_power_mode` measured **two ways**, in four conditions (each flanked by null windows,
rules 29/40):

| condition | peek histogram | wire `0x80` d2 high-3 |
|---|---|---|
| null before | `0x00` ×78 | 0 |
| **A** enum 8 alone | `0x00` ×92 | 0 |
| **B** LOCK → enum 8, same ID | `0x00` ×107 | 0 (+1 transient) |
| **C** LOCK → enum 8, different ID | `0x00` ×103 | 0 (+1 transient) |
| **D** B repeated at 2.5 s gap (rule 26) | `0x00` ×158 | 0 (+2 transients) |
| null after | `0x00` ×68 | 0 |

**Value 4 never appears**, in either channel, in any condition.

### 3.1 The non-degeneracy control that makes this meaningful (rule 8)

A cell that reads one value everywhere is as suspect as one reading zero. It is not stuck:

```
APP_power_mode over 751 continuously-sampled 0x80 frames (62 ms period, 46.6 s):
    mode 0 : 747 frames (99.5%)
    mode 1 :   4 frames (0.5%)     <-- 4 pulses, widths 59/60/61/60 ms
    mode 4 :   0 frames
```

The mode-1 pulses are `APP_lock_request_dispatch` writing `APP_power_mode = 1` — the
**documented** value-1 writer (`tx_pack_stage.md` §4.3, re-derived as the C1 control in
`287`). So the cell demonstrably moves, under its documented writer, during this very run.
That is what licenses "mode 4 never occurred" as a finding rather than a dead reading.

### 3.2 ⚠ The peek MISSED the mode-1 pulses — quantified blindness (rule 40)

The peek histograms above show `0x00` only, including for condition B where the wire caught a
mode-1 pulse. Cause: the round-robin sampler reads `APP_power_mode` at ~13 Hz (~77 ms), and the
pulses are **~60 ms** — so it misses them more often than not.

**The peek's null on mode 1 was blindness, not absence.** Stating it plainly because it is the
exact failure this project has recorded twice before, and because it forces the right
instrument choice: for a cell mirrored onto a periodic frame, the **wire is the superior
channel** — 62 ms continuous, no sampling gaps. The mode-4 negative rests on the wire
(751 frames), not on the peek.

This does bound the claim honestly: a mode-4 excursion **shorter than ~62 ms** would evade even
the wire. On the vehicle, mode 4 persisted for the *entire* remote-start run (tens of seconds,
§3 of `remote_start.md`), so a sub-62 ms mode 4 would be a different phenomenon from the one
being reproduced.

---

## 4. Hypotheses: outcome

| # | hypothesis | verdict |
|---|---|---|
| H1 | enum 8 drives `APP_power_mode` 0→4 | **not reproduced on the bench** |
| H2 | LOCK-first is required (fob-ID stored by the enum-1 arm) | **untested** — B and C are indistinguishable because *neither* reached mode 4 |
| H3 | fob ID must match | **untested**, same reason |

H2/H3 are recorded as untested, **not refuted**: a discriminator cannot be evaluated when the
outcome it discriminates never occurs in any arm.

### 4.1 Why the bench plausibly cannot do this (leads, level c)

Nothing here is established; these are the candidates the evidence points at:

1. **The bench has no vehicle context.** `FUN_000ADADA`'s guard needs `(req94 >> 0x1B & 7) == 7`
   *before* it even looks at the enum. On the vehicle, remote start requires PCM/engine
   preconditions (hood, brake, gear, alarm state) that a bare BCM on a bench cannot satisfy.
2. **`FUN_00087486` needs `APP_lock_request_input` (`0x40008D2C`) `== 1`** to take its mode-4
   arm — and that cell read **`0x00` in every sample of every condition**, consistent with the
   long-standing finding that it has no writer reachable on this build
   (`tx_pack_stage.md` §9, `bench_session_3.md` §9.3).
3. ~~**Config bytes.**~~ **MEASURED — not the blocker** (§4.3).
4. **The `0x3A0` ignition-status frame is absent** — no module transmits it on the bench, so any
   arm requiring "ignition off / key out" context may not be satisfiable.

### 4.3 Config bytes read — they ACQUIT themselves (a)

Single flash reads, so no sampling concerns:

| cell | value | gate in the decompile | verdict |
|---|---|---|---|
| `DAT_00008116` | **`0x02`** | demux needs `x-2 < 2` (i.e. 2 or 3) | **satisfied** — consistent with §2, the enum decode demonstrably works |
| `DAT_000081F3` | **`0x02`** | `FUN_000ADE12` case 1 needs `== 2` | **satisfied** |
| `DAT_00008154` | **`0x01`** | `FUN_00087486` takes the `APP_lock_command = 3` arm iff `== 2` | **not taken — and that is the arm we do NOT want** |

The last row matters: with `DAT_00008154 != 2`, `FUN_00087486` falls through to the **else**
branch, which is the one containing `APP_power_mode = 4`. So the config routes *toward* mode 4,
not away from it. **Lead 3 is eliminated**; `0x00008116 == 2` also independently explains why
the enum decode works on this unit.

⇒ The surviving candidate is lead 2: `APP_lock_request_input` `0x40008D2C` read `0x00` in every
sample of every condition, and `FUN_00087486`'s mode-4 arm requires it `== 1`.

### 4.2 Bus-side null, recorded

- MS `0x1A4` d0: **`0x40` in all 902 frames**, field `(d0>>4)&3 = 0` throughout. The §7.2 open
  item (1-of-3 on the vehicle) stays open; the bench adds a fourth null.
- MS `0x3A` d4 bit7: **0 in all 901 frames** — consistent with §2, it is an engine-run
  indicator and nothing on the bench is running.

---

## 5. What this session did and did not settle

**Settled (a):**
- The peek service and the RFA rig both work on this unit; every acceptance and liveness
  control passes, before and after.
- Enum 8 reaches `APP_rke_command_code` exactly as the static decode predicts — §1 of
  `remote_start.md` is now confirmed **on hardware**, from the firmware's own cell.
- `APP_power_mode` is live and takes its documented value 1 under its documented writer.
- Enum 8 alone does **not** produce mode 4 on a bench BCM, in 4 conditions, on 2 channels,
  with the stimulus verified and the cell proven non-stuck.

**Not settled:**
- H2/H3 (the fob-identity sequencing) — untestable until *some* arm reaches mode 4.
- Whether the blocker is vehicle context, `0x40008D2C`, config bytes, or the `0x0AD…`→`0x087…`
  edge itself.

**Next, in order of cost:**

⚠ **Superseded by §6.4** — the bench cannot reach ignition-ON, so none of the steps below can
produce mode 4. Kept only to record what was tried. Step 1 was done (§4.3); steps 2–3 are moot.

1. ~~Read the config bytes~~ — done, §4.3: they acquit themselves.
2. ~~Peek the `FUN_000ADADA` state block while enum 8 is presented.~~ Would still only show the
   guard refusing on a precondition the fixture cannot satisfy.
3. ~~Synthesise the missing vehicle context.~~ Refuted structurally in §6.1 — `0x3A0` is a BCM
   **TX** frame; and per §6.4 ignition-ON is a hardware state this unit cannot enter.

---

## 6. Session 4b — the ignition lead is REFUTED, and it refutes it structurally

Script `work/bench/292_rs_guard_localise.py`, artifacts `..._rs2.json` / `..._rs2_bus.log`.
Three further conditions, each with liveness controls before and after (both passed):

| condition | what it added | `power_mode` (peek) | `power_mode` (wire, 526 frames) |
|---|---|---|---|
| **E** | `d7 bit4` held **high** for the whole press | `0` only | `0` only |
| **F** | E + synthesised `0x3A0` ignition context | `0` only | `0` only |
| **G** | F + LOCK-then-START sequence | `0` only | `0` only |

`rke_code` confirms the stimulus landed in all three (`0x1818` ×50/41/50, plus `0x1811` LOCK
in G). So E is a **clean negative**: the `d7 bit4` term of `FUN_000ADADA`'s guard was a cheap
and plausible explanation — 291 alternated that bit via the rolling counter — and holding it
high changes nothing.

### 6.1 ⚠ F and G are VOID — the injection control failed, and that is the finding

The script's own control: *if the `0x3A0` RX image `0x400006D0` never changes, the injection was
not accepted and every ignition-condition null is void.* It never changed — `0x00000000` in all
159 samples, against **672 `0x3A0` frames on the bus**.

The cause is structural, and it kills the lead outright:

```
net_frame_maps.json :  CAN1_MS  mb36  TX  0x3A0  image 0x40000A69
rx_frame_map.json   :  CAN1_MS  mb36  RX  0x3A0  image 0x400006D0
```

**The same mailbox, 36, is the BCM's `0x3A0` TRANSMIT mailbox.** The BCM is the *producer* of
ignition status on MS-CAN, not a consumer — so no RX path for `0x3A0` exists on this bus and the
RX image is dead storage. The bus capture confirms both talkers: `11 00 …` ×530 (the **BCM's
own**) and `40 00 …` ×142 (mine).

⇒ **Lead 4 is refuted, not merely untested.** "Inject the ignition frame" was never possible;
ignition context is not something the bench can hand the BCM over CAN.

### 6.2 What the BCM's own frame says — the actual blocker (b)

Reading the BCM's `0x3A0` **TX image** directly: `0x40000A69` = **`0x11`** — hi-nibble `1`,
**not** `4` (= Run, per `key_outside_gate.md`). And `APP_vehicle_state_mode` `0x40001D84` now
reads `0x07` where it read `0x09` earlier in the session.

The BCM knows perfectly well that the vehicle is not in Run, and it derives that from its
**hardwired ignition input**, not from the bus. A remote-start feature that arms on vehicle
power state therefore cannot be driven to completion by CAN stimulus alone on a bare bench
module — consistent with `FUN_000ADADA`'s `(req94 >> 0x1B & 7) == 7` state term, which no RKE
frame can satisfy.

### 6.3 Standing conclusion

| claim | status |
|---|---|
| enum 8 reaches `APP_rke_command_code` | ✅ confirmed on hardware (§2) |
| `APP_power_mode == 4` is the remote-start mode | ✅ from the vehicle captures (`remote_start.md` §3) |
| enum 8 → mode 4 **on a bare bench BCM** | ❌ not reproducible, 7 conditions, 2 channels |
| the `d7 bit4` term explains it | ❌ refuted (E) |
| config bytes explain it | ❌ refuted (§4.3) |
| missing `0x3A0` ignition frame explains it | ❌ refuted structurally (§6.1 — it is a TX frame) |
| **hardwired vehicle power state is the blocker** | **(b)** — the BCM reports non-Run from a hardware input (§6.2) |

**Do not conclude the firmware path is dead.** The vehicle captures prove mode 4 occurs in the
field; what is established here is that the *bench cannot present the preconditions*.

### 6.4 ⚠ SCOPE OF THIS WHOLE SESSION — settled by the operator, not by measurement

**The bench unit is not fully functional: it cannot turn ignition ON, and it would never perform
a remote start.** (Operator statement, and it outranks any inference drawn here — AGENTS.md
rule 22: a domain constraint from the user is a falsifier, and it re-scopes the *method*, not
just the conclusion.)

So every mode-4 null in §3, §4 and §6 was **predetermined by the fixture**, not by the firmware:

- The 7 conditions did not test "does enum 8 drive mode 4". They tested a path whose
  precondition was unreachable from the start.
- §6.2's inference — that the BCM reports non-Run from a hardwired input — was **correct but
  redundant**; the same fact was available by asking.
- The leads refuted along the way (`d7 bit4`, config bytes, `0x3A0`-as-RX) remain valid, because
  each was refuted on its own evidence rather than on the mode-4 outcome.

**What this session legitimately establishes is narrower and still worth having:**

| claim | basis |
|---|---|
| enum 8 reaches `APP_rke_command_code` as `0x1808`/`0x1818` | the ECU's own decoded cell, on hardware |
| the peek + RFA rig drives this BCM end-to-end | LOCK → `APP_lock_command 0x01` → `0x3A` d3 = `01` on the wire |
| `APP_power_mode` is live and takes its documented value 1 | 4 pulses, 59–61 ms, from `APP_lock_request_dispatch` |
| the peek sampler is blind to ~60 ms pulses at ~13 Hz | wire caught what the peek missed (§3.2) |
| `0x3A0` is BCM-**sourced** on MS-CAN | mailbox 36 is a TX mailbox (§6.1) |

**No further bench work on remote start is warranted.** Mode 4 requires ignition-ON, which this
fixture cannot produce. The remaining questions (H2/H3 fob identity, the `0x0AD…`→`0x087…` edge,
`r31`) are **vehicle-only** — or, for a mod, moot: see below.

### 6.5 Consequence for the original goal

The goal was to enter remote-start mode *programmatically*. Two routes, and the bench result
does not damage either:

1. **Reproduce the precondition** — needs a vehicle. Nothing to do on a desk.
2. **Bypass it in firmware** — the acc-fix/rke-lock pattern. The targets are already located and
   confirmed: `APP_power_mode` (`0x40001D85`, struct `0x40001D80`+5) with its three dirty flags
   `0x40003EB6/B7/B8`, and the six immediate-4 writers (§5 of `remote_start.md`), of which
   `FUN_00087486` is the structured one. A cave that sets mode 4 + the dirty flags does not care
   why the stock guard refused.

⚠ Route 2 is **not** validated by anything in this session, and forcing a power-mode cell is a
materially different risk class from rewriting a TX byte: it changes what the BCM believes about
vehicle state, which other modules act on. That needs its own analysis before any VBF is built.

---

## 7. The EEFA / EEFB / EEFD settings DIDs (operator clue) — a configuration cluster

Operator: *"the remoteStart settings stored in EEFA and EEFB and EEFD DIDs."* Read live from the
bench BCM and traced to their backing cells. Scripts: `work/bench/293_did_read.py`,
`work/owner/294_eef_settings_join.py`.

### 7.1 Live values and their cells (a — two independent channels agree)

⚠ Instrument note first: `work/bench/did_probe.py` probes a **fixed plan list** and silently
ignores DIDs given on the command line — it reported success for five different arguments and
rewrote the same output file each time. `293_did_read.py` was written to replace it and carries
its own known-truth control (`F188` must return `JV6T-14C094-AD`; it did).

| DID | UDS value | reader | backing cell | peek of that cell |
|---|---|---|---|---|
| **EEFA** | `0x07` | `APP_did_did_EEFA_read` `0x0E3070` | `DAT_40001E7A` | `0x07` ✅ |
| **EEFB** | `0x04` | `APP_did_did_EEFB_read` `0x0E307E` | `0x40001DB1` | `0x04` ✅ |
| **EEFD** | `0x00` | `APP_did_did_EEFD_read` `0x0E3150` | `DAT_40001E7B` | `0x00` ✅ |

3/3 exact agreement between the UDS answer and a direct memory read — the DID→cell binding is
**derived, not assumed**. (`EEFC` is a packed 2-bit field off `DAT_4000286E`; `EEF8` is 6 bytes,
all zero.)

**`EEFD = 0x00` is the eye-catching one** — a plausible "remote start disabled" setting.

### 7.2 ⚠ RETRACTED — "the remote-start code does not read these cells" was BLIND

> **This section originally reported a controlled negative: 0 remote-start readers for the
> EEFA/EEFB/EEFD cells against 13 for the `APP_power_mode` positive control, and concluded the
> settings are merely reported to a scan tool. That conclusion is WRONG and is retracted.**
> The measurement was correct; the inference was not — for the third time in this project, and
> by the *same mechanism* (rule 30) that hid `APP_power_mode` for four layers.

`295_settings_band_form.py` classified the **form** of every access into
`0x40001E50..0x40001E90`, with all three known DID readers rediscovered as controls (PASS):

| | count |
|---|---|
| absolute-form accesses | **22** |
| **`disp(rX)`-form accesses** | **183** |

Per cell, the two that matter:

| cell | absolute | base-relative |
|---|---|---|
| `0x40001E7A` (EEFA) | 1 | **5** |
| `0x40001E7B` (EEFD) | **0** | **4** |

**EEFD has ZERO absolute references.** An absolute-reference scan could never have seen its
readers, so §7.2's original "0 remote-start readers" was a tautology — the same shape as the
retracted `0x40008D2C` "no writer, path inert" verdict (AGENTS.md rule 14/44).

**Second, independent defect — the SCOPE was wrong too** (rule 18). `294`'s `RS_RANGES` were
`0x0AD800-0x0AE200`, `0x087400-0x087600`, `0x087900-0x087A00`, `0x08C700-0x08C800`. The functions
that actually read the settings — `FUN_000AC666`, `FUN_000AC9D0`, `FUN_000AECBC` — lie **outside
every one of them**. So even a perfect base-relative scan would have returned 0.

⚠ **And the positive control passed anyway.** `APP_power_mode`'s 13 readers sit at `0x087xxx`,
*inside* the ranges, so the control exercised a region the subject never occupied. That is the
sharp lesson here: **a positive control only validates the scan over the region it shares with
the subject.** A control that passes in a different address range than the one the subject lives
in provides no coverage guarantee at all — it made a doubly-broken scan look trustworthy.

The real readers, all in the remote-start neighbourhood:

| cell | read by |
|---|---|
| `0x40001E7A` (EEFA) | `APP_did_did_EEFA_read`, **`FUN_000AC9D0`**, **`FUN_000AC666`** |
| `0x40001E7B` (EEFD) | `APP_did_did_EEFD_read`, **`FUN_000AECBC`** |

### 7.3 `FUN_000AECBC` — EEFD is read AS BITS, and `0x40001E60` is the enable gate (a)

> ⚠ Read with §7.4.2: EEFD is *read* as bits here but *written* as a 4-value enum `{0,3,4,7}`.

Decompiled, the consumer is unambiguous:

```c
uVar1 = DAT_40001E60;
if (((uVar1 >> 0x19 & 1) == 0) || ...)      // <-- 0x40001E60 BIT 25 = enable gate
    { *(u8*)(r30+0x80) = 0; *param_4 = 0; } // reset
else if (*(char *)(r30 + 0x80) != 0)
    *param_4 += 10;                          // 10 ms/tick, same cadence as 0xADADA

if (... DAT_000081F3 == 2 && ...) {
    bVar3 = DAT_40001E7B;                    // <-- EEFD, read as a BITFIELD
    ...
    if ((bVar3 >> 1 & 1) == 0) { ... }       // EEFD bit1
    if ((bVar3 >> 2 & 1) == 0) { ... }       // EEFD bit2
}
```

Three things this establishes:

1. **EEFD is consumed as a bit-mask, not a scalar** — `bit1` and `bit2` are tested separately.
   This is rule 13 again (wire/DID representation ≠ internal representation): a scan-tool value
   of `0x00` is *all feature bits clear*, which is materially stronger than "a setting is zero".
2. **`0x40001E60` bit 25 is an enable gate** guarding a 10 ms-tick timer — the same cadence as
   `FUN_000ADADA`'s. Live value `C103003C`, so **bit 25 = 0**: on this bench the function takes
   its **reset** path (timer cleared, flag cleared) every tick. See §7.4 — that bit has a name.
3. `DAT_000081F3 == 2` appears here too — the config byte measured as `0x02` in §4.3, i.e.
   **satisfied**, so this arm is live on this build.

Also relevant: `FUN_000AD97C` (the block that reads `0x40001E60` at `0xAD95A`) divides a
millisecond accumulator by **60000** — ms→**minutes** — the classic remote-start *run-duration*
computation, and EEFA's live value is `0x07`. A 7-minute duration is a natural reading but is
**not established**; do not state it as fact without a capture.

### 7.4 `0x40001E60` is a PACKED CONFIG WORD, and **EEAB is the gate bit** (a)

The `295` dump answered the "setting or runtime state?" question left open above. All **7
writers** of `0x40001E60` sit in `0x0EAxxx–0x0EBxxx` — the DID **write** region — and **six
`APP_did_did_*_read` functions** each extract a different bit of it. It is configuration, not
runtime state.

Decoding those readers and checking each against its live UDS value:

| DID | extracts | bit of `0x40001E60` | computed | live UDS | |
|---|---|---|---|---|---|
| **EEAB** | `(w >> 0x19) & 1` | **25** | 0 | **`0x00`** | ✅ |
| EEEF | `(w >> 0x1B) & 1` | 27 | 0 | `0x00` | ✅ |
| EEEC | `(w >> 0x1E) & 1` | 30 | 1 | `0x01` | ✅ |
| EEE8 | `(w >> 0x1F)` | 31 | 1 | `0x01` | ✅ |

**4/4 agreement** between the bit extracted from a peeked word and the value returned over UDS —
the packed-word decode is *derived*, not assumed, on two independent channels.

**`EEAB` is bit 25 — precisely the bit `FUN_000AECBC` tests:**

```c
if (((DAT_40001E60 >> 0x19) & 1) == 0)   // EEAB == 0
    { timer = 0; flag = 0; }             // reset every tick
```

and on this module **EEAB reads `0x00`**, so that gate is **closed**.

⚠ What this does and does not mean:

- ✅ **Established:** EEAB is a configuration bit, DID-readable and DID-*writable* (its writers
  are in the DID write region), and it gates a remote-start-adjacent timer that is held in reset
  while it is 0.
- ❌ **NOT established:** that EEAB is *the* remote-start enable, or that setting it to 1 would
  make the feature work. `FUN_000AECBC` has not been traced to `APP_power_mode = 4`, and §6.4's
  ignition-ON blocker is independent of it. Two closed gates can coexist.
- The honest summary: the operator's "settings live in EEFx" clue has led to a **coherent
  configuration cluster** — EEFD (bitfield, all clear), EEFA (`0x07`, near a ms→minutes
  computation), and EEAB (bit 25, the gate) — all read by `0x0AC…/0x0AE…` remote-start code, all
  currently in their disabled/zero state on this module.

⚠ **Writing any of these is a configuration change to the module**, is almost certainly
security-gated (`0x27` before `0x2E`), and must not be attempted without explicit intent. The
read-side evidence above required no writes.

### 7.4.1 `DE05` — a three-channel confirmation, and what its NRC really means (a)

`DE05` also reads `0x40001E60` (bit 24) but answered **`NRC 0x31 requestOutOfRange`** on the
bench. That is *not* "the DID is unsupported" — the decompile shows an explicit conditional
refusal:

```c
if ((DAT_40003C11 >> 3 & 1) == 0)   APP_diag_nrc_slot = 0x31;   // refuse
else if (fnptr(4) == 1)             APP_diag_nrc_slot = 0x33;   // securityAccessDenied
else  *out = (DAT_40001E60 >> 0x18) & 1;                        // bit 24
```

So the observed NRC **names the branch taken**, and it makes a falsifiable prediction the decode
itself knows nothing about: `DAT_40003C11` bit 3 must be **0** on this module.

| channel | result |
|---|---|
| decompile | bit 3 == 0 ⇒ emit `0x31` |
| **peek** `0x40003C10` = `00001200` ⇒ `0x40003C11` = `0x00` | bit 3 = **0** ✅ |
| **wire** `22 DE05` | `NRC 0x31` ✅ |

**Three independent channels agree.** This is the strongest single confirmation in the session —
static decode, live memory, and bus behaviour all pinned to one bit — and it validates the whole
`0x40001E60` packed-word decode by a route that does not depend on §7.4's bit arithmetic.

Two reusable lessons (rule 35 — *read the NRC, it names the mechanism*):

- A `requestOutOfRange` on this ECU can mean **"conditions not met for this DID"**, not
  "unknown DID". Treating `0x31` as "not served" would have written this DID off.
- `DAT_40003C11` bit 3 is an **access-enable** for at least one config DID. If EEAB's writer is
  gated the same way, `0x2E` would fail for a reason that has nothing to do with security
  access — worth knowing *before* concluding a write is impossible.

### 7.4.2 The EEFD **writer** — legal values are an enum `{0,3,4,7}` (a)

`FUN_000EB5A0` is the EEFD write handler. Its accept condition, verbatim from the decompile:

```c
if ((v == 0) || ((2 < v) && ((v < 5) || (v == 7)))) {
    if (DAT_40001E7B != v) APP_signal_error_latch_1 |= 0x80;  // config-changed flag
    DAT_40001E7B = v;
    FUN_0005049C(0xD);                                        // commit/notify, index 0xD
    return 0;
}
return 0x31;                                                  // requestOutOfRange
```

Brute-forcing that predicate over `0..255` (not reasoning about it) gives the accepted set:

**`{0, 3, 4, 7}`** — everything else is rejected, including `1`, `2`, `5`, `6` and all `> 7`.

> ⚠ **This partly contradicts §7.3's "EEFD is a bitfield" framing, and the tension is the
> finding.** If EEFD were a free bitfield whose bits 1 and 2 are independently meaningful, all 8
> low combinations would be writable; only 4 are. So EEFD is **written as a constrained enum and
> read as bits** — both descriptions are true of different halves of the code, and neither alone
> is right (rule 13: wire/DID representation and internal representation are independent).
> Live `0x00` is the "all clear" member of that set.

Note what this does **not** say: the decompiled handler shows no security check itself, but it is
reached through the DID write dispatcher, which may gate it (cf. §7.4.1, where a *separate*
enable bit refused DE05 with `0x31` before security was ever consulted). **Do not infer that
EEFD is writable without `0x27`.** Untested, deliberately.

### 7.4.3 EEFA is also a bitfield — and it is fully ENABLED (a)

`FUN_000AC9D0` (an EEFA consumer, in the remote-start region) splits it bit by bit:

```c
bVar1 = DAT_40001E7A;
*(byte *)(r6 + 6) = bVar1 & 1;   // bit0 -> flag byte
*(byte *)(r6 + 7) = bVar1 & 2;   // bit1 -> flag byte
*(byte *)(r6 + 8) = bVar1 & 4;   // bit2 -> flag byte
```

Live EEFA = `0x07` ⇒ **bits 0, 1 and 2 all set**. This is a useful contrast to EEFD's `0x00`:
within one settings cluster, one cell is fully enabled and another fully clear, so "the cluster
is just zeroed out" is refuted — the values are meaningful and differ per cell.

### 7.5 Standing — corrected

- The operator's clue is **confirmed twice over**: the DID→cell mapping is derived (3/3 UDS vs
  peek agreement), *and* the cells are genuinely consumed by remote-start code.
- **EEFD `= 0x00` is now a live candidate for a feature-disable**, contrary to §7.2's retracted
  negative — its bits 1 and 2 are tested by `FUN_000AECBC`.
- This does **not** overturn §6.4: ignition-ON is still unreachable on this fixture, so the
  bench cannot discriminate "disabled by setting" from "blocked by power state". Both may hold.
- ⚠ Whether EEFD is *writable* (`0x2E` WriteDataByIdentifier, likely security-gated) is
  **untested**. That is the cheap next experiment and it is non-destructive to *read* the
  write-path; actually writing a settings DID is a change to the module's configuration and
  should not be done without explicit intent.

---

## 8. `r31` resolved to two candidates — preferred base `0x400095EC` (b)

`docs/remote_start.md` §7.0.2 recorded a controlled negative: r31 is not defined within 300
instructions of any `0x0AD…` entry, so a backward walk cannot reach it. That negative was
**correct for its scope, and its scope was too narrow** — the new evidence that `FUN_000AD97C`
indexes `r31[0x17]`/`r31[0x08]`/`r31[0x24]` (the same `+0x5C`/`+0x20`/`+0x90` cells
`FUN_000ADADA` uses) proved the whole `0x0AC000..0x0AF000` span is **one feature module sharing
one state block**. `296_r31_wide.py` swept that span for *any* definition of r31.

| r31 value | sites |
|---|---|
| **`0x400095EC`** | **5** (incl. `0xAD6E0`, `0xAD75E` — the blocks around `FUN_000AD97C`/`FUN_000ADADA`) |
| `0x40001D80` `APP_mode_flags` | 3 |
| others | 1 each |

Controls: the known RKE base `0x40002D20` was recovered **5×** by the identical mechanism
(C1 PASS), and **14** distinct base values were resolved (C2 PASS, rule 8).

**Derivation verified, not just the answer** (rule 17). The base comes from an *adjacent*
instruction pair inside one block — `0xAC3D0 e_lis r31,0x4001` + `0xAC3D4 e_add16i r31,r31,-0x6A14`
⇒ `0x40010000 − 0x6A14` = `0x400095EC` — so this scan's known weakness (register tracking not
scoped per function) **cannot** have leaked a base across a function boundary here.

**Method blindness, stated (rule 40).** r31 has **57** definitions in the span; only **11**
resolved to addresses. The other 46 are overwhelmingly *not* address synthesis — `e_andi r31,r4,2`,
`se_li r31,0`, `se_lbz r31,0(r0)` — i.e. r31 reused as a scratch register, not a missed base.
⚠ Still, "5 sites is the most" is a **plurality among resolved sites only**; it is the content
check in §8.1, not the site count, that carries this identification.

⚠ **Confidence is (b), not (a)** — §8.1 shows a second candidate (`0x400095D4`) survives.

### 8.1 The base is confirmed by CONTENT — but the first discriminator FAILED

A resolved address could still be wrong. Dumping 0x40 bytes from it is informative — the block is
**not** zeros, and every non-zero word is a round human duration in milliseconds:

| field | value | = |
|---|---|---|
| `r31+0x0C` | `0x000007D0` | 2 s |
| `r31+0x10`, `+0x14`, `+0x28` | `0x00000BB8` | 3 s |
| `r31+0x18` | `0x0036EE80` | **60 min** |
| `r31+0x1C` | `0x000001F4` | 500 ms |
| `r31+0x24` | `0x0000EA60` | 1 min |
| `r31+0x2C` | `0x00004E20` | 20 s |
| **`r31+0x30`** | `0x001B7740` | **30 min** |

`FUN_000AD97C` computes `(r31[0xc] − elapsed) / 60000` — `(r31+0x30 − elapsed)` in **minutes** —
so with `+0x30` = 30 min this is **remaining remote-start run time against a 30-minute limit**.
That establishes the *region* is a remote-start duration/calibration block.

> ⚠ **It does NOT establish which of two candidate bases is correct, and my first attempt to
> discriminate them was invalid.** `0x400095D4` (1 site) and `0x400095EC` (5 sites) differ by only
> `0x18`, so their field windows **overlap**. I proposed "+0x30 → minutes" as the discriminator;
> run properly it **fails** — `0x400095D4+0x30` = `0x0036EE80` = **60 min**, also a perfectly
> plausible run limit. A shared duration table cannot separate two bases inside it. (Rule 9:
> that check asked "is this value plausible?", which almost anything in this block answers yes to.)

**Corrected discriminator — the guard word itself:**

| base | sites | `+0x94` | `(>>27)&7` |
|---|---|---|---|
| **`0x400095EC`** | **5** | `0x30007FFF` | **6** |
| `0x400095D4` | 1 | `0x00000000` | 0 |

`0x400095EC` is preferred on two independent grounds: 5× the sites, and its `+0x94` carries a
**non-degenerate** value. The alternative's `+0x94` reads all-zero — which per rule 8 cannot
distinguish "state 0" from "not a state word at all".

⚠ **This is a preference on evidence, not a proof.** Both bases remain formally possible. A
vehicle capture must peek **both** `0x40009680` and `0x40009668`; whichever moves to 7 is the
real one, and that measurement settles the base as a by-product.

### 8.2 A cell-level explanation of the bench null (a)

With the base known, `FUN_000ADADA`'s guard can be evaluated term by term against live memory:

| term | live value | passes? |
|---|---|---|
| `DAT_40003C42 < 0` | `0x00` | no short-circuit |
| **`(req94 >> 0x1B) & 7 == 7`** | `req94` = `0x30007FFF` ⇒ **6** | ❌ **BLOCKS** |
| `(rke_code & 0xF) == 8` | `0x1808` observed | ✅ reachable |
| `(rke_code >> 4) & 1` | tested in condition E | ✅ |

**The 3-bit state field at `r31+0x94` bits[27:29] reads 6, and the guard needs 7.** That is a
derived, cell-level reason the guard cannot pass on this fixture *regardless of RKE command* —
exactly what seven conditions across two channels showed empirically. §4–§6's black-box null now
has a white-box mechanism.

⚠ **Not established:** that this field reads 7 on a vehicle, or that ignition-ON is what drives
it there. The field is *consistent* with the operator's statement that the bench cannot remote
start, but only a vehicle capture closes it. Do not present "6 vs 7" as the vehicle's behaviour.

### 8.3 Addresses for a vehicle capture

| cell | meaning |
|---|---|
| `0x40009680` | **the gate field** (preferred base) — expect `(>>27)&7 == 7` |
| `0x40009668` | the gate field under the **alternative** base — peek BOTH to settle §8.1 |
| `0x40009648` | hold timer (`+0x5C`), 10 ms ticks |
| `0x4000961C` | run-duration limit, 30 min |
| `0x4000967C` | request word `+0x90` |
| `0x40001E60` | packed config word (EEAB = bit 25) |

