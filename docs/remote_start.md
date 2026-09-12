# Remote start — MS-CAN trigger, mode cell, and the firmware writers

> ## ⚠ READ THIS FIRST — the mechanism is SOLVED, and parts of this document are SUPERSEDED
>
> **The trigger is the ANNOUNCE byte, not the command value.** Injecting RKE enum 8 into
> `0x40002DA2` leaves it resident indefinitely and nothing happens, because no consumer is told it
> arrived. The receive path also writes **`0x40003F53 = 0xFF`** (a Volcano dirty-flag byte); the
> remote-start consumer at `0x0AEEDA` tests mask **`0x20`**. Bench-confirmed **2/2 vs 0/2** with a
> matched negative control — see **`docs/vehicle_session_1.md` §10–§11**.
>
> **Two headline claims in this document were later REFUTED on the vehicle:**
> - **`APP_power_mode == 4` is NOT the remote-start discriminator** (§3, §5) — it is constant `0x04`
>   before, during and after a genuine remote start, on two independent channels. Use the **run
>   timers** `0x40009620` / `0x40009658` as the success observable instead.
> - **`0x40009680` bit 27 is NOT a remote-start gate** — it opens for any fob button in any vehicle
>   state; it is a receiver-active indicator.
>
> §1, §4, §7 and §7.1 stand. §3, §5 and the old §8 next-steps are superseded. Sections are kept
> rather than deleted so the refuted reasoning stays auditable.

> Session: RKE **LOCK** then **RemoteStart ×2**.
> Captures: `hscan_remote_start2.log` / `mscan_remote_start2.log` (primary),
> `hscan_remote_start.log` / `mscan_remote_start.log` (second run),
> plus the independent pair `CANBus/{hs,ms}can_remotestart.log`.
> **Control:** `CANBus/mscan_running_still.log` + `hscan_running_still.log` — engine running
> after a **normal key start**. Everything below that claims "remote-start specific" is
> stated *against that control*, not against idle.
> Firmware: `ghidra_proj_fullflash` / `BCM_OwnerFlash` (`cflash.bin`), JV6T-14C094-AD.
> Scripts: `work/owner/286_power_mode4_writers.py`, `work/owner/287_power_mode4_value_trace.py`.

---

## 1. The trigger — RKE command ENUM 8 (a)

Remote start enters on **MS-CAN `0x100` d6:d7**, the *same* 13-bit field the shipped
`rke-lock` mod already reads. Per `docs/rke_0x100_lock.md` the firmware consumes the low
nibble as a **command ENUM**, not a bitmask (rule 13):

| `d7 & 0xF` | button | evidence |
|---|---|---|
| 1 | LOCK | `rke_0x100_lock.md`, reproduced here |
| 2 | UNLOCK | `rke_0x100_lock.md` |
| **8** | **RemoteStart** | **this session, 3 captures** |

`mscan_remote_start2.log`, relative to capture t0:

| t (s) | `0x100` d6 d7 | enum | action |
|---|---|---|---|
| 39.998 | `3A 61` | 1 | **LOCK press** |
| 40.358 | `20 00` | 0 | release |
| 40.898 → 41.619 | `3A 08` … `3A D8` | **8** | **RemoteStart burst** (2 presses, ~0.7 s) |
| 41.799 | `20 00` | 0 | release |
| 50.738 → 51.098 | `39 88` … `3A 58` | 8 | shutdown press |

The high bits of d7 (`0x10`, `0x20`, `0x40`, `0x80`) and d6 bit5 are the **rolling counter** —
ignore for identity, exactly as the lock decode does. Note `UB` (d6 bit2) is **0** on every
frame of this session: as `rke_0x100_lock.md` §1 already warned, the RFA does not assert the
validated bit on every press, so **do not gate on UB**.

Chain into the firmware is the established one:

```
MS 0x100 d6:d7 --get16 desc 0x142FD4--> APP_rke_command_code 0x40002DA2 (+valid 0x40003F53)
    --APP_rke_code_commit 0x58538--> --APP_rke_command_demux 0x992B2--> one-hot bits 0x40009034/38
```

`APP_rke_command_demux` decodes `n = code & 0xF` with branchless `LZCOUNT(n^k)` tests for
k = 1..7 — **k = 8 is not among them**, so enum 8 is dispatched somewhere else. That hop is
**not yet located** (see §6).

---

## 2. ⚠ A refuted first candidate — `0x3A` d4 bit7 is NOT remote-start (rule 8/9)

`0x3A` d4 bit7 rises at t=41.710 s, right after the RemoteStart burst, and stays high for the
whole run. It looks decisive and **it is not**: the normal-key-start control shows

```
mscan_running_still.log:  03A d1=83 d3=02 d4=80   (d4 bit7 = 1, 1185/1185 frames)
```

⇒ d4 bit7 is an **engine/run indicator common to both start methods**. Recorded here because
it was the first hypothesis and would have shipped a gate that fires on every normal start.
The control capture is what killed it — a stimulus-only capture could not have.

---

## 3. The discriminator — `APP_power_mode == 4` (a)

> ⚠ **REFUTED ON THE VEHICLE — see `docs/vehicle_session_1.md` §3 and §5.4.**
> During a real fob remote start this cell is **constant `0x04` before, during and after**
> (120 s peek watch), and `0x80` d2 is constant `0x7D` on the wire (5,915 frames). `APP_power_mode`
> is **not** the remote-start discriminator on `JV6T-14C094-AD` / vehicle `WF0AXXWPMAEL32600`.
> The real signature is in the `0x400095EC` state block: a state enum at **+0x70** (`0 → 0x0A`
> while running) and run-timers at **+0x34 / +0x6C** (both `0` when quiet). The section below is
> retained because the *code* analysis of the value-4 writers is still correct — what is wrong is
> the inference that reaching value 4 means remote start.

Differential over **constant-and-different** cells, remote-start run vs normal-key run, with
both remote-start captures required to agree:

| signal | normal key run | **remote-start run** |
|---|---|---|
| **MS `0x80` d2** | `0x07` | **`0x80`** |
| MS `0x3A` d3 (`APP_lock_command`) | `0x02` | `0x01` |
| MS `0x130` d2 | `0x04` | `0x05` |
| MS `0x030` d6 / d7 | `81` / `20` | `A1` / `28` |
| MS `0x2A0` d4 | `0x3E` | `0x1E` |

HS-CAN produced **zero** such cells — the mode distinction is MS-side only.

### 3.1 `0x80` d2 is TWO signals sharing one byte

This is why the old note never reconciled. `tx_signal_dict.json` binds the MS `0x80` image
(`0x400009FD`, from `net_frame_maps.json` — **not** the HS base) as:

| dest | mask | shift | source | site |
|---|---|---|---|---|
| d2 | `0x1F` | 0 | `0x40002E3F` | `0x4C7A6` |
| **d2** | **`0xE0`** | **5** | **`0x40001D85` = `APP_power_mode`** | **`0x4C740`** |

So `ign_powermode_0x80.md`'s "codes 0..7" read the **low 5 bits** (6 = ignition-on, 7 = run),
while `APP_power_mode`'s "codes 0..4" live in the **high 3**. Decoding `(d2 >> 5) & 7`:

| capture | `0x80` d2 | `APP_power_mode` | ign low5 |
|---|---|---|---|
| normal key run (control) | `0x07` | **0** | 7 = run |
| remote-start run ×3 | `0x80` / `0x81` | **4** | 0 / 1 |
| key-off / accessory | `0x40`..`0x47` | 2 | 0..7 |

⇒ **`APP_power_mode == 4` is the remote-start mode**, held for the entire remote run and
never present in the normal-start control.

> **This closes `owner_flash_layers.md` open item 29** ("correlate `APP_power_mode` 0..4 with
> the wire power state, *or demote the name*"). The name is correct; the two code sets were
> never the same field. Item 29 should be marked resolved and this table cited.

---

## 4. Structural finding — `APP_power_mode` is a STRUCT FIELD (rule 30)

All **205** references to `0x40001D85` have the form `se_stb rX,0x5(rY)` / `se_lbz rX,0x5(rY)`.
Not one is an absolute access. So:

```
struct @ 0x40001D80 :  +0x0 APP_mode_flags
                       +0x4 APP_vehicle_state_mode
                       +0x5 APP_power_mode      <-- the remote-start cell
```

Same shape as the `0x40008DE8` body-control struct in `bench_session_2.md` §9.2. Consequence:
reference counts on this cell are **accesses to a shared struct**, not uses of one variable —
do not read "49 writers" as 49 independent features.

---

## 5. The writers of value 4 (a — both controls pass)

`287_power_mode4_value_trace.py` walks back from each write site to the instruction defining
the stored register. **6 sites store an immediate 4:**

| site | function | loader |
|---|---|---|
| `0x087528` | `FUN_00087486` | `0x087526 se_li r7,0x4` |
| `0x0875C6` | **NONE (unswept)** | `0x0875C4 se_li r7,0x4` |
| `0x0879AA` | `FUN_0008799A` | `0x0879A8 se_li r7,0x4` |
| `0x08B754` | `FUN_0008B71A` | `0x08B752 se_li r0,0x4` |
| `0x08C240` | **NONE (unswept)** | `0x08C23E se_li r0,0x4` |
| `0x08C7C8` | `FUN_0008C7B8` | `0x08C7C6 se_li r7,0x4` |

Full immediate distribution: `0`×2, `1`×13, `2`×19, `3`×1, `4`×6, plus 8 computed (non-immediate).

**Controls — both PASS:**
- **C1** the documented value-1 writer inside `APP_lock_request_dispatch` resolves at
  `0x087C0A ← se_li r30,0x1`. ✓
- **C2** non-degeneracy: distinct immediates `{0,1,2,3,4}`, not a single saturated value. ✓

Two of the six sites are in **unswept blocks** — reference-based methods alone are structurally
blind there (rule 44); they were only caught because the scan keys on references *to the data
cell*, not on function membership.

### 5.1 ⚠ Two instrument failures, both diagnosed (rules 17/27/36)

Neither was a fact about the firmware. Recording them so they are not re-derived:

1. **`286`'s p-code scan reported "no constant-4 store" with its POSITIVE CONTROL FAILING.**
   Per rule 27 that is **INCONCLUSIVE, not a negative**. Cause: it tested
   `getFunctionContaining(site).getEntryPoint() == 0x87A0E`, but this image's linear sweep
   splits one routine into many zero-caller `FUN_` blocks (rule 19), so entry-point equality
   can never match. The fix is an **address-range** control, not a function-identity one.
2. **`287`'s first run also failed C1**, for a *different* reason: the backward walker treated
   `se_stb`'s **operand 0 as a definition**, but for a store that operand is the **SOURCE**.
   The walk halted on the store itself and reported the documented value-1 write as
   "computed by `se_stb r30,0x9(r3)`". Fixed with a `NON_DEFINING` mnemonic set (stores +
   compares). **The six value-4 sites were identical before and after the fix** — the bug only
   suppressed the control, it moved no result. Same family as rules 16/21: a mis-parsed
   operand silently drops sites.

---

## 6. `FUN_00087486` — the remote-start state machine (b)
The only one of the three named writers with real logic; the other two (`FUN_0008799A`,
`FUN_0008C7B8`) are identical 6-instruction tails that set mode 4 + the error latch + three
dirty flags, i.e. shared epilogues reached by fallthrough.

```c
if (DAT_40008D75 != 0) {
    if (APP_lock_request_input == 1) {              // 0x40008D2C — the lock-chain input
        req70 = (req70 & ~0xE0000) | 0x20000;
        if (APP_power_mode != 3) {
            if (APP_power_mode != 4)                // not already in remote-start
                APP_signal_error_latch_0 |= 0x80;
            APP_power_mode = 4;                     // *** ENTER REMOTE-START ***
            DAT_40003EB6 = DAT_40003EB7 = DAT_40003EB8 = 0xFF;   // dirty -> TX
        }
    } else {
        DAT_40008D7C = 1;  DAT_40008D75 = 0;
        if (DAT_00008154 == 2 && (DAT_40001A8B >> 1 & 1)) {
            if (APP_power_mode == 2 || APP_power_mode == 4)
                req84 &= ~0x20000000;
            APP_lock_command = 3;                   // note: code 3, matches bench session 1
            APP_lock_command_dirty = 0xFF;
            DAT_40008D12 = 4;
        } else { ... APP_power_mode = 4 ... }
    }
}
```

What this gives us, concretely:

- **The mode-4 entry is a plain `se_stb` of an immediate**, guarded by
  `APP_power_mode != 3`, with the three `0xFF` dirty flags that make `APP_tx_compose` emit
  `0x80` d2 on the next tick. That is a directly patchable / directly settable site.
- It reads **`APP_lock_request_input` `0x40008D2C`** — the *same* cell at the centre of the
  lock chain (`tx_pack_stage.md` §9, `bench_session_3.md` §9.3). This is consistent with the
  observed operator sequence **LOCK first, then RemoteStart**: the LOCK press is not incidental,
  it is on the path.
- `DAT_00008154` is a **flash config byte** (`== 2` required for the `APP_lock_command = 3` arm)
  — a build/as-built variant gate, worth reading on the bench unit.
- `DAT_40008D75` is the arming flag: mode 4 is only reachable when it is non-zero, and the
  function clears it on the other path. **This is the most likely "two presses required" latch**,
  but that is a hypothesis (c), not established.

---

## 7. `FUN_000ADADA` — the enum-8 consumer (a/b)

`288_enum8_dispatch_hunt.py` swept every access to `APP_rke_command_code` for a
compare-against-8 within 24 instructions. It emits **(access, compare) pairs**, and the two
counts are not the same number — several accesses fall through to the same compare:

| | count |
|---|---|
| (access, compare) pairs | **11** |
| **distinct compare sites** | **7** |

Reporting 11 would double-count (the rule-24 corollary: one logical test reached from several
reference sites is still one test). The 7 distinct sites, by function:

| function | distinct enum-8 compares |
|---|---|
| `FUN_0009930C` | 1 — **false positive**, see below |
| `FUN_000ADADA` | 1 |
| `FUN_000ADB1E` | 1 |
| **`FUN_000ADE12`** | **4** |

`FUN_0009930C`'s `se_cmpi r7,0x8` at `0x9936C` is **discarded**: that function is a sweep-split
block of `APP_rke_command_demux` itself and the compare belongs to the `LZCOUNT(n^k)` idiom for
k=1..7, not a dispatch. Checked and rejected rather than counted.

⇒ **6 genuine enum-8 tests, all in `0x0ADA…–0x0ADF…`** — one contiguous feature module, with
`FUN_000ADE12` carrying the majority.

> ⚠ **Correction.** An earlier revision of this note said *"Five hits; four are in `0x0AD…`"*.
> That was read off a **truncated** view of the scan output (`head -80` cut the listing mid-sweep)
> and is wrong in both numbers. The scan itself was correct and printed its own total; the error
> was in reading it. Rule 27's sibling: **a truncated instrument reading is not a reading** —
> check the tool's own reported count against the rows you actually saw.

**`FUN_000ADADA` @ `0x0ADADA` is the real consumer.** Its guard, in one expression:

```c
if (DAT_40003C42 < 0 ||
    ( (req94 >> 0x1B & 7) == 7 &&                       // 3-bit state == 7
      (*(ushort *)(r30 + 0x82) & 0xF)  == 8 &&          // *** RKE enum == 8 ***
      (*(ushort *)(r30 + 0x82) >> 4 & 1) != 0 ))        // d7 bit4
{
    if (timer_5c > limit_20) { req90 |= 0xC00000; req94 |= 0x200000; }   // expiry
    else                      timer_5c += 10;                            // +10 ms/tick
}
```

Three things this nails down:

- **`+0x82` is `APP_rke_command_code`.** Identical offset to `APP_rke_to_body_cmd`'s
  `e_lhz r0,0x82(r5)` (rule 30: the code is a field of the RKE struct, which is why
  absolute-reference scans see only some of its readers).
- **`(code & 0xF) == 8` is tested literally** — confirming §1's enum decode from the *code*
  side, independently of the captures.
- **It is a debounce/hold timer**, `+10` per 10 ms tick against a limit, exactly the shape of a
  "hold the button" or "second press within N ms" requirement. The reset arm requires
  `(code & 0xF) == 0` (release) **and** `(other_field & 0xF) == 8`.

The `0xAD` region also holds `FUN_000ADB1E` (1) and `FUN_000ADE12` (4) — 5 further distinct
enum-8 tests beyond `FUN_000ADADA`'s own, i.e. a coherent multi-state feature module, not a
lone site.

### 7.0 ⚠ `FUN_000ADADA` and `FUN_000ADB1E` are ONE routine, not two

Decompiling `0xADB1E` shows it shares its **entire tail** with `0xADADA` — the same
`LAB_000ADCB2` / `LAB_000ADC58` / `LAB_000ADDB0` blocks, byte for byte. They are two entry
points into one routine that the linear sweep split (rule 19, the same pathology that made
`FUN_0009930C` look like a separate function). **Do not count them as two features.**

What `0xADB1E` contributes is the **reset arm** of the same guard:

```c
if (DAT_40003C42 >= 0 ||
    ( (rke[0x82] & 0xF) == 0 &&          // RKE released
      (state[0x76] & 0xF) == 8 &&        // ...while this field holds 8
      *(char *)(param_1 + 5) == 1 &&
      (rke[0x82] >> 4 & 1) == 0 ))
{ state[0x94] &= ~0x200000;  state[0x5C] = 0; }   // clear request + timer
```

so `0xADADA` **arms and times** on enum 8, and `0xADB1E` **clears** on release — the two halves
of one edge-triggered request, which is consistent with §1's observation that the wire shows a
sustained enum-8 burst followed by a release to enum 0.

Note also the **two distinct struct bases**: `r30 + 0x82` is the RKE struct (`0x40002D20`, §7.1),
while `r31` is the feature's own state block (`+0x5C` timer, `+0x90`/`+0x94` request words,
`+0x76` the field compared against 8).

### 7.0.1 ⚠ `r31` is NOT resolved — a passing control did not save a broken walker

`289_ad_state_base.py` scanned `0x0AD800..0x0AE200` for the `e_lis`+`e_add16i` address-synthesis
idiom. Its control **passed** — it independently recovered the known RKE base
`r30 = 0x40002D20` at two sites (`0xADE0E`, `0xAE0C0`) — and it reported a single r31 candidate,
`0x40003C68`. **That candidate is rejected**, on three independent grounds:

1. **`0x40003C68` is a standalone byte cell, not a struct base.** It appears as plain
   `DAT_40003C68` in `APP_rke_command_demux` (`/tmp/dec1.txt:135`). A base whose `+0x90` and
   `+0x94` would be request words cannot also be a scalar read elsewhere.
2. **The hit is at `0xAE0B8`, outside the routine body** (`0xADADA..~0xADE00`) — a different
   sweep-split block's use of the same register.
3. **The decompiler calls it `unaff_r31`** — Ghidra's marker for *not set in this function*. The
   base arrives from a **caller**; there is nothing in this window to find.

⚠ The walker also has a real defect, found while checking the above: for `e_addi rD,rA,imm` it
used `partial[rD]` instead of the **source** `rA`, so rows like
`r6 = 0x4000005C  e_addi r6,r31,0x5c` are arithmetic nonsense (they are `r6 = r31 + 0x5C`).
Those rows are nevertheless *useful as evidence of the offsets in use* — `+0x44`, `+0x54`,
`+0x5C`, `+0x6C` are all indexed off `r31` — but **no r31 value may be read out of them**.

⇒ This is the rule-17 trap in its purest form: **a passing positive control does not certify an
instrument.** C1 exercised the `e_lis`+`e_add16i` path for a register set *inside* the window;
it never exercised the `rD,rA,imm` source-register path, nor the case where the base is an
incoming parameter. A control only licenses the thing it actually tested. Same lesson as §5.1,
one level deeper.

**Correct next attack:** find the *callers* of the `0x0AD…` routine and read `r31` there —
`getReferencesTo` accepting `CALL`/`JUMP`/fallthrough per rule 19, not `getCallingFunctions()`.

### 7.0.2 The caller-side read — a CONTROLLED negative (a)

`290_ad_caller_r31.py` does exactly that. Result, with the control passing **through the same
code path** that would produce an r31 answer (the §7.0.1 lesson applied):

| entry | predecessor | r31 | r7 |
|---|---|---|---|
| `0x0ADADA` | `0x0ADAD8` **fallthrough** | unresolved | unresolved |
| `0x0ADB1E` | `0x0ADB1C` **fallthrough** | unresolved | unresolved |
| `0x0ADE12` | `0x0ADE0E` **fallthrough** | unresolved | **`0x40002D20`** ✅ CONTROL PASS |

Two structural facts, both worth keeping:

- **All three entries have `0 refs, 0 CALL/JUMP` from the reference manager** and were reached
  *only* by byte-adjacency. This is rule 19's signature exactly: they are sweep-split blocks of
  one routine, not independently-called functions. Had this used `getCallingFunctions()` it
  would have reported "no callers" and concluded the code was dead — the documented false
  negative this project has already paid for once.
- **`r31` is not defined within 300 instructions of any entry**, while `r7` resolves cleanly at
  one of them. Since the control passes on the same walk, this is a **real negative, not an
  instrument failure**: `r31` is established further up the call chain (it is a long-lived
  callee-saved base held across the whole feature task), and a linear backward walk cannot
  reach it.

⚠ The first run of `290` **failed its own control** (`r7 = 0x40000000`) for an instructive
reason: the walk started at `getPrevious()` of the predecessor, skipping the predecessor
instruction itself — but for a **fallthrough** the predecessor *is* part of the stream and at
`0x0ADE0E` it is the very definition sought (`e_add16i r7,r7,0x2d20`). Fixed with an
`inclusive` flag (correct for fallthrough, wrong for a call site, since a call defines nothing).
Third instrument bug this session caught by a control rather than by inspection.

⇒ **`r31` will not yield to static walking.** Resolving it needs either the task-level caller
(the `APP_feature_periodic` dispatch that owns this block's state) or — far cheaper — the
**bench**: peek the candidate range while the feature runs and watch which cells move.

### 7.0.3 What the fixed walker DID establish (a)

Repairing the `rA`-vs-`rD` bug (the script now records offsets off an unknown base instead of
inventing a value) turned the noise into two clean results:

| site(s) | form | meaning |
|---|---|---|
| `0xAD9AC`, `0xADB4A`, `0xADC86`, `0xADD56`, `0xADDCC` | `<r31>+0x6C/0x5C/0x54/0x44` | the feature's own state block — **base still unknown** |
| `0xADE68`…`0xADFE8` (**8×**, all in `FUN_000ADE12`) | `<r7>+0x80` | **r7 = `0x40002D20`**, set at `0xADE0E` |

The second row **independently re-derives §7.1's struct base by a different route**. `r7` is
loaded with `0x40002D20` immediately before the block, so `r4 = r7 + 0x80 = 0x40002DA0`, and
`r4 + 0x02` = **`0x40002DA2` = `APP_rke_command_code`** — i.e. `r4` is simply a *shifted view*
(+0x80) of the same RKE struct. That is a second, independent confirmation of the base I first
derived from the `+0x82` field alone, and it makes the §7.1 field table a derivation rather than
an assumption:

| offset (r7 view) | address | field |
|---|---|---|
| `+0x082` | `0x40002DA2` | `APP_rke_command_code` |
| `+0x084` | `0x40002DA4` | fob / transmitter ID |
| `+0x25A` | `0x40002F7A` | output → MS `0x1A4` d0[5:4] (§7.2) |
| `+0x271` | `0x40002F91` | case-4 input |

`+0x25A` reproducing `0x40002F7A` — the exact cell `tx_signal_dict.json` binds to MS `0x1A4` —
is the acceptance test, and it passes. **Two struct bases, one resolved, one open:** the RKE
struct is `0x40002D20` (confirmed twice); the `r31` state block remains unknown.

### 7.1 `FUN_000ADE12` — the press-SEQUENCE state machine (b)

`switch ((r0 >> 0xC) & 0xF)` over ~8 states, every arm re-testing the RKE struct. Deriving the
struct base from the known field (`param_5 + 0x82 == APP_rke_command_code 0x40002DA2`) gives
**`param_5 = 0x40002D20`**, and the arms then read:

| offset | address | role |
|---|---|---|
| `+0x82` | `0x40002DA2` | `APP_rke_command_code` (enum tested `== 8`, `== 1`, `== 0`) |
| `+0x84` | `0x40002DA4` | compared against `param_3 + 0x7F` — a **transmitter/fob identity** match |
| `+0x25A` | `0x40002F7A` | the arm's **output** cell |

State 8 is the interesting one: it requires **`enum == 8` AND two flags AND the fob-ID match**,
then advances the state; a separate arm accepts **`enum == 1` (LOCK)** and *stores the fob ID*
into `+0x7F`. That is exactly the shape of "**LOCK first, then RemoteStart**" — the LOCK press
registers which fob is talking, and the RemoteStart arm refuses unless the same fob returns.
`LAB_000AE052` runs the same `+10` per-tick timer as `FUN_000ADADA`, i.e. a bounded window.

This is a much better-grounded candidate for the press-sequence requirement than the earlier
`DAT_40008D75` guess, which is hereby **withdrawn as the latch hypothesis** (it remains the
arming flag `FUN_00087486` gates on, nothing more).

### 7.2 ⚠ Falsifiable prediction — CONFIRMED ONCE, REFUTED TWICE (do not use)

The output cell `0x40002F7A` resolves through `tx_signal_dict.json` to **MS `0x1A4` d0,
mask `0x30`, shift 4** (site `0x4CE70`). Prediction (rule 11): that field should rise on a
remote-start press and stay 0 on a normal key start.

| capture | result |
|---|---|
| `CANBus/mscan_remotestart.log` | **0 → 1 at t=3.183**, between the enum-8 press (3.159) and the run indicator (3.613); back to 0 at 3.434 | 
| `mscan_remote_start2.log` (cap2) | **flat 0** |
| `mscan_remote_start.log` (cap1) | **flat 0** |
| normal-key control | 0 ✓ |

**This is NOT a sampling artifact and must not be explained away as one.** The pulse is 250 ms
against a measured 50 ms period (5 frames), and cap2 has **24 consecutive `0x1A4` frames** across
the identical press window, every one `d0=0x40`, field 0. The frame was present and observed.

⇒ Per rule 40 (*a novel value is not a result unless it RECURS across stimulus passes*), the
field is **1-of-3** and therefore **not an established remote-start indicator**. Something else
gates it — the two sessions differ in ways not yet isolated. Recorded because the temptation to
report the single clean hit as "prediction confirmed" was real, and the two nulls are the more
informative half of the measurement. The `0x40002F7A → 0x1A4 d0` *binding* is sound (it comes
from the pack descriptor); what the field **means** is open.

> ⚠ **NOT ESTABLISHED:** the edge from `FUN_000ADADA` to `FUN_00087486`'s
> `APP_power_mode = 4`. They are in different regions (`0x0AD…` vs `0x087…`) and no call or
> flow edge between them has been demonstrated. The natural bridge is the request-word bus
> (`req90`/`req94` here vs `req70`/`DAT_40008D75` there), but per rule 23 a reachability claim
> is worthless without unrelated-site controls, and per rule 43 a static edge would still not
> prove a runtime one. **This is the remaining link.**

⚠ Instrument note: `288`'s p-code arm **failed its positive control** (it could not reproduce
the known struct-field reader `0x8D522`), so its silence is INCONCLUSIVE (rule 27) and no
conclusion above rests on it. The findings come from the reference manager plus the
compare sweep, whose control (`FUN_00087486` as a reader of the arming flag) **passed**.

---

## 8. Status — ⚠⚠ SOLVED, see `docs/vehicle_session_1.md` §10–§11

> **The trigger mechanism is closed.** The missing piece was never the command *value* — it was the
> **announce**. `0x40003F53` is a Volcano dirty-flag byte; the remote-start consumer at `0x0AEEDA`
> calls `VOL_test_and_clear_dirty(&flag, 2)`, i.e. it tests mask **`0x20`**. Writing the command
> code alone leaves it resident forever with no consumer ever informed.
>
> **The real receive path does both, in this order:**
>
> ```asm
> 0x058568  se_bmaski r0,0x8     ; r0 = 0xFF
> 0x05856A  e_stb r0,0x51(r30)   ; 0x40003F53 = 0xFF   <-- ANNOUNCE
> 0x05856E  e_sth r3,0x82(r31)   ; 0x40002DA2 = code
> ```
>
> **Confirmed on bench #1 by injection**, depth 5 vs depth 2, both orders, identical command code in
> every arm and only the announce byte varied: **2/2 advanced vs 0/2**. The read-back is the proof —
> `0xFF` written, `0x9F` read back, i.e. bits `0x60` cleared = Volcano indices **1 and 2**, exactly
> the two predicted consumers test-and-clearing their own bits and no others.
>
> This supersedes items 1 and 4 below and the whole "vehicle-only from here" framing of §8.1.

**Established (a):**
- RKE enum 8 = RemoteStart, on MS `0x100` d6:d7 — 3 captures, and read from the ECU's own cell.
- **The announce byte `0x40003F53` mask `0x20` is the arrival signal** — bench-confirmed with a
  matched negative control (`vehicle_session_1.md` §11).
- **The chain `0x0AEEDA → 0x400095E1 → 0x0ADA24 → 0x0ADA3E → bit 27 of 0x40009680`** reproduced on
  hardware by injection alone.
- MS `0x80` d2 = `APP_power_mode`<<5 | ignition-code, from `tx_signal_dict.json`.
- `0x3A` d4 bit7 is **not** remote-start-specific (refuted).

**⚠ REFUTED since this section was written:**
- ~~`APP_power_mode == 4` ⇔ remote-start run~~ — **refuted on the vehicle**
  (`vehicle_session_1.md` §3): constant `0x04` before, during and after a genuine remote start, on
  two independent channels (peek and the `0x80` wire). Do not use it as a discriminator or as a
  success observable. The **run timers** (`0x40009620` / `0x40009658`) are the correct signal.
- ~~`0x40009680` bit 27 is the remote-start gate~~ — it opens for **any** fob button in **any**
  vehicle state (operator observation, `vehicle_session_1.md` §1). It is a receiver-active
  indicator, not a command-specific gate.

**Still open:**
1. **Does the announce produce an actual engine start?** Bench #1 cannot reach ignition-ON, so §11
   confirms the RAM chain and *not* the outcome. `0x4000968B` stayed `0x00` in all four bench arms —
   expected without ignition, but unresolved.
2. **What gates MS `0x1A4` d0 bits 4-5** (§7.2) — fires in 1 of 3 captures; binding sound, meaning
   open.
3. **The 8 computed (non-immediate) writers** of `APP_power_mode` were never resolved.

### 8.1 ⚠ SUPERSEDED next-steps (kept for the record)

The reasoning below was written when `APP_power_mode == 4` was still believed to be the
discriminator and the bench was thought useless for this feature. **Both premises turned out to be
wrong**: the mode-4 theory was refuted on the vehicle, and the bench went on to *settle the actual
mechanism* — because the announce chain is pure RAM state and needs no ignition. Retained because
the error is instructive: the bench was declared closed for a feature it was perfectly capable of
deciding, once the right question was asked of it.
1. ~~**The hop from RKE enum 8 to `FUN_00087486`.**~~ **Half-closed** (§7): the enum-8
   *consumer* is `FUN_000ADADA` @ `0x0ADADA`, which tests `(code & 0xF) == 8` literally and
   runs a 10 ms-tick hold timer. **Still open:** the edge from that module to
   `FUN_00087486`'s `APP_power_mode = 4` — different code regions, no demonstrated call or
   flow edge, likely via the request-word bus. **Static walking is exhausted** — §7.0.2 is a
   controlled negative: `r31` (the state block holding the `+0x90`/`+0x94` request words) is not
   definable within 300 instructions of any entry, and all three entries are sweep-split blocks
   with zero CALL/JUMP refs. Resolve it on the **bench** instead (peek the range while the
   feature runs), not with another walk.
2. ~~**That `DAT_40008D75` is the two-press latch.**~~ **Withdrawn** (§7.1) — a better-grounded
   candidate is `FUN_000ADE12`'s state machine, whose state-8 arm requires enum 8 **plus a
   fob-identity match** against an ID stored by the **enum-1 (LOCK)** arm. That matches the
   observed LOCK-then-RemoteStart operator sequence. `DAT_40008D75` remains only the arming
   flag `FUN_00087486` gates on.
3. **What gates MS `0x1A4` d0 bits 4-5** (§7.2) — fires in 1 of 3 remote-start captures with
   the frame demonstrably observed in the other 2. Binding is sound; meaning is open.
4. **Which of the 6 sites actually fires on the vehicle.** Static reachability is not runtime
   reachability (rule 43), and a reachability result means nothing without unrelated-site
   controls (rule 23).
5. **The 8 computed (non-immediate) writers** were not resolved; one could also produce 4.

> ⚠ **§7.0.2's r31 negative is SUPERSEDED** — r31 resolves to a preferred base `0x400095EC`
> (a second candidate `0x400095D4` survives), see `docs/bench_session_4.md` §8. The negative was
> correct for its 300-instruction scope; the module is larger than that scope.

### Next steps — ⚠ REVISED after bench session 4 (`docs/bench_session_4.md`)

**The bench route is closed.** The bench unit cannot turn ignition ON and would never perform a
remote start (operator, §6.4 of that note), and `APP_power_mode == 4` requires that state. Seven
conditions across two channels returned mode 0; those nulls are properties of the **fixture**,
not of the firmware, and no further bench experiment on this feature is warranted.

What the bench *did* settle, and it is not nothing:

- ✅ enum 8 reaches `APP_rke_command_code` as `0x1808`/`0x1818` — §1's decode **confirmed on
  hardware**, read from the ECU's own cell.
- ✅ the rig drives this BCM end-to-end (LOCK → `APP_lock_command 0x01` → `0x3A` d3 = `01`).
- ✅ `APP_power_mode` is live (4 documented mode-1 pulses, 59–61 ms).
- ❌ refuted along the way: the `d7 bit4` guard term, the config bytes, and `0x3A0`-as-an-input
  (it is a BCM **TX** frame — mailbox 36 transmits it).

1. **Vehicle-only from here.** H2/H3 (fob identity), the `0x0AD…`→`0x087…` edge, and `r31` all
   need a car that can actually enter remote start. Capture `0x80` d2 continuously (62 ms — the
   superior channel, `bench_session_4.md` §3.2) rather than relying on peek sampling.
2. ~~Find enum 8's dispatcher.~~ **Done** — `288_enum8_dispatch_hunt.py`, §7.
3. ~~Read the config bytes.~~ **Done** — `bench_session_4.md` §4.3; they acquit themselves
   (`0x8116 = 2` ✓, `0x81F3 = 2` ✓, `0x8154 = 1` routes *toward* the mode-4 arm).

**If the goal is a mod rather than an explanation**, the vehicle is not strictly required: the
targets are already located and confirmed — `APP_power_mode` (`0x40001D85`, field +5 of the
struct at `0x40001D80`), its three dirty flags `0x40003EB6/B7/B8`, and the six immediate-4
writers of §5. A cave that sets mode 4 + the flags does not care why the stock guard refused.

⚠ But note the risk class differs from the shipped mods: acc-fix and rke-lock **rewrite a TX
mailbox byte**, whereas this would change *what the BCM believes about vehicle power state* —
which other modules consume. That needs its own analysis before any VBF is built; nothing in
this project validates it yet.
