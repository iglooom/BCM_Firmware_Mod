# Live debugging via UDS — feasibility, and the cheapest route

**Question asked:** do we know where the UDS services live, and can we add/modify a
*read-memory-by-address* service so a live session can read any RAM address?

**Short answer: yes, and the cheapest route is not a new service at all — it is the existing
492-entry DID table, whose smallest reader is a 14-byte function with the read address stored as
two plain immediates.** Nothing has been patched; this note records the evidence and prices the
options.

Scripts: `work/owner/265_uds_live_debug.py`, `266_did_hook_plan.py`. Image: owner full flash.

---

## 1. `0x23 ReadMemoryByAddress` does not exist in either loader (a, already known)

| where | status | source |
|---|---|---|
| PBL (primary bootloader) | absent from the 12-entry permission table @`0x43C` **and** from the dispatcher | `owner_flash_layers.md` §6.2 |
| SBL (secondary loader) | live request returns `7F 23 7F` | `sbl-upload-patch.md` |

The PBL's complete service set is `0x10 0x11 0x27 0x22 0x3E 0x2E 0x31 0x34 0x35 0x36 0x37 0x19`.

**The application is a separate question**, and that is what `265` measured.

## 2. The application: SID compares exist, but that is *not* proof of a service (b)

A full-image sweep for immediate compares (control: SID `0x22` must be found — it was, including
`PBL_uds_dispatch` `0x22BA`) reports:

| SID | compare sites |
|---|---|
| `0x22` ReadDataByIdentifier | 8 (incl. the PBL dispatcher) |
| `0x2E` WriteDataByIdentifier | 3 |
| `0x23` | 19 |
| `0x3D` | 19 |

⚠ **Do not read the `0x23`/`0x3D` counts as "the app implements them."** `0x23` and `0x3D` are also
ordinary small integers; the sites found sit in functions like `FUN_0008898C` and `FUN_0002AAD0`
with no diagnostic context. Deciding this properly means checking whether any of them is reached
from the app's request dispatcher — **not yet done**, and the numbers alone are meaningless
(rule 9: coverage is not agreement).

## 3. The DID route — the real opportunity (a)

`APP_did_identifier_array` @ `0x01FFCC`, **492** identifiers, 2-byte stride, ending `0x203A4`.
First entries verified: `0x0202 0x0329 0x0631 0x203E 0x203F 0x2040 0x2041 0x2042`.

Reader sizes: **min 10, median 38, max 1576 bytes**. The smallest are ideal templates:

| size | DID | reader |
|---|---|---|
| 10 | `0xE203` | `0xE210C` |
| 14 | `0x0631` | `0xDE278` |
| 14 | `0x401B` | `0xDE312` |
| 14 | `0x406B` | `0xDE58A` |

### The template, byte for byte

```
de278  70 E8 E0 00   e_lis  r7,0x4000        ; address high half
de27c  30 E7 19 C4   e_lbz  r7,0x19c4(r7)    ; address low half  -> reads 0x400019C4
de280  90 73         se_stb r7,0x0(r3)       ; store into the response buffer
de282  01 43         se_mr  r3,r4
de284  00 04         se_blr
```

**The read address is two immediates.** Re-pointing this DID at any RAM byte is a **4-byte edit** —
no code cave, no dispatcher change, no new service.

## 4. Two options, priced

### Option A — static probe DID (minimal, safest)
Patch the two immediates of one spare reader so a chosen DID returns a chosen RAM byte.
**Cost: 4 bytes.** Risk profile identical to `acc-fix`/`rke-lock`: a wrong address is a wrong
*reading*, not a brick. Limitation: the address is fixed per flash.

Immediately useful for: `[r29]` in the `0x1E0` enum guard (§5.8) — patch the probe to each candidate
and compare against the bench's known `1→2` transition; `0x1E0` d0 bit 5; and item 41, by probing
`req_word_74` while pressing the fob.

### Option B — arbitrary-address probe DID (a real debugger)
Point one DID's handler at a small cave that takes the address from the **request** buffer — a poor
man's `0x23`. **Cost: one vector entry + ~40–60 bytes of cave.**

**The one blocker:** a DID reader's signature is `(r3 = response buffer, r4/r5/r6 = context)`; where
the *inbound request bytes* live at that moment is **not yet established**. It must be recovered
from `APP_did_dispatch_switch` `0x0DBD34`. That is the single unknown between us and a general RAM
reader — and it is a static question, answerable without the bench.

⚠ `0x20B80..0x21318` (486 entries) is **not** the per-DID vector table: every entry points at
`APP_did_dispatch_switch` itself, so it is a thunk/trampoline table. The real per-DID vector is
inside the dispatcher and still has to be located.

## 5. Both options need all three integrity layers repaired

`AGENTS.md` §2.1/§5: internal `sum8` → per-block CRC-16 → file CRC-32, delivered byte-exact. The
existing `work/acc-fix/build_vbf.py` pipeline already does this and can be reused verbatim.

## 6. ⚠ A tooling trap found while doing this (rule 8)

`memory.getBytes(addr, bytearray(n))` **silently writes nothing and still returns `n`** — a false
success. It made `266` report the template as 14 zero bytes *while the listing showed real code at
the same address*, and every derived structure (identifier array, pointer table) came out empty.

JPype only fills a genuine Java array:

```python
from jpype.types import JArray, JByte
arr = JArray(JByte)(n); mem.getBytes(addr, arr)
```

`mem.getByte()` in a loop also works. `266` now begins with a **self-check** that compares a
memory read against `listing.getInstructionAt(...).getBytes()` and refuses to run on mismatch.

---

## 7. What is NOT established

- Whether the **application** implements `0x23`/`0x3D` at all (the 19+19 compare sites are
  uncontextualised integers, not evidence). **Moot for Option A** — we no longer need them.
- Where the app's **request buffer** is when a DID reader runs — blocks Option B only.
- The **real per-DID vector table** inside `APP_did_dispatch_switch`.
- Whether security access (`0x27`) gates `0x22` in the *application* (ungated in the PBL table).
- Whether any chosen DID is used by the scan tool — **irrelevant on the bench** (user: modify
  freely), but it would matter for a vehicle build.

---

## 8. ✅ Option A is fully specified — a 17-probe bank, assembled and round-tripped

Everything Option A needs is now measured. Scripts `267`–`271`.

### 8.1 Reader inventory (a)

492 identifiers, classified by load/store width:

| shape | count | use |
|---|---|---|
| load1/store1 | **171** | the probe template |
| load2/store2 | 25 | halfword probes |
| load4/store1 | 21 | |
| load4/store4 | 6 | 4-byte watch windows |
| other | ~40 | |

**93 readers** are exactly the 14-byte template form *and* carry table length 1 — far more than the
17 probes needed.

### 8.2 The response-length table @ `0x21318` (a)

Length is **not** inferred from the reader; it is a byte-per-DID array immediately after the thunk
table, index-parallel to `APP_did_identifier_array`.

Validation (script `269`): **318/357 exact**, against a **49.0 %** best shifted-base control — and
that control matters, because 59.4 % of DIDs have length 1, so any block of `0x01` scores ~59 % by
luck. All **39** disagreements are `table ≥ measured`, i.e. one-sided: my `response_len()` counter
under-reports (stores via a re-based register, loop copies, unswept tails), so **the table is right
and my measurement was the weaker instrument**.

⇒ A length-1 probe returns 1 byte with **no length-table edit**. Widening to 4 bytes means picking a
reader whose table entry is already ≥ 4.

### 8.3 ⚠ The bug that would have silently produced garbage probes

Script `270` decoded the template's watched address by reading plain 16-bit fields out of the
instruction bytes, and reported `0xDE278` as reading **`0xE00019C4`**. The listing says
**`0x400019C4`**. The VLE `e_lis` immediate is a **split field** — `0x4000` is *not* at `bytes[2:4]`:

```
70 E8 E0 00  =  e_lis r7,0x4000      <- high half is SPLIT across the encoding
30 E7 19 C4  =  e_lbz r7,0x19c4(r7)  <- low half IS contiguous at [2:4]
```

Hand-assembling would have written probes pointing at nonsense addresses — a wrong *reading*, not a
crash, and easily mistaken for a firmware finding. `AGENTS.md` rule 3 already forbids this: assemble
VLE **only** with Ghidra's assembler (`contextreg = 0x20000000`) and round-trip every instruction.
`271` does that, and its first act is to assert `assemble("e_lis r7,0x4000") == the template bytes`.

A second trap handled: when the low half has bit 15 set, `e_lbz`'s displacement is **signed**, so the
high half must be pre-incremented (`0x40008E74` → `e_lis r7,0x4001` + `e_lbz r7,-0x718c(r7)`).
7 of the 17 probes need this; all round-trip.

### 8.4 The bank

**17 probes, 0 round-trip failures.** Each is a 4-byte edit to one reader's two immediates.

| DID | watches | why |
|---|---|---|
| `0x0631` | `0x40002E70` | **POSITIVE CONTROL** — `APP_lock_command`, bus already shows `01/02/06` |
| `0x401B` | `0x40002EEC` | the `0x1E0` mode enum — bench saw 1→2 |
| `0x406B` | `0x40003FD7` | its pack dirty flag |
| `0x4085/97/99/A1` | `0x40008E74..77` | `APP_req_word_74` all 4 bytes — **open item 41** |
| `0x40A6/A9` | `0x40008E58/5A` | `APP_body_cmd_bus` — the 3-bit RKE command field |
| `0x40BE/C0` | `0x40002DA2/A3` | the 13-bit fob command code |
| `0x40D1` | `0x40008D3A` | `APP_rke_join_gate` — meaning unknown |
| `0x411B` | `0x40003CE6` | timed-feature output cell |
| `0x411F` | `0x40008D2C` | Path A's edge-detector input |
| `0x4120` | `0x40008E70` | `req_word_70` bit 3 = lock request |
| `0x4125/2D` | `0x40000A57/58` | MS `0x1E0` d0 (the unclaimed bit 5) and d1 |

**The positive control is not optional.** If `0x0631` does not track the value already visible on
`0x3A` d3, the bank is untrustworthy and no other probe may be believed.

Read on the bench with `22 <hi> <lo>` on can0 (tester `0x726` / ECU `0x72E`), polled in a loop while
driving the RKE stimulus, correlated against the existing candump + acoustic channels.

### 8.5 ✅ Validated against the real ECU *before* flashing

`work/bench/did_probe.py` — plain `0x22` reads on the bench BCM, stock firmware:

- **16 of 17 DIDs SERVED**, each returning **exactly 1 byte**.
- `0x406B` → NRC `0x31 requestOutOfRange` (present in the table, not served by the app).
  Replaced with **`0x412E`** (verified SERVED, 1 byte, value `86`); 77 spare template readers remain.
- **No security gate**: every read succeeded in the default session, with no `0x27` — so the probe
  bank is readable with nothing more than TesterPresent keepalive.

**The length table is now confirmed on the wire**, not just statically: all 16 served DIDs replied
with 1 byte, exactly as `0x21318` predicts. That is an independent dynamic confirmation of §8.2.

OEM idle values (the guard rail for recognising a probe that took):

| DID | OEM | DID | OEM | DID | OEM |
|---|---|---|---|---|---|
| `0x0631` | `00` | `0x40A1` | `00` | `0x411B` | `08` |
| `0x401B` | `00` | `0x40A6` | `00` | `0x411F` | `00` |
| `0x4085` | `00` | `0x40A9` | `01` | `0x4120` | `00` |
| `0x4097` | `00` | `0x40BE` | `05` | `0x4125` | `14` |
| `0x4099` | `09` | `0x40C0` | `00` | `0x412D` | `00`/`01` |

### 8.6 ⚠ A second uncontrolled-result near-miss

The first baseline run reported a tidy **"0 DIDs vary under the stimulus"**. It was meaningless:
`did_baseline.py` invoked `rfa_sim.py press <nibble>`, but that script's press mode takes
`--cmd {idle,lock,unlock}`. **Every press failed with an argparse error**, output swallowed by
`DEVNULL` — so the DIDs were "static" because *nothing ever happened*.

This is `AGENTS.md` rule 8 again, and it would have been indistinguishable from a real negative
after the flash. Fixed: `verify_stimulus()` now fires one press up-front, checks `rfa_sim.py`'s exit
status, and counts **MS `0x3A` execute-strobe frames on the wire**, refusing to record a baseline
unless the stimulus is confirmed. The corrected run reports **3 strobes seen → ✓ confirmed**, and
*then* finds all 17 static — which is now a real result.

(The re-run also showed `0x412D` reading `01` where the first pass read `00`: OEM cells do drift, so
"differs from baseline" alone is not proof a probe took. The positive control is what settles it.)

### 8.7 ✅ The VBF is built and verified

`work/probe-bank/build_vbf.py` → **`work/probe-bank/JV6T-14C094-AD_probe-bank.VBF`**
sha256 `6f1d1982ec5a06b2916d607cf085ab9bd29c428a6b37f64b342db6e0b548be07`

**Addressing cross-check first** (rule 5 — the two Ghidra projects are not interchangeable): all 17
reader addresses came from `ghidra_proj_fullflash`, so before patching anything the builder asserted
their OEM bytes against the **VBF app block**. **17/17 matched byte-for-byte**, so the fullflash
addresses are valid file offsets here.

Integrity repaired in order: `sum8 0x7572 → 0x77CB`, CRC-16 `0x9CE3` / `0x52E7`, CRC-32 `0x5000CEA7`.

`work/probe-bank/verify.py` — fully independent, re-reads the artifact from disk:

| check | result |
|---|---|
| both block CRC-16 | **PASS** |
| file CRC-32 | **PASS** |
| internal sum8 | **PASS** |
| 17 probes written, OEM tails intact | **PASS** |
| diff vs OEM = expected clusters only | **PASS** — 18 clusters, 18 explained (17 probes + sum8) |
| **probes decode to the intended address** | **PASS — 17/17** |

The last row is the one that matters. It writes the rebuilt bytes into a scratch program (rollback
transaction), sets VLE context, lets **Ghidra disassemble**, and reconstructs the address from
*Ghidra's decode* — not from the immediates I wrote. That is an instrument independent of the one
that built the bytes, and it is exactly what catches the §8.3 split-field class of bug:

```
0x4085  e_lis r7,0x4001   e_lbz r7,-0x718c(r7)  -> 0x40008e74 OK
0x4125  e_lis r7,0x4000   e_lbz r7,0xa57(r7)    -> 0x40000a57 OK
```

### 8.8 Reading the bank — and the acceptance test

`work/bench/probe_read.py` with three modes: `idle`, `watch --cmd lock`, and **`control`**.

**`control` must be run first and must pass before any other probe is believed.** It polls only
`0x0631` (watching `APP_lock_command`) while pressing lock and unlock, and simultaneously captures
MS `0x3A` d3 — the *same cell seen on the wire*. Probe and bus must agree. If they don't, the flash
didn't take or the DID route doesn't read what we think, and the whole bank is void.

#### ⚠ 8.8.1 The sample-rate trap — measured, not assumed

§8.9 originally listed "polling may be too slow" as an open risk. Measuring it turned a *guess* into
a **fixed bug**:

| implementation | rate | verdict vs a 0.10 s transient |
|---|---|---|
| `candump` subprocess per read (first version) | **1.3 Hz** | hopeless — would report "nothing changed" |
| persistent raw `AF_CAN` socket | **100.2 Hz**, 401/401 answered | comfortable |

The ECU answers in **9 ms median** (min 1.6 ms). The entire 77× gap was **host-side subprocess
overhead**, not the BCM. Had this shipped unmeasured, the bank's first real run would have produced
a clean, confident, entirely false negative — the same failure family as §8.6, caught this time
*before* it cost a trial.

`probe_read.py` now uses one persistent socket for all modes and **prints its achieved Hz**, so the
sample rate is visible in every result rather than assumed. `watch` also records a timestamped
change-trace per probe, not just a value set.

#### 8.8.2 Tooling exercised against the stock unit

`idle` mode, run on the **unflashed** bench BCM: **17/17 DIDs respond**, returning the OEM values of
§8.5. (The earlier intermittent `NO-RESP` on `0x40D1` was the slow poller's timeout — it disappears
at socket speed, confirming it was an instrument artifact.)

**This validates the reader tooling, not the probes.** The bench unit is still on stock firmware, so
every value is an OEM cell.

---

## 9. ✅ §4 Option B's blocker is RESOLVED — see `docs/uds_peek_design.md`

§4 priced "Option B — arbitrary-address probe DID" and recorded one blocker: *"where the inbound
request bytes live when a DID reader runs is not established."* Scripts `272`–`279` settle it, and
the answer **refutes Option B as framed while enabling something better**:

- **A DID reader can never see the request.** `APP_did_read_dispatch` @ `0x107C1A` is
  `(idx, buf, len, offset)` and the per-DID readers are `(response_buffer, context)`. No request
  pointer exists anywhere in that ABI.
- **The service layer above it holds the request as an absolute global.** `FUN_0010B65E` @ `0x10B65E`
  uses request object `0x4000538C` and response object `0x400053A4`, with accessors
  `FUN_001098DE(msg,i)` (get request byte), `FUN_00109916(msg,b)` (append response byte),
  `FUN_001098D0(msg)` (length) and `FUN_00109D26(nrc)` (set NRC). It reads the DID out of the request
  two bytes at a time — exactly the operation a peek handler needs.

⇒ A **genuine `0x23`-equivalent peek** is buildable as one hook + one cave (~90–140 bytes), with
**167,661 bytes** of contiguous `0xFF` padding confirmed free at `0x1170F3`. Full design, wire
format, safety bounds, the refuted resident-SBL alternative, and the acceptance-test order are in
**`docs/uds_peek_design.md`**. The probe bank below remains valid and is the cheaper option while
the peek handler is unbuilt.

### 8.9 What is still NOT established

- **The bank has not been flashed.** Every probe reading so far is OEM firmware.
- Whether a repointed reader can read a cell **outside** the OEM reader's own memory window (the
  load is absolute, so there is no reason it shouldn't — but it is unproven on hardware).
- Whether `0x22` polling at 100 Hz **perturbs** the behaviour under study (a diagnostic load that
  heavy is not free; the acoustic channel is the independent cross-check if this is ever suspected).
- Items 30 and 41 remain open until the bank runs on the flashed unit.
