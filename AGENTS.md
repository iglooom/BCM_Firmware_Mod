# AGENTS.md — Porting the ACC-FIX SWM cruise-button remap to another OEM BCM firmware

Audience: an AI agent (or engineer) asked to reproduce the **ACC-FIX** modification on a **different
OEM version** of this Ford BCM firmware (different part suffix, MY, or calibration) than the one it
was developed on (`JV6T-14C094-AD`). This is a **method** guide: every address below is
version-specific and **must be re-derived** on the target image — do not paste them in blind.

Read first: `README.md` (§2.1 integrity, §4 gateway model, §5.4 ACC-FIX, §7 retractions),
`docs/acc-fix.md` (exact current build), `docs/gateway_map.md` (table layouts + frame maps),
`docs/0c0_standby_read.md` and `docs/030_composition_trace.md` (evidence).

> **Worked second example — same method, different bus/frame:** the shipped **`rke-lock`** mod
> (`docs/rke-lock.md`, README §5.5) reuses this exact TX-mailbox-injection technique on **MS-CAN
> (CAN1) `0x3A`** instead of HS-CAN `0x030`, layered into the **same two caves** as acc-fix (no new
> hook) and delivered as one combined VBF. It demonstrates: re-deriving the MB-CS gate for a
> different controller (`0xFFFC4090`), reading RX-image inputs + a raw TX-mailbox byte for a gate,
> a second proven-unused scratch byte next to acc-fix's, and — the key on-vehicle lesson — that a
> command bit can be a **one-shot strobe** not a level (capture the ECU's *own* native action to
> learn the exact frame shape before injecting). See `docs/key_outside_gate.md` for the full
> capture-driven v1→v2→v3 debug history.

---

## 0. What ACC-FIX does (recap)

The BCM composes TX HS-CAN **`0x030`** from LIN steering-wheel-module (SWM) buttons. A new SWM puts
its cruise combo buttons on bits the **old PCM** ignores. ACC-FIX installs a small **code-cave
trampoline** at the FlexCAN TX choke point that, **only for the mailbox carrying `0x030`**, rewrites
the assembled payload:

- `ACC_Res_Plus` (d1 bit6) → **CC_Res** (d5 bit5) if cruise/limiter is *cancelled with a stored
  set-speed*, else **CC_Set_Plus** (d5 bit7); clears d1 bit6. The decision is **edge-latched** for
  the whole press (§F2).
- `ACC_Lim` (d1 bit5) → **CC_Lim** 2-bit field d6[5:6] = `0b10` (pressed); clears d1 bit5.
- The Resume-vs-Set+ discriminator needs **two** received frames — `0x0C0` d0 (PCM status) AND
  `0x060` d6 (stored set-speed). Single-byte tests on `0x0C0` d0 all failed on the vehicle (§E).

The remap is done at the mailbox because d1 and d5/d6 come from **different composition PDUs** and
cannot be moved earlier. See §7 of this file if the target maps buttons differently.

---

## 1. Golden rules (do not skip)

1. **Verify, don't assume.** Every address (hook site, cave, MB gate constant, 0x0C0 read address,
   integrity fields) is version-specific. Re-derive each with evidence (decompiled code + xrefs),
   cross-checked two independent ways where possible. The project history is full of costly wrong
   assumptions (README §7); the biggest wins here came from *disproving* a guess with a capture.
2. **Three integrity layers or the BCM bricks to safe mode.** After ANY app-block edit you MUST
   repair, in order: (1) internal `sum8`, (2) per-block CRC-16, (3) file CRC-32. Missing the
   *internal* one boots the BCM into a software-integrity fault (real-vehicle observed). README §2.1.
3. **Assemble VLE only with Ghidra's assembler**, and **round-trip every instruction** (assemble →
   write → re-disassemble → compare). `llvm-mc` has no VLE target; binutils VLE isn't installed. The
   Ghidra assembler needs the **VLE context** fully specified (`contextreg = 0x20000000`) or it
   errors "Incompatible context". See §4 + `work/acc-fix/build_caves.py`.
4. **Deliver the app block byte-exact** (no re-alignment/re-padding) or `sum8` drifts.
5. **Four Ghidra projects — never mix them.** `ghidra_proj/` (`BCM_C1MCA`, `work/flash_merged.bin`,
   OEM VBF set) is what the shipped `acc-fix`/`rke-lock` VBFs are **built and verified against** —
   `work/acc-fix/{build_caves,annotate_ghidra,verify}.py` all open it, so it must not be deleted or
   repointed. `ghidra_proj_fullflash/` (`BCM_OwnerFlash`, `cflash.bin`) is the **primary analysis**
   project and the only one containing anything below `0xC000` (the 48 KB PBL), the shadow array and
   DFlash. Also present: `ghidra_proj_accfix_rkelock/` (built mod image) and `ghidra_proj_sbl/`
   (`SBL`). Addresses are **not** interchangeable between them.
6. **Read-only Ghidra, single holder.** Open the project read-only for analysis; only the annotate
   step opens writable. Always `project.close()` in `finally`. One process at a time.
7. **The final proof is a candump on the car.** Static analysis cannot fully close the
   frame→mailbox binding; confirm on the bus. Worst realistic failure is a no-op (gate never fires),
   not a brick — provided integrity is repaired.
8. **A scan whose result is *constant* across every input is as suspect as one returning zero.**
   Both usually mean the scan is broken, not that the target is empty/uniform. Before reporting
   "X is 0 everywhere", check that the field you are reading *can vary at all* — the SIUL `PA`
   fiasco (`owner_flash_layers.md` §28.1) reported `PA = 0` on 48 values from a bit position that
   was identically zero for every value the firmware writes, and that tautology was then re-measured
   and written up as two independent negative results.
9. **Coverage is not agreement.** A cross-check that asks "does *some* entry overlap this bit?"
   will answer yes for almost any input and proves nothing. Compare the *meanings*, not the
   presence: the `0x3A`/`0x100` database check reported a clean "6/6 covered", but reading the
   actual signal names showed only 3 exact matches, 1 partial and **1 outright contradiction**
   (the database calls rke-lock's proven execute strobe a vehicle-speed quality field) — the
   vehicle databases are a generic platform export, not this part number. Where a database and an
   on-vehicle capture disagree, **the capture wins**, and the conflict gets written into the
   listing so nobody later trusts the label. (`docs/owner_flash_layers.md` §36.5.)
10. **Make injectivity the acceptance test for any map that must be one-to-one.** If two sources
   claim the same destination, the *extraction* is broken — drop the clashing pairs rather than
   picking one. `148`'s pad→bit map was non-injective and had to be discarded entirely; the redo
   (`171`) kept only unambiguous pairs (37 of 60), reproduced both capture-verified pads as a
   regression, and independently agreed with the rejected map on 31 of 33 shared pads. Report the
   dropped entries explicitly; a map with honest holes beats a complete one with invented cells.
11. **Validate a bitfield decode with a falsifiable prediction against independent evidence.**
   Not "the datasheet says so" — derive a consequence the decode does not know about and test it.
   For `PA` it was *a pad muxed to a peripheral must never be written via GPDO*: 9/0 vs 0/11,
   perfect separation (§28.3). When a cross-check contradicts you on the one case you understand
   best, suspect the instrument before rationalising the data.
12. **A descriptor scan must model the PRIMITIVE'S WIDTH, or it will report a read byte as unread.**
   The Volcano codec's `VOL_sig_get16`/`set16` read **the descriptor's byte AND THE NEXT ONE**
   (`CONCAT11(mask & *d[0], *(d[0]+1))`), so a 16-bit signal spanning `d6:d7` is anchored on **d6**
   and `d7` never appears in any descriptor, pointer table, or xref. A raw-flash scan for pointers to
   MS `0x100` d7 returned **zero with a passing positive control** — a correct measurement and a
   wrong inference, which had stood as a documented "provably not findable statically" negative
   (`docs/rke_0x100_lock.md` §3, now corrected). Before reporting a byte as unconsumed, ask whether a
   **wider primitive anchored on a lower byte** consumes it. Same family as rule 8: the scan worked,
   the assumption behind it didn't.
13. **Match the firmware's representation, not the wire's.** A signal decoded from captures as
   *bit flags* (`d7 bit0 = LOCK`, `bit1 = UNLOCK`) is consumed in code as a **command enum**
   (`(code & 0xF) == 1`). A classifier looking for a `0x01`/`0x02` bitmask reported "no button decode
   exists" while the decoders sat in plain sight. Wire semantics and internal representation are
   independent; derive the second from the code, never from the first.
14. **"No writer found" is only as strong as the ANALYSER'S COVERAGE — check for unswept blocks.**
   Before concluding a cell is never written, call `getFunctionContaining()` on the neighbourhood of
   its *readers*. If that returns `None`, the region was never swept: Ghidra created no function,
   therefore no references, and **every** reference-based method (xrefs, base-register walks,
   indexed-store scans) is structurally blind there. `0x40008D2C` was declared "no writer, path
   inert" on four independently-controlled negatives; the writer was `se_stb r0,0xc(r29)` at
   `0x9749A`, in an unswept block, found immediately by decompiler **p-code** (which resolves the
   address itself). The measurements were all correct — the *inference* was not.
   Corollary: in this language memory access is modelled as **`CALLOTHER` userops**, not `STORE`
   ops — `0x10000002` = store, `0x10000001` = load, and they are disjoint (a clean way to prove a
   p-code ram operand is a write). A `STORE`-only p-code walk finds **nothing** here.
   (`docs/tx_pack_stage.md` §10, `docs/owner_flash_layers.md` §43.)

15. **`os._exit(0)` in a `finally` block hides tracebacks — a crashing script exits 0 silently.**
   If an exception escapes the body, the `finally`'s `os._exit(0)` terminates the process before
   Python prints it. Always wrap the body in `except Exception: traceback.print_exc()` followed by a
   flush, so a crash is distinguishable from a clean run producing no output.

16. **Parse signed displacements correctly, and never swallow the parse error.**
   `int(d, 16) if d.startswith("0x") else int(d)` raises on `"-0xbc"`, and a bare
   `except ValueError: pass` turns that into a silent omission — **361 stores** vanished from one
   scan this way, including the form the search actually needed (the target sat at `-0xBC` from the
   block base). Strip the sign, parse the magnitude, re-apply the sign; count and report anything
   you skip.

17. **Two controlled scans that DISAGREE is itself the finding — adjudicate, never pick a favourite.**
   Three full-image methods gave three different writer counts for one cell: the p-code `CALLOTHER`
   scan found 1 (blind when the decompiler routes accesses through a **pointer parameter** — a
   658-byte function yielded only 4 ram-resolved ops), a raw base+disp sweep found 3 (right answer,
   **broken instrument**: its register tracker leaked across a function boundary), and Ghidra's
   reference manager found 3 correctly. In the *previous* layer the reference manager was the blind
   one (unswept blocks) and p-code was right — **exactly reversed**. Neither dominates. Reconcile
   them; a method that finds what another cannot must *explain the other's blindness*. Stopping at
   the passing-control p-code scan would have reproduced the "no writer ⇒ path dead" error one level
   deeper. Corollary: **a correct output does not validate a method** — verify the derivation, not
   just the answer. Scope register tracking **per function**, always.
   (`docs/tx_pack_stage.md` §11, `docs/owner_flash_layers.md` §44.)

18. **When a scan's result is suspicious, check its SCOPE before its logic.**
   A writer scan over `0x030000..0x0B0000` found one initialiser and implied a dead path; the same
   scan over the full image plus the reference manager found the live logic writer. State the scope
   in the script's own output so a null result is explicitly a claim about that scope only.

19. **Follow JUMP and FALLTHROUGH edges, not just CALL edges — and never use
   `getCallingFunctions()` to prove "no callers".** That API enumerates calling *functions*, so a
   call site inside an unswept block is silently skipped; it produced a false "0 callers" that became
   a documented open item. The **reference manager** had the caller all along. Likewise, this
   firmware's linear sweep splits one routine into dozens of zero-caller blocks: a CALL-only climb
   from `0x97382` stalled instantly, while a JUMP+CALL+fallthrough climb reached
   `APP_feature_periodic` in 14 hops through 15 such blocks. Use `ReferenceManager.getReferencesTo()`
   and accept any `CALL`/`JUMP` reference, then fall back to byte-adjacency.
   (`docs/tx_pack_stage.md` §12, `docs/owner_flash_layers.md` §45.)

20. **A literal-pointer scan in this image is UNINFORMATIVE unless its control finds one.**
   Addresses are synthesised with `e_lis`+`e_add16i`, so code and data pointers rarely appear as
   4-byte literals: a scan for pointers to `APP_main` and `APP_feature_periodic` returns **zero**.
   Always run that control before reading "no pointer found" as "not in a dispatch table".

21. **Decode `rlwinm`/`rlwimi` with the ROTATE AMOUNT, not just `mb`/`me`.** The rotate is what
   distinguishes an extract from an insert; ignoring it produced impossible field ranges
   ("bits 17..13") and a "3 write, **0 read**" verdict on a live bus field. Per rule 8, a write-only
   field is as suspect as a zero — treat it as a decoder bug until proven otherwise.
   Correct extract: `value = (x >> (32-sh)) & mask(mb,me)`.

22. **When the user supplies a domain constraint, treat it as a falsifier and re-examine your
   method — not just your conclusion.** "The lock button can only arrive on MS-CAN, because the RFA is
   the radio receiver" killed a hypothesis (that the HS-CAN copy of `0x100` held the extraction) and
   forced the search back into the MS path, which is where rules 12 and 13 were both found. Domain
   knowledge outranks a clean-looking scan.

---

## 2. Environment

```bash
cd <repo>/BCM/Research && . .venv/bin/activate     # pyghidra venv
# Ghidra 12.x at /opt/ghidra ; language PowerPC:BE:64:VLE-32addr
python3 work/gw_dec.py 0xADDR [0xADDR ...]          # decompile by entry address
python3 work/gw_mbfull.py                           # dump FlexCAN MB acceptance-filter ID lists
```
Merged flat image: `work/flash_merged.bin` (BE; app block at file/mem `0x10000`; SRAM `0x40000000`).
Build the merged image for a new OEM set with the `vbf_extract`/`build_image` pipeline (README §2).

### 2.1 pyghidra pitfalls — bake these into every script you write

Two environment traps that cost real time on this project. They apply to **any** pyghidra script in
this repo, not just the porting work.

**1. The GUI claims the project "has not been analyzed yet" even when it has.**
`AutoAnalysisManager.startAnalysis()` populates the database correctly but never writes the
`PROGRAM_INFO` option `"Analyzed"` — only `GhidraScript.analyzeAll()` and the GUI's own analyze
action do. Answering "No" to the resulting prompt makes the GUI persist `Analyzed=False` +
`Should Ask To Analyze=True`, so the nag becomes sticky. Call
`GhidraProgramUtilities.markProgramAnalyzed()` + `markProgramNotToAskToAnalyze()` before saving
(as `work/owner/01_analyze.py` does). To check or repair an existing project:

```bash
python3 work/owner/07_check_analyzed_flag.py         # report only
python3 work/owner/07_check_analyzed_flag.py --fix   # set the flags and save
```

It prints the real database contents first (instructions / functions / defined data / user symbols)
so you can confirm you are fixing a **stale flag** rather than masking genuinely missing analysis.

**2. The pyghidra JVM never exits.** Non-daemon threads keep the interpreter alive indefinitely — a
39-minute zombie was observed after a 19-second analysis had already saved. End every script with:

```python
sys.stdout.flush(); sys.stderr.flush(); os._exit(0)
```

The flush is **mandatory**: `os._exit()` bypasses buffer flushing, so with stdout redirected to a
file all output is silently discarded.

Also: only one process may hold a Ghidra project at a time; always `project.close()` in `finally`;
open read-only unless the script's whole purpose is annotation.

**3. Three write-path traps that all report success on stdout.** Each of these printed a confident,
wrong result while the database on disk was unchanged:

- **`os._exit(0)` kills the JVM mid-flush on a large save.** A sweep script printed
  `13,592 functions`; disk still held `2,402`. Small annotation saves had always completed in time,
  which is why this never surfaced earlier. **A large save must exit normally** — trap 2 above
  applies only to scripts that have finished writing.
- **`program.getDomainFile().save(monitor)` can never work under `GhidraProject`.** `openProgram()`
  leaves a transaction open for the program's lifetime, so the save raises
  `IOException: Unable to lock due to active transaction`. Corollary: `getCurrentTransactionInfo()`
  is **never** `None` — polling it for "transaction closed" is an infinite loop. Use
  **`project.save(program)`**, which handles it.
- **Aborting a nested transaction rolls back the enclosing one.** Rejecting one bad result with
  `endTransaction(tx, False)` discarded **all 646 good results** along with the 91 bad ones. Fix:
  **always commit**, and undo a bad unit of work explicitly (e.g. `listing.clearCodeUnits(...)`).

> **General rule: after any bulk Ghidra write, reopen the project read-only and re-read the counts.**
> Every one of the failures above reported success.

---

## 3. Port procedure (step by step)

### Step A — Rebuild the base image & Ghidra project for the target OEM
Extract the target's VBFs, verify CRCs, assemble `flash_merged.bin`, load in Ghidra with the VLE
context set on the code region, auto-analyze. (README §2–3. If reusing this repo's project, replace
the program or make a new project — don't mix versions.)

### Step B — Confirm the `0x030` TX path and the two packers
`0x030` is normally the **first HS-CAN (CAN0) TX** entry. Confirm with `work/gw_mbfull.py` (look for
id `0x030`, dir=TX on CAN_0 `0xFFFC0000`). Identify the **mailbox index** it uses and the **generic
TX packer** function(s). In `-AD` these are `FUN_000fc218` (single-frame) and `FUN_000fc2f6`
(periodic walker), reached from the TX dispatcher. Method to find them on any version:
- Find the FlexCAN transmit-arm store: the instruction that writes the MB **CS/CODE** word
  (`code=0xC` "data" with length) to arm transmit — an `e_sth`/`se_sth rX,0x0(rMB)` where `rMB`
  holds the mailbox **CS address**. Decompile candidate packers (`gw_dec.py`) and look for the
  loop that copies the frame image into `base+0x80+idx*0x10+0x8..` then stores the CS word.
- There may be **two** packers (single + walker). Hook **both**; either can emit `0x030`.

### Step C — Determine the MB-CS gate constant for `0x030`
The gate compares the packer's live MB-CS pointer against the absolute CS address of the `0x030`
mailbox: `CAN0_base + 0x80 + idx*0x10`. For CAN0 `0xFFFC0000`, MB0 → `0xFFFC0080`. **Recompute for
the target's actual `0x030` MB index.** Data bytes are at `CS+0x8` (d0) … so d1=`CS+0x9`,
d5=`CS+0xD`, d6=`CS+0xE`. (In the cave we load `CS+0x9` into a base reg and use d5=`0x4(base)`,
d6=`0x5(base)`.)

### Step D — Find the `0x0C0` status read address (paused discriminator)
The BCM **receives** `0x0C0` on HS-CAN. Find the **decoded RAM frame-image** byte for `0x0C0` d0 and
read that (safe plain RAM), NOT the raw mailbox.

> **⚡ Shortcut (owner full-flash project):** this whole lookup is now **precomputed for every RX
> frame** in `work/owner/rx_frame_map.json` — 279 frames, each with its mailbox, CAN ID, copymask and
> the absolute address of every present byte. Generate it for a new image with
> `python3 work/owner/80_rx_record_decode.py` then `83_annotate_l13_rxmap.py`. The record layout was
> read out of `VOL_rx_copy_to_image`'s own field accesses, and the result reproduces the two addresses
> this mod already depends on (`0x40000707`, `0x40000705`) — see `docs/owner_flash_layers.md` §17.
> Use the manual method below only to verify, or when the JSON is unavailable.

Method (see `docs/0c0_standby_read.md`):
1. In the CAN0 acceptance-filter list, find `0x0C0` (dir=RX) and its **filter-list position** =
   hardware MB index (verify via the bring-up loop that programs `MB[i].ID = list[i]`).
2. In the reception-descriptor table, find the 32-byte record whose MB-index field matches; its
   frame-image pointer (+0x18) + the per-byte copy mask (+0x1a covers d0) give the RAM address.
3. Confirm the RX copier (`FUN_000fc63e`-equiv) does a **verbatim** byte copy (no repack), so the
   RAM byte preserves the wire layout (bit3=StandBy, bits4-6=mode/status).
Cross-check the two routes (MB index vs reception descriptor) agree on which physical frame is
`0x0C0`. In `-AD`: MB30, RAM d0 `0x40000707`.

### Step E — Confirm the `0x030` bit map and the RES+ Resume-vs-Set+ condition on the target
Do NOT trust the `-AD` bit numbers blindly. Confirm the `0x030` button bits against the composition
handlers, `PCM/PCM_Research/SWM_CRUISE_BUTTONS.md`, and decoded HS-CAN bus captures.

For the RES+ gate, **capture on the car and correlate CAN values with what the car is actually
doing** — this took FOUR on-vehicle rounds because `0x0C0` d0 is treacherous:
- `0x0C0` d0 status codes on `-AD`: cruise `0x18` engaged-not-set / `0x10` active / `0x40` cancel;
  limiter `0x38` engaged-not-set / `0x30` active / `0x48` cancel.
- **The status byte DECAYS**: ~2 s after a cancel, cruise `0x40`→`0x18` and limiter `0x48`→`0x38`,
  i.e. cancelled becomes byte-identical to *engaged-but-no-speed-set-yet*. No single-byte test on d0
  can separate "cancelled (want Resume)" from "just engaged, no speed (want Set+)".
- **Resolve with a second frame:** `0x060` d6 = the stored **set-speed** (0 until a speed is set).
  Final rule = **`(d0 & 0x48) != 0` AND `(0x060 d6 != 0)`** → Resume, else Set+.
- Failed earlier gates (record these so nobody repeats them): bit3-alone (fires on limiter `0x38`
  no-speed standby); `(d0&0x28)==0x08` (from misreading cruise-started/active as paused); bit6-alone
  (broke after the status byte decayed). Captures: `candump-2026-09-09_175536.log`, `..._191816.log`.
- The exact status codes and which byte holds set-speed **may differ by MY** — re-derive both from
  a fresh capture covering every state *and* the ~2 s post-cancel decay.

### Step D2 — Find the set-speed read address (`0x060` d6) the same way as `0x0C0`
`0x060` is RX on CAN0. Repeat Step D: filter-list position = MB index (on `-AD`, MB22), then the
reception descriptor's frame-image base + copymask. ⚠ The RX copier **compacts** (dest pointer
advances only for set copymask bits), so a byte's image offset is the count of set mask bits *below*
it, NOT the CAN byte index. On `-AD`: base `0x40000700`, mask `0xFE` → d6 has 5 set bits {1..5}
below it → `0x40000700 + 5` = `0x40000705`. Verify the copymask covers your target byte and compute
its compacted offset from the copier loop (`docs/0c0_standby_read.md` shows the method).

### Step F — Pick two code caves in the app block's `0xFF` padding
Find contiguous `0xFF` padding **inside** the app block (so it's covered by `sum8`) large enough for
each cave (~280 bytes with the edge-latch). In `-AD`: `0x117100` and `0x117300`. Ensure they don't
overlap and that a 32-bit `e_b` reaches from hook site to cave (VLE `e_b` is ±16 MB — always fine
in-block).

### Step F2 — Edge-latch + a persistent scratch RAM byte (REQUIRED — buttons are held)
A physical press is **held for a few hundred ms** and `0x030` is retransmitted every ~10 ms while
held. Because Resume flips the PCM `paused→active` *during* the press, a stateless per-frame gate
emits Resume then Set+ (bumping the set-speed). You MUST **latch the Res/Plus decision at the rising
edge** and hold it until the button releases, using one persistent RAM byte `L` (0=idle,1=Res,2=Plus):
`if (held){ if(L==0) L=decide(); apply(L); } else L=0;`. Both caves share the same `L`.

Finding a safe `L` is delicate — it must be RAM **no firmware code ever touches**. Do NOT reuse
stock SWM button-state bytes: the LIN handlers rewrite them every frame and will fight the latch.
Method (see `docs/scratch_ram.md`): from the startup code (reset `0x10F4A0`) find (a) the ECC/zero-
init range (so the byte powers up 0), (b) the stack pointer init + growth direction, (c) the SDA
base (r13/r2) and its ±32 KiB reach, (d) `.data`/`.bss` extents. Pick an address that is inside the
zero-init range, above the stack top, outside SDA reach, and has **zero references** in a full flash
scan (both Ghidra-resolved refs and a raw 4-byte-aligned pointer scan). On `-AD`: `L = 0x40011000`
(inside ECC-init `[0x400039A0..0x40014000]`, above SP=`0x4000CAC8`, below SDA `0x40017920`, zero
refs; ~5 KB of clean run there). Note r0 cannot be a load/store base register in PPC — keep the
address in another reg (r4) and the value in r0.

### Step G — Write, assemble, and round-trip the trampolines
Use `work/acc-fix/build_caves.py` as the template. It builds each cave symbolically with labels,
does a two-pass size/branch resolution, assembles every line via Ghidra with `contextreg=0x20000000`,
writes the bytes into a scratch program, and **re-disassembles to prove** each instruction. Update:
- gate constant (Step C), MB base reg per packer, data-byte offsets,
- the `0x0C0` read address (Step D), the gate bit (Step E),
- hook sites and the **displaced original instruction(s)** to replay (must be replayed *after* the
  bit edits and *before* returning, because the displaced store is what arms the mailbox),
- return addresses (hook site + size of displaced bytes).
Watch instruction lengths: VLE mixes 16-bit (`se_*`) and 32-bit (`e_*`) forms. A 4-byte `e_b` hook
may need to displace **two** 16-bit instructions (as in the walker) — replay both.

### Step H — Patch the VBF and repair all three integrity layers
Use `work/acc-fix/build_vbf.py` as the template. It asserts the **expected original bytes** at each
edit site (guards against wrong offsets/version drift), applies the blobs, then repairs sum8 →
CRC-16 → CRC-32. Update the `EDITS` expected-byte guards and any changed addresses. Output only the
APP VBF unless your target needs an F10A edit too (this hook doesn't).

### Step I — Verify everything
Use `work/acc-fix/verify.py`: re-parse the VBF (all block CRC-16, file CRC-32), recompute sum8,
re-disassemble both caves **from the rebuilt image**, run the behavior simulation across all `0x0C0`
states, and diff vs OEM (expect only the small expected clusters: 2 hooks, 2 caves, file_checksum
text, sum8+CRC16 word). All must pass before flashing.

### Step J — Annotate the Ghidra project
Run `work/acc-fix/annotate_ghidra.py` (opens writable, labels caves/read-addr, plate+EOL comments,
`Note`/`ACC-FIX` bookmarks, saves). Adjust addresses for the target.

### Step K — Flash & confirm on the car
Flash the APP VBF. Confirm BCM boots (no safe mode) and candump `0x030` while pressing RES+ and LIM
in each cruise state. Success criteria in `docs/acc-fix.md` §8.

---

## 4. VLE assembly cheat-sheet (hard-won)

- Assembler: `ghidra.app.plugin.assembler.Assemblers.getAssembler(program.getLanguage())`.
- Context: `AssemblyPatternBlock.fromBytes(0, JByteArray([0x20,0,0,0]))` passed to `assembleLine`;
  the VLE context bit is `0x20000000`. Without it → "Incompatible context".
- When writing bytes then disassembling: set the context register on the range first
  (`programContext.setRegisterValue(start,end, RegisterValue(ctxBaseReg, 0x20000000, 0xFFFFFFFF))`)
  and `clearCodeUnits` before `DisassembleCommand`.
- Comment-constant types are on `ghidra.program.model.listing.CodeUnit` (`PLATE_COMMENT`,
  `EOL_COMMENT`), not on the listing object.
- To open a program writable via `GhidraProject`: `openProgram("/","<name>",False)` (3rd arg is
  `readOnly`), edit in a transaction, then `project.save(program)`.
- Useful mnemonics used here: `e_stwu/e_stw/e_lwz` (frame), `e_lis`+`e_or2i`/`e_add16i` (build const),
  `cmplw rX,rY` (32-bit unsigned compare — valid in VLE, cleaner than `se_cmp` which only takes
  low regs), `e_bne/e_beq cr0,target`, `e_lbz/e_stb` (byte load/store), `e_andi./e_and2i./e_or2i`,
  `e_b target`. `se_*` are the 2-byte forms.

---

## 5. Integrity repair (exact)

```
sum8   @0x13FFFE (low16, high half at 0x13FFFC stays 0xFFFF)
       = sum(bytes 0x10000 .. 0x13FFFE, exclusive) & 0xFFFF   # covers RCHW block + app, not the word itself
CRC16  per VBF block, CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflect), 2 bytes after [start][len][data]
CRC32  header 'file_checksum = 0x..;', zlib.crc32 over from first block's start-addr field to EOF
```
Order: data → sum8 → CRC16(all blocks) → CRC32. Confirm the target's internal-checksum location the
same way it was found originally: **diff two OEM versions of the same part** and find the `(algo,
range)` whose result equals the stored value in *both* (README §2.1). Don't assume `0x13FFFE` — a
different MY could move it (though it's stable across `-AB`/`-AD`).

---

## 6. File / script map (`work/acc-fix/`)

| File | Purpose |
|---|---|
| `build_caves.py` | assemble both caves + hook branches (Ghidra VLE, round-trip verified) → `patch_blobs.json` |
| `patch_blobs.json` | cave/hook byte blobs + cave addresses (produced by build_caves) |
| `build_vbf.py` | patch APP VBF (with expected-byte guards) + repair all 3 integrity layers |
| `verify.py` | re-parse CRCs + sum8 + re-disasm caves from rebuilt image + behavior sim + diff-vs-OEM |
| `annotate_ghidra.py` | apply labels / plate+EOL comments / bookmarks to the Ghidra DB and save |
| `JV6T-14C094-AD_acc-fix.VBF` | the built artifact (this OEM version) |

Supporting evidence docs: `docs/acc-fix.md`, `docs/0c0_standby_read.md`, `docs/030_composition_trace.md`.
Reusable RE helpers in `work/`: `gw_dec.py` (decompile), `gw_mbfull.py` (MB filter lists),
`gw_rxdesc.py` (reception descriptors), `find_algo.py`/`check_internal.py` (integrity hunt),
`vbf_crc_validate.py` (CRC check), `cmp_ab_ad.py` (OEM version diff).

---

## 7. If the target differs structurally

- **Different `0x030` bit assignments:** redo Step E; change only the masks/target bytes in the cave.
- **Only one TX packer:** hook just it; drop the second cave.
- **Displaced instruction is 16-bit and a 4-byte `e_b` clobbers the next one:** displace and replay
  **both** halves (as the walker does), returning past both.
- **`0x0C0` not received / different status frame:** find whichever frame the PCM uses to advertise
  cruise/limiter cancel state; repeat Step D/E for it. If no such frame exists, the RES+ gate can't
  be data-driven — fall back to **unconditional Set+** (drop the latch's decide branch and always
  set d5 bit7).
- **No in-block `0xFF` padding big enough:** find a smaller pair of caves, or split the logic; never
  place a cave outside the `sum8`-covered region (it wouldn't be checksummed and, worse, may not be
  flashed as part of the app block).

---

## 8. Definition of done

- [ ] All block CRC-16 OK, file CRC-32 OK, internal sum8 OK (verify.py).
- [ ] Both caves re-disassemble from the rebuilt image exactly as intended; both hooks branch to caves.
- [ ] Diff vs OEM shows only the expected clusters (2 hooks + 2 caves + checksum bytes).
- [ ] Behavior sim correct across all `0x0C0` states.
- [ ] Ghidra project annotated (labels/comments/bookmarks) and saved.
- [ ] BCM boots on the car (no safe mode) and candump confirms the remap in every state.
- [ ] README §5.4 / `docs/acc-fix.md` updated with the target version's addresses + artifact hash.
