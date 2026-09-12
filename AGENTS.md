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

23. **A REACHABILITY result means nothing until you measure the reachability of UNRELATED code.**
   Before reporting "site X flows to target Y", run the *identical* walker from a handful of sites
   with no relationship to the question, and compare **which targets** they reach. Layer 36 produced
   a beautiful candidate — a tight, complete, 7-instruction path from `0x8B3D6` into
   `APP_lock_command = 3` — and then found that `FUN_00087486` and `FUN_0008B382`, neither of which
   has anything to do with RKE, reach **the same write site**. Reaching it was a generic property of
   the code region, not evidence. Two corollaries, both of which nearly slipped through:
   - **Compare target SETS, not counts.** The hit's score (1) *tied* the worst unrelated control (1),
     and the first verdict logic printed "SIGNAL" on that tie. A target also reachable from unrelated
     code has **zero** discriminating power regardless of how the counts land.
   - **A walk that hits its bound is not a result.** The sibling hit reached 10 of 32 targets after
     exploring 1201 blocks — the shape of an unbounded sweep of the layer, not of a path. Print the
     bound and mark such walks PARTIAL; a PARTIAL null is a lower bound, and a PARTIAL hit is noise.
   Same family as rules 8 and 9: the instrument worked, the inference didn't.
   (`docs/rke_lock_join.md` §5, `docs/owner_flash_layers.md` §46.3.)

24. **Decode a bitfield with the ROTATE, the WRAP, and the PRIMITIVE'S SHAPE — all three.**
   Rule 21 covered the rotate. Layer 36 found two more failure modes in the same decoder, each of
   which independently corrupts the output: (a) PowerPC allows **`mb > me`**, so the mask *wraps* —
   with `sh=0` the idiom `e_rlwinm r0,r0,0x0,0x12,0xe` is a masked **clear** (a WRITE), not a read of
   an impossible field "bits 17..13"; (b) `e_lwz`/`e_rlwimi`/`e_stw` is **one logical access across
   three reference sites**, and `rlwimi`'s operand[1] is the *source*, not the loaded register, so
   keying events by reference site both double-counts and loses the load. Also: never credit a bulk
   reset (`x &= ~big_mask`) to the write-set — claiming ~28 bits makes the set uninformative and will
   trip your own non-degeneracy control. Acceptance test: a complementary insert/extract pair on one
   field (`sh` and `32-sh`) must land in the **same bucket**.

25. **`project.close()` already releases the program, and `setBookmark` overwrites.** Two
   annotation-path quirks that each look like a failure but are not: calling `program.release(project)`
   *and then* `project.close()` raises `IllegalArgumentException: unknown consumer` **after** a
   successful save; and `setBookmark(addr, type, category)` replaces any existing bookmark at the same
   address+category, so an address given both a label bookmark and a plate bookmark yields **one**.
   Verify annotations by asserting the bookmark **address set**, never a count.

26. **A constant offset between two signals locked to the same stimulus cadence is NOT a lag —
   vary the stimulus timing before calling it causal.** Two press-locked square waves sharing a
   period show a *constant* offset at any arbitrary phase, so "+1040 ms, twice" looks exactly like a
   pipeline delay and means nothing. Re-running at a different inter-press gap is the falsifier: a
   real lag survives, a phase coincidence moves. Worse, the same trace exposed a second, independent
   error — **pairing each event with the next RISING transition instead of its NEAREST neighbour**.
   `lock_command 01`'s partner is `body_cmd_bus 0A`, not the following `0C`; corrected, the two cells
   are simultaneous to **±10 ms** (the round-robin poll interval) at all six transitions, i.e. one
   event, not two stages. Both the "ordering resolved" claim and its 1-second pipeline were wrong.
   Corollary: **state your pairing rule explicitly and test it against the alternative**, and treat
   a suspiciously round, repeated delta as a signature of shared cadence until proven otherwise.
   (`docs/bench_session_2.md` §6.1–6.2.)

27. **An empty instrument reading is INCONCLUSIVE, never a negative verdict about the subject.**
   The probe-bank acceptance test printed `✗ CONTROL FAILS` when the probe side was perfect and the
   *bus observer* had captured nothing: `candump -L` emits `03A#A040...` but `candump -ta` emits
   spaced columns `can1  03A   [8]  A0 40 ...`, so a `03A#` regex matched zero frames and
   `probe ∩ bus = ∅` was rendered as disagreement. A verified-good 1.2 MiB flash was one careless
   reading from being condemned. Any comparison against a reference channel must **assert the
   reference is alive first** and report INCONCLUSIVE when it is not. Same family as rule 8.

28. **Gate a flash on the DID that actually carries the software part number.** `F111` is the ECU
   hardware/assembly part (`DV6T-14C245-FF`) and never equals an EXE VBF's `sw_part_number`; the
   application part is **`F188`**, the calibration is **`F124`**. A safety check keyed on `F111`
   refuses every legitimate application flash — and a check that only ever false-positives is worse
   than none, because the habit it teaches is `--force`. Derive erase regions and block addresses
   from the **VBF header**, never from a capture: the reference log
   (`hscan_bcm_flash.log`) is a `JV6T-14C095-AB` **DATA/calibration** flash — 1 erase region of
   16 KiB at `0xC000` — while the application needs **11** regions spanning `0x10000..0x140000` and
   1.2 MiB. Also: the erase routine answers `7F 31 78` (responsePending) *first* and only then
   `71 01 FF 00`, so a tool that aborts on the first negative stops **after erase, before write**.
   (`docs/bcmflash_tool.md`.)

29. **A repeated-trial sweep must reset state between conditions, and must verify its edges are
   STIMULUS-LOCKED before any verdict.** A hypothesis sweep over `req_word_74` b2 printed a clean
   "consistent with H3 (needs ≥3 presses)" that its own raw data refutes, via three independent
   defects: (a) trials ran back-to-back and the change-trace records the **first sample as a change**
   (no previous value exists), so a cell still holding the target value from the *previous* condition
   was counted as a fresh firing at t≈0.006 — inflating every count; (b) the edge times were **not
   stimulus-locked** and nobody checked — `3.510` appeared at `gap=0.6` *and* `gap=2.5`, while press
   times move as `settle + k·(hold+gap)`; (c) the free-running control was **blind by construction**
   — 10 s, run *first*, before any press, so a press-armed-then-free-running mechanism could not
   appear in it. Fixes: record the initial value **separately** from edges; assert that edge times
   **move when the stimulus timing moves**; and run the null control **both before and after** a
   confirmed stimulus, for a duration comparable to the real trials.
   (`docs/bench_session_2.md` §8.1–8.3.)

30. **If every access to a "global" has the form `disp(rX)`, it is a STRUCT FIELD — and treating it
   as a global is what manufactures saturation.** All 33 reads covering `0x40008E76` are
   `e_lwz rX,0x8c(r4/r5/r6/r7/r31)`, never an absolute load, and four sampled sites in different
   functions all build the base identically (`e_lis rX,0x4001` + `e_add16i rX,rX,-0x7218` =
   `0x40008DE8`). So `APP_req_word_74` is **field +0x8C of one global body-control struct**, and the
   project's other named cells are its neighbours: `APP_body_cmd_bus` = base+0x70,
   `APP_req_word_70` = base+0x88, `APP_lock_request_input` = base−0xBC. That last offset is the very
   `-0xBC` recorded in rule 16 — **the same struct was implicated long before it was recognised.**
   `APP_body_cmd_bus`'s notorious **226 references** are therefore not 226 uses of one variable but
   accesses to a struct the whole subsystem shares; every reference-based join on it looked
   saturated for a structural reason. Before declaring a cell "a shared bus with too many refs to
   discriminate", **check whether its accesses are field offsets off a common base, and enumerate
   the struct instead.** Corollary: a constant base at every site means ONE instance — do not assume
   multiple instances without checking, and do not treat field reads as ambiguous when they are not.
   (`docs/bench_session_2.md` §9.2–9.4.)

31. **A DEBUG TOOL IS AN INSTRUMENT — validate it against known-truth bytes before believing one
   word of its output, and never attach an unvalidated one to a live ECU.** The calandoa `xpc56`
   OpenOCD fork connected, matched the IDCODE, printed `=== DBG ENTER ===`, tracked OnCE OSR across
   debug entry/exit (`0x221` ↔ `0x201`), and then returned `0x00000000` from `mdw` at **every**
   address — including `0x000DE278`, where the VBF we had just flashed guarantees
   `70e8e000 30e719c4`. `reg` showed PC, MSR and all 32 GPRs as zero marked `(dirty)`: the cache was
   never populated. It would have been easy to write that up as "flash reads as erased" or "debug is
   censored"; both would have been fiction. Three things this cost, each generalisable:
   - **Ground truth must be external and independent.** The acceptance test is `mdw 0x000DE278` ==
     `70e8e000 …`, taken from the image we flashed — not "the value looks plausible".
   - **Bisect the stack with a check the silicon defines, and change ONE variable at a time.**
     Reading IDCODE at 32…256-bit scan lengths has a ground truth no reasoning can distort: it
     passed 10/10, proving the transport healthy. ⚠ An earlier bisect using a BYPASS shift blamed the
     fork's CMSIS-DAP driver — **wrong**, because it swapped host driver *and* probe firmware at
     once; holding firmware fixed showed stock OpenOCD failing identically. See rule 34.
   - **Working subsystems do not vouch for the broken one.** TAP addressing, OnCE status reads and
     scan integrity were all genuinely fine; the core still never entered debug mode.
   ☠ **Operational corollary, learned repeatedly on hardware:** `xpc56_examine()` calls
   `debug_enter()` during `init`, so *merely connecting halts the CPU*; its broken state tracking
   then makes `resume` a silent no-op (`Already running`) and `exit` leaves the core stopped. The BCM
   goes silent on CAN, and `-c 'init; resume; exit'` cannot help because `init` re-halts first. A
   **50 ms nRESET pulse recovers a shallow halt** (one caused by a bare `init`), but **not** a deep
   one — after any CPUSCR/GPR-sweep session, 250 ms / 1 s / 3 s pulses all failed and a **physical
   power cycle was required**. Before attaching any debugger to a live module: **prove you can get
   out before you go in, and keep power access available regardless.**
   (`docs/jtag_bringup.md` §5, §7.)

32. **Two devices of the same model are not the same device — read the identity, do not infer it.**
   Bench #2 was assumed to be the probe-bank unit because it answered on the same bus. `bcmflash.py
   ident` showed a completely different module: `GV6T-14C094-AJ` / PBL V014 / serial `007670223726`,
   every identifier differing from bench #1's `JV6T-14C094-AD`. Had the assumption stood, Ghidra
   addresses from one image would have been applied to different firmware. **Rule 5's "never mix
   projects" applies to hardware too.** Corollary: after reflashing one block, the unit is a
   *hybrid* — bench #2 now runs the JV6T application over a GV6T calibration and GV6T hardware, so
   **code addresses are valid while behaviour is not comparable**. State which layer a claim rests
   on. And record physical condition with the identity: this unit has **no relays fitted**, so an
   absent actuation there is not evidence of anything.

33. **A "no effect" result from a GPIO/pin operation is meaningless until you prove the pin MOVED —
   and a pin driven high to "release" is reading your own output.** Five nRESET pulse experiments
   (100 ms → 5 s, plus stock OpenOCD `jtag_reset 1 1`) all reported failure, and that was written up
   as "nRESET cannot clear OnCE debug state; only a power cycle recovers". **Every one was a no-op**,
   for four stacked reasons, each of which independently nullified the test:
   - **The command never reached the pin.** `DAP_SWJ_Pins` in the probe firmware indexed `select`/
     `value` by **RP2350 GPIO number** (14–21) instead of the CMSIS-DAP **protocol bit** (0–7); the
     fields are single bytes, so `select & (1U<<16)` never matches and `PIN_nRESET_OUT` was
     **unreachable dead code**. Caught by a diagnostic worth reusing: patching the function produced
     a **byte-identical binary even after `make clean`** — only dead code does that.
   - **The same bug inverted the readback**, making all six pins read `0x00`, which nearly became the
     conclusion "nRESET is not wired".
   - **"High-Z" was not high-Z.** RP2350 pads reset with `PDE=1` (pull-down **on**) and `gpio_init()`
     never touches pulls, so the probe kept pulling the line down against the target's *weak*
     pull-up — potentially holding the ECU in reset for the whole session.
   - **The test's own release selected nothing** (`pins(0, 0)` ⇒ `select=0`), so the pad stayed
     driven low from the previous assert.
   The earlier "wired and controllable ✓" was equally worthless: it drove the pin **actively high**
   and read it back — the probe measuring its own output, a textbook rule-9 self-confirming control.
   The valid test is to **stop driving** and ask the *board* to hold the line, and the decisive one
   is **functional**: after the fixes a **50 ms** pulse took the BCM from 0 → 14/14 UDS responses.
   ⇒ For any pin-level claim: prove the pin changes state with the drive removed, state the pull
   configuration explicitly, and prefer a functional outcome over a readback. Corollary: on an
   open-drain/bidirectional reset (MPC560x `RESET` is **bidirectional**, so the MCU drives it low
   itself) **never drive high** — assert low, release to high-Z.
   (`docs/jtag_bringup.md` §3–§4.)

34. **Verify a bit index against the reference manual BEFORE building a mechanism on it — and check
   a register's CONSTANT bits to prove you are decoding the right register at all.** The JTAG
   investigation produced **four** confidently-reasoned, fully-written-up, wrong mechanisms, every
   one rooted in an unchecked bit position or arithmetic prediction:
   - `DAP_SWJ_Pins` indexed by GPIO number (14–21) instead of CMSIS-DAP protocol bit (0–7), making
     `PIN_nRESET_OUT` unreachable **dead code** — so five "nRESET does nothing" experiments were all
     no-ops. *(Tell: patching the function produced a byte-identical binary even after `make clean`.
     Only dead code does that.)*
   - Polling OSR `BIT(5)` and calling it DEBUG; `BIT(5)` is **STOP**, DEBUG is `BIT(6)`. The
     "core enters debug then falls out after one scan" story was the core stopping and un-stopping.
   - Decoding `0x001D` as an OnCE status register. The RM fixes OSR `b8=0, b9=1`; `0x001D` has
     **b9=0**, so it cannot be an OSR — a **one-line constant-bit check** that invalidates the whole
     decode, available the moment the RM was in hand.
   - Retracting a **correct** BYPASS prediction (`out == in << 1`) as "invented arithmetic" because
     the *inference* drawn from it was wrong. Withdrawing a true result to protect a false conclusion
     is its own failure mode — separate the measurement from the interpretation.
   ⇒ Practice: get the actual RM before decoding (`docs/refs/e200z0.pdf` was downloaded far too
   late); **print every field BY NAME** in instrumentation rather than a single derived verdict, so
   the raw evidence is visible; and where a register has documented constant bits, assert them first
   — it is the cheapest possible proof that you are even talking to the right register.
   Corollary: **change ONE variable at a time.** "The fork's driver corrupts scans" came from
   swapping host driver *and* probe firmware together; holding firmware fixed showed stock OpenOCD
   failing byte-for-byte identically. (`docs/jtag_bringup.md` §8.)

35. **Falsify a WIRE FORMAT against the stock target before you build anything for it.** The peek
   service's original envelope — `22 <DID> <addr32>`, "the handler ignores trailing bytes" — was
   assumed from a decompile and looked obviously fine. Two minutes of `0x22` requests on **stock**
   firmware refuted it **5/5**, and the *NRC identified the mechanism*: `0x31 requestOutOfRange`, not
   `0x13 incorrectMessageLength`, because the handler **loops** over DID pairs, so trailing bytes are
   parsed as bogus DIDs. The replacement (address carried **as two synthetic DIDs**) was then
   confirmed the same way — `22 0631 401B 4099` → `total=10`. Building first would have cost a full
   assemble → integrity-repair → 1.2 MiB flash cycle to learn the same fact. ⇒ Any protocol
   assumption that can be tested on the unmodified target **must** be, before a line of VLE is
   written. Corollary: **read the NRC, don't just note the failure** — it tells you *why*, and here
   it pointed straight at the correct carrier.

36. **A constant reading proves nothing about liveness — find a SELF-REFERENTIAL control.** After the
   peek service passed two known-truth checks, four SRAM cells sampled 12× over 3 s returned **one
   distinct value each**. "The cells are idle" is the tempting write-up and is indistinguishable from
   a frozen snapshot, a cached read, or a decode that ignores its address argument (rule 8 again).
   The decisive control needs no stimulus at all: **peek the UDS request buffer**, whose contents are
   *the very request performing the peek*. `peek 0x4000A9E5 → 4000A9E5` — the returned value **is**
   the address asked for, and the window slides byte-for-byte at ±1. No snapshot can manufacture
   that. ⇒ When you need to prove an instrument reads *current* state and the subject won't move,
   look for a cell whose content is **a function of the measurement itself**.

37. **Assembler rejections are free evidence — mine them instead of guessing.** Three encoding facts
   were settled by the assembler and the OEM's own bytes rather than by reasoning: `e_cmpli` takes a
   **scaled IMM8** and cannot encode `0xDEAD`; Ghidra spells the arbitrary 16-bit compare
   **`e_cmpl16i.` with the trailing dot**; and the correct spelling was proven by **reproducing an
   OEM instruction byte-for-byte** (`e_cmpl16i. r26,0xf3ff` == `73DAABFF` at `0x10B7CC`) before being
   used. Guessing a third spelling would have been another full build cycle. ⇒ When an assembler
   refuses a line, find an instruction of that form **already in the image** and make the assembler
   reproduce it; that is a ground truth no reasoning can distort. Same discipline as rule 3, applied
   to mnemonics rather than to whole caves.

38. **Before clobbering a register in a cave, COUNT its references in the enclosing function.** The
   peek cave needed a scratch register across several `e_bl` calls. Rather than assume the PPC EABI
   volatiles were free, a scan of all 391 instructions of the host function showed `r9`/`r10`/`r11`/
   `r12` with **zero references** and `r8` with two. `r9` was chosen on measurement, not convention.
   Cheap, and the failure mode it avoids (silent corruption of a live value) is one of the hardest
   classes of bug to diagnose over CAN.

39. **A verifier's own string matching is part of the instrument — a formatting mismatch reads as a
   missing feature.** The peek verifier reported two FAILs, "calls the request-byte accessor" and
   "calls the response-append accessor", while the listing it was searching plainly contained
   `e_bl 0x001098de`. Cause: Ghidra prints addresses **zero-padded to 8 digits**, and the needle was
   `0x1098de`. The right fix was to match the real format *and make the check stricter* (assert the
   exact **call counts** the design implies: 4 request reads, 10 response appends), not to loosen it
   until it passed. ⇒ When a verification step fails, establish whether the **artifact** or the
   **checker** is wrong before changing either — and prefer fixing a checker *upward* in strictness.

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
