# Adjudication: 311 vs 313 on 0x4000965C (state enum, base+0x70)

Subagent scan adjudication. Read-only against `ghidra_proj_fullflash` /
`BCM_OwnerFlash` / `cflash.bin`.

Scripts written for this adjudication:
- `work/rs-trigger/314_adjudicate.py` — site context + method C (p-code) + method D (whole-listing linear sweep)
- `work/rs-trigger/315_indirect_bound.py` — residual-risk bound: struct pointer live in an arg register at a call
- `work/rs-trigger/316_bulk_writers.py` — memset-class bulk writers whose `[dst,dst+len)` covers the cell

Logs: `work/rs-trigger/logs/adj_311.log`, `adj_314.log`, `adj_315.log`,
`adj_316.log`, `adj_helpers.log`.

---

## 0. Headline

Both scripts are blind, in different ways, and **both undercount**.

| instrument | count |
|---|---|
| 311 method A — Ghidra reference manager | 6 |
| 311 method B — per-function base+disp sweep | **3** |
| 311 reported (union of A and B) | 6 |
| 313 — per-function base+disp sweep only | **3** |
| C — decompiler p-code, CALLOTHER `0x10000002` | 6 |
| D — whole-listing linear sweep (this report) | 6 |
| **true total including bulk writer** | **7** |

The 3-vs-6 disagreement is **not** 313 being a different instrument that
disagrees with 311. It is the *same* instrument, run alone. 311's "6" was the
**union of two instruments**; its own sweep found the same 3 that 313 found.
313 dropped method A and reported the survivor's number as the answer.

And 6 is itself a lower bound: the real count is **7**.

---

## 1. Mechanism by which 313 misses the three sites

### 1.1 Root cause A — 313 deleted the instrument that was doing the work

311 runs two instruments and unions them (311 lines 86–158, results merged into
one `hits` dict at lines 167–171). Re-running 311 verbatim
(`logs/adj_311.log`):

```
A. REFERENCE MANAGER
   0x4000965C STATE ENUM base+0x70    6 store ref(s)
B. BASE+DISP SWEEP (per function)
   0x4000965C STATE ENUM base+0x70    3 store(s)
```

313 (lines 79–125) implements **only** 311's method B. It has no reference
manager pass at all. Its 3 is therefore exactly 311's B-arm result — the two
scripts agree perfectly on the instrument they share. 311's docstring claims
"three instruments"; it implements two, and its own comment at 313 line 16
("reference manager + per-function base+disp sweep, the pair that agreed in
311") is factually wrong — the pair did *not* agree in 311; A found 6, B found
3, and the union hid the disagreement.

**The union operator is what made the control useless.** 311's control check
(lines 180–190) asks only `any(A[a] or B[a] for a in CONTROLS)` — an *or* across
instruments. A passing control on the union cannot detect that one arm
contributes nothing. Re-reading `adj_311.log`, B found **1** store for each
control cell where A found **5**: B was failing at 80% on the controls too, and
the control still printed PASS. 313 inherited the control design (line 140,
`any(stores[a] or loads[a] for a in CONTROLS)`) but not the second instrument, so
its control now passes on a single hit produced by the very arm that is blind.

This is exactly AGENTS.md rule 8/12 territory: the control was structurally
incapable of failing. A control that ORs over instruments, or that passes on
"≥1 hit" when the truth is 5, measures nothing.

### 1.2 Root cause B — per-site, why the shared sweep is blind

The per-function sweep resets `regs = {}` at every function entry (313 line 81,
311 line 117) — correct per rule 17, since leaking register state across
function boundaries fabricates addresses. But it then only ever walks bodies
returned by `FunctionManager.getFunctions(True)` and starts at
`body.getMinAddress()`. Site-by-site (from `adj_314.log` Phase 1):

**0x0AEB88 — `se_stw r7,0x2c(r6)`** — `getFunctionContaining()` returns `None`.
The instruction lies in an **unswept block**. `fm.getFunctions(True)` never
yields it, so the `while` loop at 313 line 85 never visits this address at all.
No amount of register tracking helps; the instruction is outside the iteration
domain. 313 lines 79–85 are responsible.

**0x0AD738 — `e_stw r0,0x70(r31)`** — containing function is `FUN_000ad72e`,
whose body is `000ad72e..000ad73d`: **sixteen bytes**. The defining instruction
for the base register is `e_add16i r31,r31,-0x6a14` at **0x0AD6E0**, thirty
instructions earlier and *outside* that body. Ghidra has carved a branch target
out of the middle of a larger routine and called it a function. When the sweep
enters `FUN_000ad72e` it wipes `regs`, so `r31` is unknown for the entire
16-byte body and the store's effective address is unresolvable. The reset at
313 line 81 — correct in the general case — is fatal here because the function
partition is wrong.

**0x0AEBE0 — `se_stw r0,0x2c(r6)`** — containing function is `FUN_000aebcc`
(`000aebcc..000aecbb`). The base is defined by `e_addi r6,r30,0x44` at
**0x0AEB84**, which is *before* the function's own start address — and sits in
the same unswept block as 0x0AEB88. Same failure as 0x0AD738: the definition is
outside the reset scope.

So all three misses share one mechanism: **the sweep's unit of register scope is
Ghidra's function partition, and in this region that partition is wrong** — one
region is unswept entirely, and two stores have their base-register definition
on the far side of a spurious function boundary. The reference manager escapes
this because Ghidra's own constant propagation ran during analysis, before and
independently of the function carve-up, and recorded the resolved references on
the instructions themselves.

### 1.3 A second, latent defect in 313 (does not cause this miss, but will bite)

313 line 47–48 puts `"e_b"` in `NON_DEFINING`, and line 123 tests
`mn.startswith(NON_DEFINING)`. `"e_bl".startswith("e_b")` is **True**, so a
**call never invalidates any tracked register**. Volatile registers r3–r12 are
caller-clobbered on this ABI; a base held in r3 across an `e_bl` will be
believed afterwards and can fabricate an effective address. 311 has the mirror
version of the same gap (line 153 kills only on non-cmp, and never models
call-clobber). Neither produced a false positive here, but this is a
false-*positive* generator, the opposite failure mode to the one under
investigation, and it should be fixed before either script is trusted on a cell
with more writers.

---

## 2. Is 6 a lower bound? Yes — the true count is 7

### 2.1 Third method (C): decompiler p-code — **6**

`314_adjudicate.py` Phase 2. Decompiled all 1143 functions in
`0x0A0000–0x0B4000` (1143/1143 succeeded), walked `HighFunction.getPcodeOps()`,
and matched `CALLOTHER` with input0 == `0x10000002` (store userop, per rule 14 —
a `PcodeOp.STORE` walk finds nothing in this image). Result: **6 sites, exactly
311's set.**

### 2.2 Fourth method (D): whole-listing linear sweep — **6**

Phase 3. Same base+disp resolution, but iterating
`listing.getInstructions(True)` over the entire program (352,906 instructions)
instead of `fm.getFunctions()`, with `regs` reset on **address discontinuity**
rather than function boundary. This is the corrected version of the instrument
313 uses, and it recovers all three missing sites including 0x0AEB88 in the
unswept block. **6 sites, identical set.** Three independent methods converge.

### 2.3 …and then a seventh, invisible to all of them

Instruction-level store scanners share one blind spot: a write executed *inside
a helper*, at an address unrelated to the struct. `315_indirect_bound.py` tested
for this by finding every call site with a pointer into
`[0x400095EC, 0x400096EC)` live in an argument register. 28 such sites; one
passes the **struct base itself** in r3 to `FUN_0010dab8`. Decompiling that
(`logs/adj_helpers.log`) identifies it as **`APP_memset`**, and its caller:

```c
void FUN_000aefbc(void) {
  ...
  APP_memset(&DAT_400095dc, 0, 0x10);
  APP_memset(&DAT_400095ec, 0, 0xa4);   // <-- 0x4000965C is base+0x70 < 0xA4
  ...
  FUN_000ae820();
}
```

`316_bulk_writers.py` resolved dst/val/len at all **158** `APP_memset` call
sites (154 fully resolved) and intersected each `[dst, dst+len)` with the
target. Exactly one covers it:

```
0x0AEFEC  APP_memset(0x400095EC, 0x0, 0xA4)  in FUN_000aefbc  -> covers +0x70
```

**Site 0x0AEFEC is a real writer of 0x4000965C** (the module-init block zero),
and it is invisible to the reference manager, to both base+disp sweeps, and to
the p-code CALLOTHER walk — none of them is wrong, all of them are answering a
narrower question than "what writes this cell". This is the same family as
AGENTS.md rule 12: correct measurement, wrong inference from it.

**So: 6 is a lower bound. The count is 7 — six inline stores plus one bulk
initialiser.** Practically, 0x0AEFEC only ever writes 0, on the init path, so it
does not change the *semantic* conclusion that no writer stores a literal 0x0A
(the 0x0A is computed) — but a trigger design that assumes "six writers, all
accounted for" is assuming something false.

### 2.4 What bounds the answer at 7

- No pointer to `0x400095EC` or `0x4000965C` exists as a literal anywhere in
  `cflash.bin` (byte-scan of both backup copies: 0 hits each). So there is no
  pointer-table / dispatch-through-RAM writer.
- The only bulk helper receiving the struct base is `APP_memset`, and only once.
- `VOL_test_and_clear_dirty` (0x31360) and `FUN_0010df50` receive pointers to
  *other* offsets in the struct (+0x74, +0x7C, +0x44), not +0x70.
- Residual, unexcluded: a write through a base register whose value arrives as a
  **function parameter** rather than being materialised locally. None of the
  instruments here model interprocedural argument propagation. That is the one
  remaining hole in the 7.

---

## 3. Recommended corrected scanning approach

Replace both scripts' single-instrument-with-a-weak-control pattern with a
four-arm scan and an **agreement-based, not union-based**, control.

1. **Arm 1 — reference manager.** `refmgr.getReferencesTo(addr)`, filter to
   store mnemonics. Cheap, and it is the arm that saw all 6; keep it.
2. **Arm 2 — whole-listing linear sweep, NOT per-function.** Iterate
   `listing.getInstructions(True)`; reset register state on **address
   discontinuity** (`addr != prev_addr + prev_len`), not on function entry. This
   preserves rule 17's no-leak guarantee (a gap always resets) while removing the
   dependency on Ghidra's function partition, which is wrong in this region. Also
   invalidate volatile r0/r3–r12 at every `e_bl`/`se_bl`/`*bctrl` — and fix the
   `startswith("e_b")` bug that currently makes calls transparent.
3. **Arm 3 — decompiler p-code.** `CALLOTHER` with input0 `0x10000002` (store) /
   `0x10000001` (load). Never `PcodeOp.STORE` in this image.
4. **Arm 4 — bulk/indirect writers.** Resolve `(r3,r4,r5)` at every call to
   `APP_memset` (0x10DAB8) and any memcpy-class helper, and report every call
   whose `[dst, dst+len)` interval covers the cell. **No store-instruction scan
   of any kind can find these.** Also byte-scan raw flash for the cell address
   and the containing struct base as literals, to exclude pointer tables.

5. **Report the UNION as the answer, and the PER-ARM DISAGREEMENT as a
   first-class result.** Print an arm × site matrix (as `314_adjudicate.py`
   does). Any site not found by all arms is a documented blind spot in the arms
   that missed it, and must be explained before the scan is trusted — per the
   repo rule that a method finding what another cannot must explain the other's
   blindness. 311's bug was not its arms; it was collapsing a 6-vs-3
   disagreement into a single number, which let 313 later inherit the broken arm
   with no warning attached.

6. **Fix the control.** A control must be evaluated **per arm**, not on the
   union, and must assert an **expected count**, not `>0`. Under 311's current
   control, the sweep arm found 1 of 5 control stores and still printed PASS.
   Concretely: pin the controls' known store counts and fail the arm if it
   returns fewer. Additionally require at least one control site to live in an
   unswept block, otherwise the control cannot detect the exact failure that
   actually occurred here.

---

## 4. Verdict

- **313 is not a competing measurement that disagrees with 311.** It is 311's
  weaker arm, run alone, with the stronger arm removed and the union — which was
  the only thing making 311 correct — silently discarded.
- **The blindness of the sweep arm** (shared by both scripts) is that its
  register scope is Ghidra's function partition: one site is in an unswept block
  outside the iteration domain entirely, and two have their base-register
  definition on the wrong side of a mis-drawn function boundary.
- **The blindness of the reference manager and p-code arms** is that they only
  see writes whose store instruction names the address; the `APP_memset` at
  0x0AEFEC writes the cell without any such instruction existing.
- **The count is 7, not 6 and not 3.**
