# Subagent report — every writer of `DAT_40002F3C` (0x40002F3C), and is 3 reachable?

Scripts: `work/rs-trigger/320..329_*.py` · Logs: `work/rs-trigger/logs/32*.out`
Project: `ghidra_proj_fullflash` / `BCM_OwnerFlash` / `cflash.bin` (opened read-only throughout).

---

## 0. Verdict (short)

**3 IS reachable.** The "2 writers, literals 4 and 5" result is a *lower bound produced by a
blind spot shared by every address-resolving instrument*. The value 3 is written by a **third
writer that stores through a pointer parameter**, and it is a **computed** value —
`src_byte & 3` — where the source byte demonstrably takes literal values `0x8F`, `0x93` and
`0x57`, all three of which have `&3 == 3`.

Consequently **`FUN_000AD6C6`'s gate `if (DAT_40002F3C == 3)` is LIVE**, not dead code.
Indeed `3` is the *nominal/normal* value for this cell — `4` and `5` are the exceptional
(fault / shutdown) states.

---

## 1. What the cell actually is

`r30 = 0x40002D20` (`e_lis r30,0x4000` + `e_add16i r30,r30,0x2d20` at `0x0AD6CC`/`0x0AD6D0`),
so `+0x21C = 0x40002F3C`. A second alias `r31 = r30 + 0x210 = 0x40002F30` is set at `0x1136CC`,
making the *same byte* reachable as `+0xC(r31)`.

It is one of a **three-channel group** (CAN channel state bytes):

| cell | struct offsets | channel index |
|---|---|---|
| `0x40002F32` | `+0x212(r30)` / `+0x2(r31)` | 0 |
| **`0x40002F3C`** | **`+0x21C(r30)` / `+0xC(r31)`** | **1  ← target** |
| `0x40002F37` | `+0x217(r30)` / `+0x7(r31)` | 2 |

All three are written by the identical code shape, which makes 0x40002F32 / 0x40002F37 ideal
same-region, same-addressing-form positive controls (AGENTS.md rule 45).

Reference census (script `325`): the target has **25 references — 22 reads, 2 absolute-resolvable
writes, and 1 ADDRESS-TAKEN site**. That single address-taken reference is the whole story.

---

## 2. Methods used, and their counts

Five instruments. **The first four are NOT independent** in the way that matters: they all
resolve a *target address*, so none of them can see a store performed through a pointer
parameter.

| # | method | script | writers found on target | control result |
|---|---|---|---|---|
| A | Ghidra reference manager, absolute refs | 321 | **2** | ✔ found 2/2 on both same-struct controls; 6/6 on 0x4000965C |
| B | base+disp sweep over *every instruction in the image* (not just functions) | 321 | **2** | ✔ 2/2 controls; 3/6 on 0x4000965C (misses unswept blocks) |
| C | decompiler p-code `CALLOTHER 0x10000002` | 321 | **2** | ✔ 2/2 controls; 6/6 on 0x4000965C incl. the UNSWEPT `0x0AEB88` |
| D | raw-binary VLE decoder, **no Ghidra at all** | 322 | **2** | ✔ 2/2 controls, decoder round-trip 10/10 |
| **E** | **pointer-escape census** (address-taken → callee) | 323/325/326/329 | **+1 = 3** | ✔ explains A–D's blindness |

Scope stated (rule 18): methods A/B/C/E cover the whole program
(`CFLASH 0x000000–0x17FFFF`, 352,906 instructions, 13,588 functions, 45,142 store instructions).
Method D covers all 1,572,864 bytes of `cflash.bin` at every 2-byte offset.

### Did the methods agree?

**A, B, C and D all returned exactly 2 — and all four were wrong (incomplete).**
This is the rule-17 trap in its most dangerous form: *four instruments agreeing is not
corroboration when they share a failure mode*. I adjudicate in favour of **E = 3 writers**,
because E does not merely disagree, it **explains** the other four:

> The cell's address is loaded into `r5` at `0x1136D0` and passed to `FUN_00113EA8`, which
> stores through it as `se_stb r7,0x0(r6)`. That store has **no absolute reference** (A blind),
> **no resolvable base register** — `r6` is a live-in argument (B and D blind), and **no ram
> varnode** in p-code, because the pointer is a function parameter (C blind, exactly the
> documented "2,050 of 13,588 functions yield no address-resolved memory op" failure mode of
> AGENTS.md rule 44).

Method D additionally produced the lead that cracked it: its `D3` pass (*is literal 3 ever
byte-stored at disp 0x21C or 0xC?*) surfaced 4 candidate sites, three of them in `0x077xxx`,
right beside two of the target's known read sites. Those four turned out to be **false
positives** on adjudication (script `323`) — their bases are `0x40008918`-family cells, not
`0x40002F30` — but chasing them is what forced the decompile of `FUN_0011367E`, where the
`FUN_00113EA8(1, &stack, &DAT_40002F3C)` call is plainly visible.

### Positive controls

- **Same region + same addressing form** (the rule-45 requirement): `0x40002F32` and
  `0x40002F37` — siblings in the *same* struct at `0x40002D20`, reached by the *same*
  `disp(r30)` / `disp(r31)` forms. Every method found both of their writers, and in doing so
  method A/B/C/D **discovered previously unlisted sites** (`0x1135F4`, `0x11363A`) — proof the
  scans detect writers of this exact shape at this exact address.
- **Secondary, different region:** `0x4000965C`, 6 documented writers. A=6/6, C=6/6, B=3/6
  (the misses are the unswept-block sites `0x0AEB88`, `0x0AD738`, `0x0AEBE0`), D=2/6.
- **Decoder round-trip control for method D:** 10 known instructions re-decoded from raw bytes.
  It initially scored 6/10 then 9/10 and *aborted itself* both times, catching two genuine
  decoder bugs (the VLE 16-bit register field is a 16-entry attach `r0-r7,r24-r31`, not a
  register number; and SLEIGH token fields are LSB-numbered, so `XOP_11_VLE=(11,15)` is
  `>>11`, not `>>16`). Only the 10/10 run was used.
- **Negative control:** `0x40002F30` — 0 writers by all methods, so the scans are not simply
  matching everything in the band.

---

## 3. Complete write-site list

| # | address | instruction | function | value stored | literal or computed |
|---|---|---|---|---|---|
| 1 | `0x1135AE` | `e_stb r0,0x21c(r30)` | `FUN_00113580` | **4** | literal (`se_li r0,0x4` @ `0x1135AC`) |
| 2 | `0x11378C` | `se_stb r0,0xc(r31)` | `FUN_0011367E` | **5** | literal (`se_li r0,0x5` @ `0x113786`) |
| 3 | `0x113F5E` | `se_stb r7,0x0(r6)` | `FUN_00113EA8` (Ghidra block `FUN_00113F42`) | **0, 1, or 3** | **computed** — `src_byte & 3` |

Writer 3 is reached from `FUN_0011367E` at call site `0x1136DA`, with
`r5 = 0x40002F3C` (set at `0x1136D0`) and `r3 = 1` (channel index).

Context for writers 1 and 2 (from the decompile of their functions):

- `0x1135AE` — `FUN_00113580` is a **fault/timeout supervisor**: `if (FUN_001148F8(1) != 0) { DAT_40002f3c = 4; ... }`, i.e. **4 = bus-off / error state**.
- `0x11378C` — `FUN_0011367E` sets all three channels to 5 under `if (FUN_00113504() == 1)`,
  where `FUN_00113504` returns `DAT_40003ca6 >> 3 & 1`, i.e. **5 = a global shutdown/sleep override**.
- `0x113F5E` — the **normal per-cycle state refresh**: `FUN_0011367E` calls `FUN_00113EA8`
  once per channel on every pass, *before* the 4/5 overrides. So the pointer writer is the
  routine, frequent writer; 4 and 5 are exceptional.

---

## 4. How 3 is computed — the full traced chain

Every link re-read at instruction level in script `329` (not taken from decompiler output alone):

```
FUN_0011367e:
  0x1136C4  e_lis     r30,0x4000
  0x1136C8  e_add16i  r30,r30,0x2d20     ; r30 = 0x40002D20
  0x1136CC  e_add16i  r31,r30,0x210      ; r31 = 0x40002F30
  0x1136D0  e_add16i  r5,r30,0x21c       ; r5  = 0x40002F3C   <-- ADDRESS ESCAPES
  0x1136D4  se_li     r3,0x1             ; channel index = 1
  0x1136DA  e_bl      0x00113ea8

FUN_00113ea8:
  0x113EB0  se_mr     r6,r5              ; r6 = &DAT_40002F3C
  ...  bounds-check idx against DAT_0011323C=0x00 / DAT_0011323D=0x02
  ...  translate via flash table PTR_DAT_0011322E  (bytes 00 01 02 ...)
  0x113F3A  e_slwi    r7,r5,0x3          ; idx*8
  0x113F3E  se_subf   r5,r7              ; idx*7
  0x113F40  se_slwi   r5,0x1             ; idx*0xE
  0x113F42  e_lis     r7,0x4001
  0x113F46  e_add16i  r7,r7,-0x4f50      ; r7 = 0x4000B0B0
  0x113F4A  se_add    r7,r5              ; r7 = 0x4000B0B0 + idx*0xE
  0x113F4C  se_lbz    r5,0xb(r7)         ; src = arr[idx].status  (SRAM)
  0x113F4E  e_andi    r7,r5,0x1c
  0x113F52  se_srwi   r7,0x2
  0x113F56  se_stb    r7,0x0(r4)         ; *param_2 = (src & 0x1C) >> 2
  0x113F58  e_andi    r7,r5,0x3
  0x113F5E  se_stb    r7,0x0(r6)         ; *0x40002F3C = src & 3     <== WRITER 3
```

So the stored value is `arr[1].status & 3`, range **0..3**. Whether 3 occurs reduces to:
*can the low 2 bits of that status byte be `0b11`?*

`0x4000B0B0` is **SRAM** (block `40000000..40017FFF`), i.e. a runtime structure — it is not
bounded by any flash constant table. Scripts `327`/`328` enumerated its writers and read back
their literals (`329`):

| writer of `arr[idx].status` (`+0xB`) | literal | `& 3` |
|---|---|---|
| `0x113A36` (`FUN_001139BA`) | `0x8F` | **3** |
| `0x113A82` (`FUN_001139BA`) | `0x69` | 1 |
| `0x113AB4` (`FUN_001139BA`) | `0x64` | 0 |
| `0x113B50` (`FUN_00113B02`, init) | `0x64` | 0 |
| `0x113C5C` (`FUN_00113B9A`) | `0x93` | **3** |
| `0x113D6C` (`FUN_00113CAA`) | `0x8F` | **3** |
| `0x113FEA` (`FUN_00113F6C`) | `0x57` | **3** |
| `0x113FFE` (`FUN_00113F6C`) | `0x57` | **3** |

Distinct values reaching `0x40002F3C` through writer 3: **{0, 1, 3}**.
Five of the eight source writers produce 3. Note `0x57` in `FUN_00113F6C` is stored
**unconditionally on both paths** of that function, so it is not a corner case.

Cross-check from the reader side, independent of all the above: `FUN_00077E2C` (which contains
known read sites `0x077EFE` and `0x077FB4`) contains **two separate branches** testing
`DAT_40002F3C != '\x03'`, one of which *returns immediately* when the value is not 3 —
non-3 is the early-out, 3 is the path that continues. `FUN_0004E200` and `FUN_000511AC`
likewise treat `== 3` as the *enabling* condition for their main action. A cell whose 3-state
were unreachable would make the main body of at least four independent functions dead.

---

## 5. Why the original 2-writer scan was a lower bound (and what to change)

Every absolute-reference or base-register method is blind to the dominant writer here. The
general lesson, worth adding to AGENTS.md:

> **Rule candidate (46/47): when a cell's reference list contains an ADDRESS-TAKEN site, the
> writer census is not complete until that callee is followed.** A single
> `e_add16i rX,rBase,disp` whose result is *not* used as a load/store base is a pointer escape;
> from that point the cell can be written by any code the pointer reaches, with no reference,
> no base register and no ram varnode. Method E (scan for materialisations of the cell address
> that are never dereferenced locally) is cheap — 4 hits across the whole image for this cell —
> and is the only method that closes the census. Corollary: **four address-resolving methods
> agreeing on a count is not corroboration; they share one failure mode.**

Method E's escape census also confirms completeness in the other direction: across all 352,906
instructions, the constant `0x40002F3C` is materialised into a register at only **4** sites —
`0x0E2B52` (`APP_did_did_EE8A_read`, a DID reader), `0x1136D0` (the writer path above), and
two more that form the *sibling* addresses. So there is no further hidden pointer writer.

---

## 6. Practical consequence for the remote-start work

- `FUN_000AD6C6`'s outer gate is **satisfied in normal operation**; it is not the reason a
  remote-start trigger would fail to fire. Look further in (the `DAT_40009680` bit-27 term and
  the `DAT_400095F0` / `DAT_4000965C` comparison inside).
- `0x40002F3C` is a **CAN-channel-1 state byte**, semantics roughly
  `0 / 1 / 3 = normal operating sub-states, 4 = bus fault, 5 = commanded off`.
  It is shared by ≥20 readers across the image — do **not** force it in RAM as a trigger lever;
  overwriting it would perturb every one of them, and the periodic `FUN_0011367E` refresh would
  overwrite the forced value on the very next cycle anyway.
