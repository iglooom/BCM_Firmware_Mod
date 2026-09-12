# Gate word `0x40009680` (struct `0x400095EC` + `0x94`) — writers of `0x00800000`, `0x04000000`, `0x08000000`

Project: `ghidra_proj_fullflash` / `BCM_OwnerFlash` / `cflash.bin`. All work read-only.
Scripts: `work/rs-trigger/320_dump_disasm.py`, `321_mask_analysis.py`, `323_scan_and_decomp.py`,
`324_bit23_hunt.py`, `325_rmw_exact.py`, `326_bit27_guards.py`, `327_bit27_input.py`,
`328_producer_raw.py`. Raw logs in `work/rs-trigger/logs/`.

---

## 0. Bit-numbering convention (applies to EVERY claim below)

Because this codebase mixes conventions, every result is quoted as a **literal 32-bit mask
constant**. The conversions used:

| form | rule | verification |
|---|---|---|
| `se_bseti rX,N` / `se_bclri rX,N` / `se_btsti rX,N` | mask = `1 << (31 - N)` (**MSB-numbered operand**) | Ghidra p-code: `INT_RIGHT(const 0x80000000, N)` — dumped at `0x0ADA3C`, `0x0ADA76`, `0x0AC85C`, `0x0AE7CC`, all four agree |
| `rlwinm/rlwimi sh,mb,me` | mb/me MSB-numbered, mask = bits `(31-mb)..(31-me)`, **wrapping when mb > me** | e.g. `0x0ACBC0 e_rlwinm r0,r0,0x0,0x18,0xd` → mb=24 > me=13 → mask `0xFFFC00FF`, i.e. a masked CLEAR of `0x0003FF00`, not a read |
| `e_andi rA,rS,-X` (Ghidra rendering) | `rA = rS & ~(X-1)` | `0x0AD99E e_andi r0,r0,-0x420001` → keep `0xFFBDFFFF`; decompiler independently prints `& 0xffbdffff` |
| decompiler `uVar >> 0x1B & 7` | LSB-numbered shift; `>>0x1B & 7` = mask `0x38000000` | — |

An `e_lwz` / (modify) / `e_stw` triple on `0x94(base)` is treated as **one** read-modify-write event,
keyed on the `e_stw` address. `rlwimi`'s **operand[1] is the source**, operand[0] the destination —
`rlwimi` into the loaded word is scored as "touches mask, value data-dependent", never as a plain set.

**Coverage**: 44 store sites to `+0x94` exist in the image. Ghidra's reference manager lists exactly
44 WRITE refs to `0x40009680`; my linear sweep of `0x0AC000..0x0AF000` found the same 44; all 44 were
decoded by `325_rmw_exact.py`. (The task brief's list of 33 was short by 11 — it stopped before the
`0x0AE9xx..0x0AEExx` block.)

---

## 1. Per-bit write sites

### 1a. `0x08000000` (decompiler bit 27) — the `((word >> 0x1B) & 7) == 7` term

| addr | function | effect | evidence |
|---|---|---|---|
| **`0x0ADA3E`** | `FUN_000ad97c` | **SET** `0x08000000` | `0x0ADA34 e_lwz r0,0x94(r31)` → `0x0ADA3C se_bseti r0,0x4` (mask `1<<(31-4)` = `0x08000000`) → `0x0ADA3E e_stw` |
| **`0x0ADA78`** | `FUN_000ad97c` | **CLEAR** `0x08000000` (and nothing else) | `0x0AD A6E e_lwz` → `0x0ADA76 se_bclri r0,0x4` → `0x0ADA78 e_stw` |
| `0x0AECB0` | `FUN_000aebcc` | CLEAR, but as part of a **compound reset** — touched mask `0x080C0498`, `KEEP=0xF7F3FB67`, `SET=0x00000498`. Reported separately per the brief; do **not** treat as bit-27-specific evidence. |
| `0x0AE82E` | `FUN_000ae820` | **BULK**: `se_li r0,0x0` then `e_stw r0,0x94(r7)` — whole-word zero (module reset/init). Clears every bit. Reported separately. |

**There is exactly ONE bit-specific setter and ONE bit-specific clearer, both in `FUN_000ad97c`.**

Sites that write the word but do **not** touch `0x08000000`: all the other 40.

### 1b. `0x04000000` (decompiler bit 26) — the reset arm in `FUN_000AD6C6`

| addr | function | effect |
|---|---|---|
| **`0x0AC500`** | `FUN_000ac488` | **data-dependent SET-or-CLEAR of exactly `0x04000000`**. `0x0AC4FC e_rlwimi r7,r0,0x1a,0x5,0x5` → sh=26, mb=me=5 → mask `0x04000000`; the source `r0` is `LZCOUNT(VOL_test_and_clear_dirty(&DAT_40003F25, 4) ^ 1) >> 5`, i.e. `1` when the dirty flag was set, else `0`. Decompiler confirms: `DAT_40009680 = ((uint)LZCOUNT(uVar2 ^ 1) >> 5) << 0x1a \| uVar1 & 0xfbffffff;` |
| `0x0AE82E` | `FUN_000ae820` | BULK whole-word zero (see above). |

**No other site in the image touches `0x04000000`.** `FUN_000ac488` is the sole functional writer, and
it is a straight copy of a signal-plane dirty flag — it sets and clears on every invocation.

### 1c. `0x00800000` (decompiler bit 23) — the other half of `((word >> 0x17) & 9) == 1`

| addr | function | effect |
|---|---|---|
| **`0x0AE948`** | `FUN_000ae922` | **SET** `0x00800000` — `0x0AE946 se_bseti r0,0x8` |
| **`0x0AE98A`** | UNSWEPT block at `0x0AE976` (falls into `FUN_000ae958`) | **CLEAR** `0x00800000`, touched mask exactly `0x00800000` — `0x0AE988 se_bclri r0,0x8` |
| `0x0AC87E` | `FUN_000ac85e` | CLEAR, but compound: touched mask `0x01804204`, `KEEP=0xFE7FBDFB`, `SET=0x00004204` (`se_bclri r6,0x8` + `e_or2i r6,0x4204` + an `rlwimi` into `0x01000000`). Reported separately. |
| `0x0AE82E` | `FUN_000ae820` | BULK whole-word zero. |

Guards on the two bit-specific sites (both in the same 2-state machine on `+0x8C` field
`(word8C >> 23) & 3`, read at `0x0AE914 e_rlwinm r0,r0,0x17,0x1e,0x1f`):

```
state = (DAT_40009678 >> 9) & 3            /* +0x8C */
if (state == 1) {                                          /* 0x0AE922 */
    if (VOL_test_and_clear_dirty(&DAT_40003FF1, 2) == 1) { /* 0x0AE92C */
        +0x8C field := 2;
        DAT_40009680 |= 0x00800000;                        /* 0x0AE948  SET   */
    }
} else if (state == 2) {
    if (byte@+0x89 >= 0x32) goto default;                  /* 0x0AE952 */
    ... VOL_test_and_clear_dirty(&DAT_40003FF1,2) refreshes / else +0x89 += 10
} else {                                       /* default, 0x0AE976 */
    +0x8C field := 1;
    DAT_40009680 &= ~0x00800000;                           /* 0x0AE98A  CLEAR */
}
```

Note the **structural identity** with the bit-27 machine in §2: same shape, same
`VOL_test_and_clear_dirty` input, same "hold until a `+10`/tick counter reaches a limit" tail.

---

## 2. Guarding conditions on the bit-27 producer (`FUN_000ad97c`, store `0x0ADA3E`)

Decompiled (`work/rs-trigger/logs/gate_scan.txt` line 45ff). `unaff_r31` = `0x400095EC`,
so `unaff_r31[0x24]` = `+0x90` = `0x4000967C`, `unaff_r31[0x25]` = `+0x94` = `0x40009680`.
`param_1` = `0x400095DC`, so `*(char*)(param_1 + 5)` = **`DAT_400095E1`**.

```c
LAB_000ada12:
  state = (DAT_4000967C >> 0x1A) & 3;          /* +0x90 field, mask 0x0C000000 */
  if (state == 1) {
      if (DAT_400095E1 == 1) {                 /* 0x0ADA26  se_cmpi r0,0x1     */
          DAT_4000967C = DAT_4000967C & 0xf3ffffff | 0x08000000;  /* field := 2 */
          DAT_40009680 |= 0x08000000;          /* <== 0x0ADA3E  SET            */
          goto hold;
      }
  } else {
      if (state == 2 && *(byte*)(0x400095EC+0x86) < 200) goto hold;
      DAT_4000967C = DAT_4000967C & 0xf3ffffff | 0x04000000;      /* field := 1 */
      DAT_40009680 &= 0xf7ffffff;              /* <== 0x0ADA78  CLEAR          */
      *(u32*)(0x400095EC+0x5C) = 0;
      *(u8 *)(0x400095EC+0x86) = 0;
  }
hold:                                          /* LAB_000ada4e */
  if (DAT_400095E1 == 1) byte@+0x86 = 0;       /* input still asserted -> hold  */
  else                   byte@+0x86 += 10;     /* 10 ms tick accumulator        */
```

So, in one sentence: **bit `0x08000000` is set on the tick that `DAT_400095E1` reads 1 while the
`+0x90` sub-state is 1, held for as long as `DAT_400095E1` keeps reading 1, plus a tail of
`200/10 = 20` ticks (~200 ms) after it drops, then cleared.** The function itself is additionally
reached only past the `DAT_40003CE5` bit-`0x20` test at `0x0AD984` and the ancestors of
`LAB_000ada12`; the `DAT_400095E1 == 1` test is the **sole data term** that decides the bit.

### The input `DAT_400095E1` has exactly one writer in the whole image

Reference manager + an independent per-function base+displacement sweep agree (`327_bit27_input.py`):
`0x400095E1` has **11 readers and 1 writer**, the writer being `0x0AEF14` in `FUN_000aeec6`:

```
0AEED4  e_addi r3, r29, 0x51          ; &APP_rke_code_valid   (0x40003F53)
0AEED8  se_li  r4, 0x2
0AEEDA  e_bl   0x00031360             ; VOL_test_and_clear_dirty(flag, bit 2 -> 0x20)
0AEEE6  se_stb r3, 0x3(r30)           ; -> DAT_4000968B
...
0AEF0A  se_lbz r0, 0x3(r30)           ; DAT_4000968B
0AEF14  se_stb r0, 0x5(r25)           ; -> DAT_400095E1      <<< SOLE WRITER
```

`FUN_000aeec6` is a direct callee of `APP_feature_periodic` (`0x62848`) — it runs every periodic tick.

---

## 3. Assessment: is bit `0x08000000` externally driven, or internally computed?

**Externally driven — specifically, driven from received CAN data.** Confidence: high.

The evidence chain is fully static and does not rely on the vehicle observation:

1. `0x0ADA3E` is the only bit-specific setter, and its only data term is `DAT_400095E1 == 1`.
2. `DAT_400095E1`'s only writer copies `VOL_test_and_clear_dirty(&APP_rke_code_valid /*0x40003F53*/, 2)`.
3. `APP_rke_code_valid` `0x40003F53` is this project's already-proven RKE receive flag: it is raised
   by the Volcano RX codec when MS-CAN `0x100` `d6:d7` decodes into `APP_rke_command_code`
   `0x40002DA2` (`docs/rke_0x100_lock.md` §3, `docs/tx_pack_stage.md` §431,
   `docs/remote_start.md` §45; bench-observed going `0000 → 1801` on a press,
   `rke_chain_diagram.html`).
4. `VOL_test_and_clear_dirty` (`0x031360`) is a **test-and-clear**: the flag is true only on the tick
   after the producer flagged a change, and self-clears. That is exactly the signature of a
   "refreshed while frames keep arriving, decays when they stop" input — not of a computed state.

This also explains the observed **~1.7 s** assertion quantitatively: an RF fob transmits a burst of
repeat frames, each re-raising `0x40003F53`, which pins `byte@+0x86` at 0 and holds the bit; when
the burst ends the ~200 ms `+10`/tick tail runs out and `0x0ADA78` clears it. No internal timer in
`FUN_000ad97c` could produce a 1.7 s duration on its own — its own limit is 200 units.

### Practical consequence for a RAM-poke trigger

Forcing `0x08000000` directly in `0x40009680` is **unsafe**: `FUN_000ad97c` runs on the periodic
tick and will re-clear it via `0x0ADA78` within ~200 ms of the next tick where `DAT_400095E1` is 0.
The correct injection point is **upstream** — set `APP_rke_command_code` + `APP_rke_code_valid`
(`docs/rs_trigger_design.md` "Depth 2") and let `FUN_000aeec6 → DAT_400095E1 → 0x0ADA3E` set the
bit natively. That is consistent with, and now mechanistically explains, the Depth-2 design already
in the repo.

### Note on `0x04000000` and `0x00800000`

Both are the same architectural pattern: `0x04000000` is a **direct copy** of a signal-plane dirty
flag (`DAT_40003F25`) with no state machine at all, and `0x00800000` is driven by a
`VOL_test_and_clear_dirty(&DAT_40003FF1, 2)` through a state machine structurally identical to the
bit-27 one. All three bits of the gate word examined here are **externally sourced**, not computed.
The specific signal identities of `0x40003F25` and `0x40003FF1` are **not established** — they are
flags in the same `0x40003Fxx` RX dirty-flag plane as `APP_rke_code_valid`, but no project artefact
names them.
