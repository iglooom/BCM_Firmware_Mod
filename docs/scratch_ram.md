# Scratch RAM for a persistent code-hook latch — SPC560B64 / MPC5607B BCM

Target: one persistent scratch byte (ideally an 8+ byte run) in SRAM
`0x40000000..0x40017FFF` that **no firmware code path ever reads or writes**
except the one-time startup ECC/zero-init, safe to read/write from the periodic
TX task and surviving across CAN frames (~10 ms).

## Recommendation

- **Recommended address: `0x40011000`**
- **Safe contiguous run: 5056 bytes** ( `0x40011000 .. 0x400123C0` ), zero
  references and zero raw-pointer coincidences in the whole flash.
- **Fallback address: `0x40013000`** (same hole, page-aligned, `0x40013000..0x40013FA0`
  = 4000 bytes clean; sits just below the ECC-init top `0x40014000`).

Use as little as you need (1 byte); the run gives generous headroom and alignment.

## Memory map derived from startup (reset `0x0010F4A0`)

Startup chain: `reset_head` → `FUN_0002FDF2` (clocks + SRAM ECC/paint) → set
`SP` and SDA bases → `.bss` clear → `.data` copy → app.

- **RAM ECC/zero init** (`FUN_0002FDF2`, `e_stmw`/`e_stw` of `0x8000011B`):
  writes **`0x400039A0 .. 0x40014000`** (all of low+mid SRAM). This is the
  allowed "startup zero-init" — it only runs once at reset.
- **Stack-paint fill** (`0xEBEBEBEB`): **`0x4000B100 .. 0x4000F920`** (high-water
  canary paint over the stack/heap band).
- **Stack pointer init**: `e_lwz r1,0x5F38(r3)` with `r3=0x10000` → word at file
  `0x15F38` = **`SP = 0x4000CAC8`**. e200z0h stack grows **down** from
  `0x4000CAC8`; the painted band `0x4000B100..0x4000F920` brackets it (stack below
  SP toward `0x4000B100`, reserved/heap above SP toward `0x4000F920`).
- **SDA bases**: `r13 = r2 = 0x40017920` (`e_lis/e_add16i`). Small-data reach is
  `0x40017920 ± 32 KiB` = **`0x4000F920 .. 0x4001F91F`**.

### Static-data extents (exact `[start,end)`)

- **.data** (flash→RAM copy loop, `e_lbzu/e_stbu`): dst **`0x40003A60 .. 0x40005492`**
  (src flash `0x1156C0…`).
- **.bss/.sbss** (byte clear loop): **`0x400054A0 .. 0x4000B06C`**.
- Highest referenced static byte cluster tops out around **`0x4000B188`**;
  effective **static-data end ≈ `0x4000B188`** (a few small globals sit at
  `0x4000B180/0x4000CAE0/0x4000F380`, all individually referenced and avoided).

### Where used RAM actually lives (from 28,536 resolved SRAM references + 5,740
defined data items; Ghidra resolves r13/r2 SDA displacements to absolute, so these
cover base+displacement access, not just absolute pointers)

- CAN signal/frame-image RAM: `~0x40000600 .. 0x4000B188` (dense).
- SDA globals cluster: heavy around **`0x40017920 .. 0x40017EE8`**.
- Max referenced target in all of flash: **`0x40017920`** (nothing above it).

## The chosen hole and why it is safe

The largest fully-untouched holes (no reference, no defined data) are:

| range | bytes | in ECC-init? | in stack paint? | notes |
|---|---|---|---|---|
| `0x40010501..0x40013FA0` | 15007 | yes (zeroed) | no | **chosen band** |
| `0x40013FA1..0x40017920` | 14719 | partly | no | ends exactly at SDA base |
| `0x4000CAE4..0x4000F380` | 10396 | yes | **yes** (above SP) | riskier: heap/stack band |

`0x40011000` sits in the first band:

1. **Zero Ghidra references** to any byte in `0x40010501..0x40013FA0` (out of 28,536
   SRAM refs), and **zero defined data**.
2. **Zero aligned raw-pointer hits**: a full flash scan (`0x10000..0x15BF4C`) for
   BE words in `0x40011000..0x400123C0` returns **0** matches. The five word-matches
   anywhere in the wider band are all **unaligned** (file offset %4 ∈ {1,2}) — i.e.
   coincidental bytes inside instruction/data streams, not pointers, and none are
   referenced.
3. **Not stack**: stack grows down from `SP=0x4000CAC8`; `0x40011000` is far above
   and cannot be reached by the stack.
4. **Not the painted heap band** (`0x4000B100..0x4000F920`): `0x40011000` is above it.
5. **Within ECC-init range** (`..0x40014000`) so it is defined/zeroed at reset — the
   only writer, and only once. Persists thereafter across every CAN frame.
6. Although it is inside the SDA reach window (`0x4000F920..0x4001F91F`), **no
   SDA-relative access resolves into it** — all real SDA traffic lands at
   `0x40017920+`. Ghidra resolved the SDA base, so SDA displacement accesses are
   included in the reference count that shows this hole empty.

## Residual risk

- **Low.** The only firmware writer proven to touch `0x40011000` is the one-time
  reset ECC/zero-init; after boot nothing reads or writes it.
- The address is inside the ±32 KiB SDA window. Static analysis found no SDA access
  there, but a compiler-emitted SDA displacement that Ghidra failed to resolve is the
  main theoretical gap. Mitigation: the fallback `0x40013000` and the whole
  `0x40010501..0x40013FA0` band share the same evidence, and if extra distance from
  the SDA cluster is wanted, staying at the low end of the band (`0x40011000`) keeps
  displacement `0x40011000-0x40017920 = -0x6920` well away from the used
  `-0x0000..+0x05C8` SDA offsets.
- No dynamic allocator was identified above SP; if one exists and grows past
  `0x4000F920` it would still not reach `0x40011000` (heap paint stops at
  `0x4000F920`).
- **Final confirmation** should be a bench/vehicle check: write a sentinel to
  `0x40011000` at hook install and read it back after several seconds of normal
  operation to confirm no other task clobbered it.
