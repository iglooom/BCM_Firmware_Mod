# Reading HS-CAN 0x0C0 d0 (Cruise_StandBy / Cruise_Mode) from a TX-time hook

**Firmware:** Ford BCM C1MCA, SPC560B64L7 (MPC5607B, e200z0h, big-endian, VLE).
Image: `work/flash_merged.bin` (flat, base 0x0). All addresses absolute.

## TL;DR

| Item | Value |
|---|---|
| 0x0C0 hardware FlexCAN MB index (CAN0) | **MB30** |
| Raw MB30 d0 (byte0) absolute addr | **0xFFFC0268** |
| RAM frame-image d0 absolute addr | **0x40000707** |
| **Recommended read (hook)** | **0x40000707** (plain RAM, no lock) |
| Fallback | 0xFFFC0268 (raw MB, needs CODE!=BUSY check + critical section) |
| Paused test | `((d0 & 0x08) != 0) && ((d0 & 0x70) != 0)` |

Raw byte and RAM image are **byte-identical** (straight byte copy, no bit repack), so the bit
layout (bit3=StandBy, bits4..6=mode) is preserved in the RAM image.

---

## Q1 — Proven MB index for 0x0C0 = MB30

### Filter list @ 0x146530 (12-byte records `[id<<18][flags][mask]`)
Position [30] = 0x0C0 (RX). Raw scan (`work/scan_0c0.py`):
```
[ 0] id=0x030 flags=0x08080000  (TX)
...
[16] id=0x72E flags=0x08080000  (TX, last TX)
[17] id=0x010 flags=0x04080000  (first RX)
...
[30] off=0x146698 w0=0x03000000 id=0x0C0 flags=0x04080000 mask=0xFFFFFFFF   <== RX
```
`0x03000000 >> 18 = 0x0C0`. flags 0x04 = RX.

### Bring-up code proves MB index == filter-list position
`FUN_000fceb8` (@0x000FCEB8, net0 config vector entry at master-net-table 0x178D8) is the
FlexCAN hardware bring-up. The controller descriptor is 0x1464E0; the MB-config array is the
filter list at ctrlDesc+0x50 = **0x146530**. The loop that writes each MB's ID/CS word walks the
list **sequentially** and writes MB[i] at `base + 0x80 + i*0x10`:
```c
lVar7 = uVar15 + 0x80;                       // uVar15 = FlexCAN base 0xFFFC0000 -> MB0 CS
for (uVar6 = 0; uVar6 < uVar9; uVar6 = uVar6 + 1) {   // uVar9 = MB count (0x40)
    *(u32*)((u16*)lVar7 + 2) = *(u32*)(pcVar14 + uVar6*0xc + 0x50);  // MB[i].ID  = list[i].w0 (id<<18)
    *(u16*)lVar7           = *(u16*)(pcVar14 + uVar6*0xc + 0x54);    // MB[i].CS  = list[i].flags
    lVar7 = lVar7 + 0x10;                     // next MB (+0x10)
}
```
`pcVar14 + 0x50` = ctrlDesc+0x50 = 0x146530 (list base); stride `uVar6*0xc` = 12-byte records;
MB stride `+0x10`. Therefore **list index i is programmed into hardware mailbox i**.
=> list[30]=0x0C0 is programmed into **MB30**.

MB30 absolute addresses (CAN0 base 0xFFFC0000):
- CS word: 0xFFFC0000 + 0x80 + 30*0x10 = **0xFFFC0260**
- ID word: 0xFFFC0264
- **data d0 (byte0): 0xFFFC0268**

Independent confirmation from the RX/TX runtime: both the RX copier `FUN_000fc63e` and the TX
packer `flexcan_tx_packer` (@0x000FC218) address a mailbox as `base + 0x80 + MBidx*0x10`, using a
per-record MB-index byte — same MB numbering.

---

## Q2 — RAM frame-image for 0x0C0 d0 = 0x40000707

The Volcano RX copier `flexcan_rx_copier` (`FUN_000fc63e` @0x000FC63E) walks 28-byte reception
records (`piVar10 += 7` words). Per record it reads the **hardware MB directly**:
```c
puVar9 = base + 0x80 + rec[0x19]*0x10;    // rec[0x19] = MB index
... BUSY poll (uVar1 & 0x100) ...
puVar9 = puVar9 + 4;                      // -> MB data byte0 (MB+0x08)
for (m = rec[0x1a]; m != 0; m >>= 1) {    // rec[0x1a] = per-byte copy mask, bit0=d0
    if (m & 1) { *dest = *(u8*)puVar9; dest++; }   // RAW byte copy, no bit manipulation
    puVar9 = (u8*)puVar9 + 1;
}
```

**The RX record for MB30** (found by scanning flash for `+0x19 == 0x1E` with a RAM word0;
`work/scan_mb30.py`, `work/scan_final.py`) exists at 0x14ADB8 / 0x14C800 / 0x14E048 (three
identical copies for the net's redundant record sets):
```
copier RX record @0x14ADB8 (28B):
  +0x00 dest(word0)   = 0x40000707     <-- frame-image base
  +0x08 statusFlagPtr = 0x400001A2     <-- freshness flag OR'd on update
  +0x18 DLC           = 8
  +0x19 MBidx         = 30 (0x1E)      <-- MATCHES Q1 (MB30 == 0x0C0)
  +0x1a copymask      = 0x13           <-- bits 0,1,4 -> copies MB bytes d0,d1,d4
```
copymask 0x13 = bits {0,1,4}, so the image is **compacted** (only 3 stored bytes, contiguous):
```
raw MB byte0 (d0) -> 0x40000707   <== target
raw MB byte1 (d1) -> 0x40000708
raw MB byte4 (d4) -> 0x40000709
```
`copymask & 1 != 0` => **byte0 (d0) IS copied**, landing at word0 = **0x40000707**.

### Cross-check (the two routes agree)
- Route A (raw MB index): filter list pos 30 -> MB30 (bring-up loop).
- Route B (reception descriptor): the copier record whose MB-index byte = 30 -> frame image 0x40000707.

Both routes independently point at the **same physical mailbox (MB30 = 0x0C0)**. Consistent.

---

## Q3 — Recommended source: RAM frame-image 0x40000707

**Read 0x40000707.** It is plain RAM, written by the RX copier task/ISR as a straight byte copy
of raw MB30 d0. A TX-time hook can load it with a single `lbz` — no side effects.

Why NOT read the raw MB (0xFFFC0268) from the hook: the FlexCAN RX read sequence is non-trivial
and stateful. The copier does it under a critical section and with a BUSY poll:
- `FUN_0004495a()` / `FUN_00044984()` bracket the read — these are lock/critical-section
  enter/leave helpers (ref-counted, mask interrupts). Evidence:
  `FUN_0004495a` increments `DAT_4000433c` and calls `FUN_0002f3ba`; `FUN_00044984` decrements and
  calls `FUN_0002f3ca` (enter/leave).
- BUSY guard: `do { uVar1 = *puVar9; } while (uVar1 & 0x100);` — must wait out CODE=BUSY(0x100)
  before the data is coherent, and the normal flow then writes CS to release/lock the MB.

Reading an RX MB data byte from a TX hook **without** that lock/BUSY handshake risks a torn read
(mid-DMA update, BUSY set) and can disturb MB lock state. The decoded RAM image sidesteps all of
that.

- **Recommended:** `lbz` from **0x40000707**.
- **Fallback (if RAM image ever suspect):** raw MB30 d0 at **0xFFFC0268**, but first verify
  `(*(u16*)0xFFFC0260 & 0x100) == 0` (not BUSY) and ideally inside a short critical section.

---

## Q4 — Bit semantics and the paused test

The frame image **preserves the raw CAN d0 layout** — the copier does `*dest = *(u8*)MBdata`
with no shift/mask/repack. So the same bit test applies to 0x40000707 and to 0xFFFC0268:

- bit3, mask **0x08** = Cruise_StandBy (1 = engaged-but-paused)
- bits4..6, mask **0x70** = Cruise_Mode (0 = off; 1=ACC, 3=LIM, 4=transition)

**Engaged-but-paused test:**
```c
uint8_t d0 = *(volatile uint8_t*)0x40000707;
if ( ((d0 & 0x08) != 0) && ((d0 & 0x70) != 0) ) {
    /* StandBy=1 AND mode!=0  -> map RES+ to CC_Res */
}
```

Because the image is a verbatim byte copy (no Volcano unpack/repack for this byte), the RAM image
is preferred and is fully equivalent bit-for-bit to the raw mailbox byte.

---

## Evidence index (addresses)
- Filter list base: 0x146530 (ctrlDesc 0x1464E0 +0x50). List[30]=0x0C0 @0x146698.
- Bring-up (MB ID programming loop): `FUN_000fceb8` @0x000FCEB8 (net0 cfg vector @0x178D8).
- RX copier: `flexcan_rx_copier` `FUN_000fc63e` @0x000FC63E.
- MB30 copier RX record: 0x14ADB8 (dup 0x14C800, 0x14E048): dest=0x40000707, MBidx=0x1E, mask=0x13.
- Lock/BUSY helpers: `FUN_0004495a`/`FUN_00044984` @0x0004495A/0x00044984.
- Raw MB30: CS 0xFFFC0260, ID 0xFFFC0264, **d0 0xFFFC0268**.
- **RAM frame-image d0: 0x40000707** (freshness flag 0x400001A2).

Scripts (read-only): `work/scan_0c0.py`, `work/scan_ctrl.py`, `work/scan_mb30.py`,
`work/scan_final.py`.
