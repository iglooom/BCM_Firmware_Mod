# Reading RX frame bytes from a TX-time hook — `0x0C0` d0 and `0x060` d6

**Firmware:** Ford BCM C1MCA, SPC560B64L7 (MPC5607B, e200z0h, big-endian, VLE).
Image: `work/flash_merged.bin` (flat, base 0x0). All addresses absolute.

This is the derivation of the two RAM addresses the shipped `acc-fix` gate reads. The **gate logic
itself lives in `acc-fix.md` §3** — this document only proves *where the bytes are* and *why the RAM
frame image is the safe source*.

| Item | `0x0C0` d0 (PCM cruise status) | `0x060` d6 (stored set-speed) |
|---|---|---|
| CAN0 mailbox | **MB30** | **MB22** |
| Raw MB data byte | `0xFFFC0268` | — |
| Image base / copymask | `0x40000707` / `0x13` | `0x40000700` / `0xFE` |
| **RAM address (what the hook reads)** | **`0x40000707`** | **`0x40000705`** |

> ⚡ **This lookup is now precomputed for all 279 RX frames** in `work/owner/rx_frame_map.json`
> (see `gateway_map.md` §3.1). Use the manual method below to verify, or when the JSON is
> unavailable.

---

## 1. Mailbox index = filter-list position (b)

HS-CAN filter list @ `0x146530`, 12-byte records `[id<<18][flags][mask]`:

```
[ 0] id=0x030 flags=0x08080000  (TX)
[16] id=0x72E flags=0x08080000  (TX, last TX)
[17] id=0x010 flags=0x04080000  (first RX)
[22] id=0x060 flags=0x04080000  (RX)
[30] @0x146698 w0=0x03000000 id=0x0C0 flags=0x04080000 mask=0xFFFFFFFF  (RX)
```

`0x03000000 >> 18 = 0x0C0`; flags `0x04` = RX.

The bring-up function `FUN_000fceb8` (net0 config-vector entry at master-net-table `0x178D8`) walks
the list **sequentially** and writes MB[i] at `base + 0x80 + i*0x10`:

```c
lVar7 = flexcan_base + 0x80;                      // MB0 CS
for (i = 0; i < mbcount; i++) {
    *(u32*)((u16*)lVar7 + 2) = *(u32*)(ctrlDesc + i*0xc + 0x50);  // MB[i].ID = list[i].w0
    *(u16*)lVar7             = *(u16*)(ctrlDesc + i*0xc + 0x54);  // MB[i].CS = list[i].flags
    lVar7 += 0x10;
}
```

⇒ **list index i is programmed into hardware mailbox i.** Independently confirmed by the RX copier
and the TX packer, which both address a mailbox as `base + 0x80 + MBidx*0x10`.

MB30 (`0x0C0`) absolute addresses: CS `0xFFFC0260`, ID `0xFFFC0264`, **d0 `0xFFFC0268`**.

---

## 2. The RAM frame image (a)

The RX copier `FUN_000fc63e` walks 28-byte reception records and copies straight from the hardware
mailbox:

```c
puVar9 = base + 0x80 + rec[0x19]*0x10;    // rec[0x19] = MB index
... BUSY poll (uVar1 & 0x100) ...
puVar9 += 4;                              // -> MB data byte0
for (m = rec[0x1a]; m != 0; m >>= 1) {    // rec[0x1a] = per-byte copymask, bit0 = d0
    if (m & 1) { *dest = *(u8*)puVar9; dest++; }   // RAW byte copy, no bit manipulation
    puVar9 = (u8*)puVar9 + 1;
}
```

Two properties matter:

1. **The copy is verbatim per byte** — no unpack/repack — so the RAM byte preserves the exact wire
   bit layout.
2. **⚠ The destination is compacted**: `dest` advances only for set mask bits. A CAN byte's image
   offset is `popcount(copymask & ((1<<k)-1))`, **not** the CAN byte index.

### `0x0C0` — record @`0x14ADB8` (dups `0x14C800`, `0x14E048`)

```
+0x00 dest        = 0x40000707    <-- frame-image base
+0x08 arrivalFlag = 0x400001A2
+0x18 DLC         = 8
+0x19 MBidx       = 30 (0x1E)     <-- matches §1
+0x1a copymask    = 0x13          <-- bits {0,1,4}: copies d0, d1, d4
```

`copymask & 1` set ⇒ d0 is copied and lands first: **`0x40000707`**.

### `0x060` — MB22

Image base `0x40000700`, copymask `0xFE`. d6 is preceded by 5 set bits {1,2,3,4,5}
⇒ **`0x40000700 + 5 = 0x40000705`**. (The naive `base+6` would be wrong — this is the compaction
trap.)

**Cross-check:** both routes — filter-list position → MB index, and reception descriptor → MB-index
field — independently identify the same physical mailbox. The owner-flash frame-map decode
(`gateway_map.md` §3.1) reproduces both addresses from the general formula as a third route.

---

## 3. Why read RAM, never the raw mailbox, from a TX hook

Reading an RX mailbox from a TX-time hook risks a torn read and can disturb mailbox lock state. The
copier only does it under a critical section with a BUSY poll:

- `FUN_0004495a` / `FUN_00044984` bracket the read — ref-counted critical-section enter/leave
  (`FUN_0004495a` increments `DAT_4000433c` and calls `FUN_0002f3ba`; `FUN_00044984` decrements and
  calls `FUN_0002f3ca`).
- BUSY guard: `do { uVar1 = *puVar9; } while (uVar1 & 0x100);` — CODE=BUSY must clear before the
  data is coherent, and the normal flow then writes CS to release/lock the mailbox.

The decoded RAM image sidesteps all of that: a single `e_lbz`, no side effects. That is what both
shipped caves do.

Fallback, only if the RAM image is ever suspect: raw MB30 d0 at `0xFFFC0268`, after verifying
`(*(u16*)0xFFFC0260 & 0x100) == 0`, ideally inside a short critical section.

---

## 4. Bit semantics of `0x0C0` d0

The image preserves the wire layout, so the same tests apply to `0x40000707` and `0xFFFC0268`:

- bit3 (`0x08`) = StandBy
- bits4..6 (`0x70`) = mode (0 = off, 1 = ACC, 3 = LIM, 4 = transition)

> ⚠ **Do not build a "paused" test from these fields alone.** An early version of this doc proposed
> `(d0 & 0x08) && (d0 & 0x70)`; that gate was **disproven on the vehicle** — the status byte decays
> ~2 s after a cancel, making cancelled indistinguishable from engaged-but-no-speed-set. The shipped
> rule combines `0x0C0` d0 with the `0x060` d6 set-speed; see **`acc-fix.md` §3** for the observed
> status codes, the decay behaviour and the final gate.

---

## 5. Evidence index

- Filter list base `0x146530` (ctrlDesc `0x1464E0` + `0x50`); list[30] = `0x0C0` @`0x146698`.
- Hardware bring-up (MB ID programming loop): `FUN_000fceb8` @`0x000FCEB8`.
- RX copier: `FUN_000fc63e` @`0x000FC63E`.
- MB30 reception record: `0x14ADB8` (dups `0x14C800`, `0x14E048`).
- Critical-section helpers: `FUN_0004495a` / `FUN_00044984`.
- Scripts: the original ad-hoc `work/scan_*.py` probes were not kept; the derivation is fully
  reproduced (and generalised to all 279 RX frames) by `work/owner/80_rx_record_decode.py` →
  `work/owner/83_annotate_l13_rxmap.py`. Read-only cross-checks: `work/gw_mbfull.py` (filter lists),
  `work/gw_rxdesc.py` (reception descriptors), `work/gw_dec.py 0xfc63e` (the copier).
