# Ford BCM (C1MCA) — HS-CAN ↔ MS-CAN ID Interaction Map

**Overall picture of which CAN IDs cross between the two main buses.** High-level only
(no bit-level conversion formulas). Companion to `gateway_map_format.md` (table layout) and
`gateway_map_current.md` (signal-level notes).

- **HS-CAN** = FlexCAN CAN_0 @ `0xFFFC0000`, **500 kbps** (main high-speed bus)
- **MS-CAN** = FlexCAN CAN_1 @ `0xFFFC4000`, **125 kbps** (mid-speed body bus)
- Source of truth: FlexCAN acceptance-filter tables (`[id<<18][dir][mask]`), **HS @0x146530**,
  **MS @0x146950**. Direction flag: high byte `0x04` = RX (bus listens), `0x08` = TX (bus sends).
- Confidence **(b)** — validated descriptor-table structure. The BCM is a table-driven Volcano
  gateway; these tables define exactly which IDs each controller accepts and emits.

---

## 1. Same-ID appearance on both buses — ⚠ NOT proven to be forwarding

Some CAN IDs appear as **RX on one bus and TX on the other**. It is tempting to read these as
"bridged" frames, but **that is not supported by evidence** and an earlier version of this document
was WRONG to list them as forwards.

**Why it's not forwarding:** these pairs come purely from *acceptance-filter coincidence* (same ID
number present in both lists). Checking the actual signal routing shows **no shared signal-RAM**
between the HS-receive path and the MS-transmit path for these IDs. The correct interpretation is
that the BCM **independently consumes** the HS-CAN frame (using its signals for internal logic) and
**independently produces its own, separately-populated frame of the same ID number** on MS-CAN.
Same ID number ≠ same content, ≠ a forward.

> Example (user-confirmed): **0x040** — the BCM receives HS-CAN 0x040 and consumes it; it also
> transmits an MS-CAN 0x040 that it builds itself. The two 0x040 frames are independent.

IDs that appear on both buses (RX one side / TX other) — treat each as "consumed here, independently
produced there" unless shared signal-RAM is proven:

| ID | HS | MS | ID | HS | MS |
|:--:|:--:|:--:|:--:|:--:|:--:|
| 0x020 | RX | TX | 0x1C0 | RX | TX |
| 0x040 | RX | TX | 0x1E0 | RX | TX |
| 0x060 | RX | TX | 0x250 | RX | TX |
| 0x070 | RX | TX | 0x270 | RX | TX |
| 0x080 | RX | TX | 0x280 | RX | TX |
| 0x1A8 | RX | TX | 0x030 | TX | RX |
| 0x1B0 | RX | TX | 0x150 | TX | RX |

**To upgrade any row to a real forward** you must prove shared signal-RAM between the HS-receive
frameObj and the MS-transmit frameObj for that ID (via the reception/transmission descriptor chain).
That work is not done for these IDs.

---

## 2. Cross-ID translation (repacked into a DIFFERENT ID on the other bus)

Signals from one bus are unpacked and re-packed into a differently-numbered frame on the other bus
(via shared signal-RAM). Proven so far:

| Source (HS-CAN RX) | → | Target (MS-CAN TX) | Basis |
|:------------------:|:-:|:------------------:|-------|
| **0x0C0** | → | **0x020** | 7 shared signal-RAM cells (0x40000751/774/77B/78A/78D/79F/7A1) — (b) |

⚠ **This cross-ID list is NOT exhaustive.** Only 0x0C0→0x020 is confirmed. A complete cross-ID
enumeration needs the frame-object→CAN-ID binding (open item — the routing table's `spec1` field was
verified NOT to be the CAN ID, so IDs must be resolved via the reception/transmission descriptor
chain). MS TX 0x020 therefore aggregates at least: its own same-ID HS 0x020 bridge **plus**
translated content from HS 0x0C0 (and probably HS 0x060, whose signal set overlaps).

---

## 3. Reference: full per-bus ID inventory (from acceptance filters)

**HS-CAN receives (RX, 46 IDs):**
`0x010 0x020 0x040 0x04A 0x04B 0x060 0x06A 0x070 0x080 0x090 0x0A0 0x0A5 0x0B0 0x0C0 0x0D0 0x0E0
0x0F8 0x100 0x120 0x130 0x138 0x140 0x160 0x170 0x180 0x190 0x1A0 0x1A8 0x1B0 0x1B5 0x1C0 0x1D0
0x1E0 0x1E8 0x200 0x208 0x210 0x218 0x229 0x250 0x252 0x269 0x270 0x280 0x298 0x500`

**HS-CAN transmits (TX, 17 IDs):**
`0x030 0x0C8 0x150 0x17E 0x260 0x290 0x310 0x360 0x380 0x3B4 0x400 0x405 0x40A 0x420 0x435 0x581 0x72E`

**MS-CAN receives (RX, 14 IDs):**
`0x010 0x030 0x090 0x0A0 0x100 0x108 0x130 0x150 0x160 0x180 0x190 0x1A0 0x1B8 0x500`

**MS-CAN transmits (TX, 49 IDs):**
`0x020 0x03A 0x040 0x060 0x070 0x080 0x083 0x110 0x1A4 0x1A8 0x1B0 0x1B4 0x1C0 0x1E0 0x215 0x217
0x220 0x230 0x240 0x241 0x250 0x265 0x270 0x280 0x281 0x290 0x295 0x2A0 0x2A7 0x300 0x320 0x340
0x360 0x361 0x363 0x370 0x3A0 0x400 0x405 0x40A 0x415 0x435 0x440 0x501 0x581 0x690 0x72E 0x7CC 0x7CE`

(IDs that appear as RX on one bus with no same-ID TX on the other are either BCM-internal consumers
or cross-ID-translation sources/targets like 0x0C0→0x020.)

---

## Bottom line

- **Many IDs appear on both buses** (RX one side, TX the other), but this is **acceptance-filter
  coincidence, NOT proven forwarding.** Default reading: the BCM independently consumes the incoming
  frame and independently builds its own same-numbered frame on the other bus (confirmed for 0x040).
- **Only one genuine cross-bus signal link is proven:** HS 0x0C0 → MS 0x020 (shared signal-RAM).
- Proving any other real forward requires shared-signal-RAM evidence via the descriptor chain —
  not yet done.
- The per-bus ID inventory (Section 3) is authoritative; the *interaction* between IDs is mostly
  still open.
