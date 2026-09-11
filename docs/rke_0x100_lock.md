# RKE lock/unlock decode — MS-CAN `0x100` — evidence note

> ✅ Part of the shipped **rke-lock** mod. Authoritative writeup: **`docs/rke-lock.md`** (README §5.5).
> This note is the button-decode evidence.

Firmware: Ford BCM C1MCA (JV6T-14C094-AD). Image `work/flash_merged.bin`.
Captures: `mmcan_rke_open.log` (UNLOCK press), `mmcan_rke_close.log` (LOCK press). Bus `can1` = **MS-CAN**.
(All bit/field meanings below are derived purely by decoding the referenced candump captures —
positions and values observed on the wire, correlated with the physical button action.)

## 1. The button bits (PROVEN from captures)

Frame `0x100` (from the remote-keyless module), 60 ms periodic, 8 bytes.
Idle payload `0217000002000000`; button press bursts differ only in the **last two bytes d6:d7**.

Non-baseline frames observed:
| event | d6:d7 words |
|---|---|
| UNLOCK | `1FE2 1FF2 3FE2 3FF2` |
| LOCK   | `1FE1 1FF1 3FE1 3FF1` |
| RELEASE| `2000` |

The trailing field is a **13-bit command code + 1 valid/"update" bit**, spanning **d6:d7**:
- **valid bit = d6 bit2 (0x04)** → asserted while a *validated* button message is active, `0` on
  release. ⚠ CORRECTION (log `mmcan_ignoon_keyout_rke_lock6.log`): it is **not** set on every
  button-active frame — the RFA only asserts it once the rolling code is validated, which can lag
  several presses (presses 1–3 had the lock bit active with UB=0). The rke-lock mod therefore does
  **NOT** gate on UB; it detects the press via the d7-bit0 rising edge (`docs/rke-lock.md` §7).
- **13-bit code = `d6[7:3] (5 bits) ∥ d7[7:0] (8 bits)`**.
- Within the code, the **button identity is the low bits of d7**:
  - **d7 bit0 (0x01) = LOCK**
  - **d7 bit1 (0x02) = UNLOCK**
  - d7 bit4 (0x10) and d6 bit5 (0x20) toggle = rolling counter (ignore for identity).

## 2. Where the firmware receives it (established)

- `0x100` is RX on **both** HS-CAN (MB34) and MS-CAN (MB53); the capture is MS-CAN.
- MS-CAN 0x100 **RX copier record** @ `0x1520F8`: dest frame-image base **`0x40000918`**, DLC 8,
  copymask `0xFF` (verbatim 8-byte copy), status flag `0x400004FE` (MS-net flag).
  ⇒ **d6 image = `0x4000091E`, d7 image = `0x4000091F`** (LOCK/UNLOCK byte).
- (HS-CAN 0x100 = MB34, separate image; the lock press was seen on MS.)

## 3. Handling path — NOT LOCATED, and provably not findable statically (CLOSED)

- The Volcano routing records for the `0x100` image only shuffle **d0–d6** among themselves
  (self/adjacent-byte normalisation). **d7 (`0x4000091F`) has ZERO references** anywhere: no
  4-aligned pointer, no raw pointer, no Ghidra code/data xref.
- The MS-net arrival-flag byte `0x400004FE` and the frame-image page likewise have **no code xrefs**
  (only calibration data-table entries).

> **Resolution (owner full-flash analysis, `owner_flash_layers.md` §20.2):** this is not a gap in
> *this* frame's trace — it is the project-wide **unpack-stage** problem. **Zero** application
> functions touch *any* RX frame-image byte by absolute address; the packed images
> (`0x40000600…`) and the app signal planes (`0x40001E00`/`0x40002800`/`0x40003C00`) are disjoint
> memory with an unlocated bridge. Static scanning is proven ineffective here — the page-base
> candidates this note once listed (`0x018CB3`, `0x04EC25`, `0x07D32B`) led nowhere, and
> `0x018Cxx` is descriptor data, not code.
>
> **This never needed solving.** The shipped `rke-lock` mod injects at the TX mailbox and reads the
> inputs straight from the RX image, so the consumer's identity is irrelevant. Finding the ignition
> gate in code was the original plan; it was abandoned for the mailbox-injection approach and the
> result is on-vehicle proven. Re-opening this requires bench instrumentation, not more scanning
> (README §8 item 1).

Scripts: `work/rke_field.py` (bit decode), `work/rke_rxdesc.py` (reception descriptor),
`work/rke_coderefs.py` (xref scan), `work/rke_pagescan.py` (page-base scan — negative result).
