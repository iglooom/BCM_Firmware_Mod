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

## 3. Handling path — OPEN (needs decompilation)

- The Volcano routing records for the `0x100` image only shuffle **d0–d6** among themselves
  (self/adjacent-byte normalization). **d7 (`0x4000091F`) has ZERO references** anywhere:
  no 4-aligned pointer, no raw pointer, no Ghidra code/data xref.
- The MS-net status flag `0x400004FE` and the frame-image page likewise have **no CODE xrefs**
  (only F10A data-table entries).
- ⇒ The lock/unlock byte is read by **application door-lock logic via computed (base+offset)
  addressing** that Ghidra's ref DB does not resolve (the classic MPC/VLE `e_lis`+displacement case).
- Next: decompile the RKE-message consumer. Leads: RX copier `FUN_000fc63e`; find the function that
  holds `0x40000918`/`0x40000900`-page base in a register and loads `+6/+7`; then find the
  **ignition gate** (lock-with-ignition-on is blocked by default) — a test of an ignition/run signal
  guarding the RKE-lock action. Goal: neutralize that gate so RKE LOCK works with ignition ON.

Page-base scan (`work/rke_pagescan.py`) — `0x4000` high-half with a `0x09xx` low-half nearby in code:
`0x018CB3`, `0x04EC25`, `0x07D32B` (candidates to inspect; 0x018Cxx is in the reception-descriptor
data region, likely not code).

Scripts: `work/rke_field.py` (bit decode), `work/rke_rxdesc.py`, `work/rke_coderefs.py` (xref scan),
`work/rke_pagescan.py` (page-base scan).
