# Key-outside gate for RKE lock — MS-CAN `0x100` d1 bit7

> **Scope:** this is the **evidence note** for the key-outside input and the record of the
> discarded design iterations. The **shipped design, cave logic, addresses and build results live in
> `docs/rke-lock.md`** (current: v6) — treat that document as authoritative; nothing here is a
> current build description.

Firmware: Ford BCM C1MCA (`JV6T-14C094-AD`). Everything below is derived by decoding candump
captures — bit positions and values observed on the wire, correlated with the physical action.

---

## 1. The gate input: `0x100` d1 bit7 = "key localized OUTSIDE"

Capture `mscan_ign_on_key_out.log` — ignition ON; door open/close ×3: (1) key inside, (2) key
outside → IPC "key not in vehicle" warning, (3) key inside → warning cleared. Door cycles read from
`0x80` d4 (`0x3F` closed ↔ `0x3D` open): open 2.95 / close 4.33, open 7.75 / close 9.85,
open 13.75 / close 15.61.

| phase | window (rel s) | `0x100` d1 | bit7 |
|---|---|---|---|
| key INSIDE | 0 – 7.5 | `0x17` | 0 |
| key OUTSIDE | 10.3 – 15.9 | `0x97` | **1** |
| key INSIDE | 15.94+ | `0x17` | 0 |

- Only bit7 changes; it flips ON right after the key-out door cycle and OFF after the key-in cycle.
- `0x400` d5 also flipped, but `0x400` is a rolling multiplexed counter frame (payload effectively
  random) → noise, not a signal.
- **Nuance:** bit7 reflects the **last door-triggered key localization**. In pure RKE-from-distance
  logs (`mscan_full_inition_on_rke_close`, `mscan_rke_close`) the key was outside but bit7 = 0
  because no door cycle had run. For the intended use case (drive → exit → door cycle → RKE lock)
  this is exactly the right gate.
- Read address: `0x100` d1 RX image `0x40000919`, bit7. On the same frame as the RKE lock button
  (d7 `0x4000091F` bit0) — one clean cave read for both inputs.

**Rejected alternative:** the `0x10` passive-key scan-area frame — event-only, non-periodic, so it
is not reliably readable from a TX-time cave.

---

## 2. The ignition input: `0x3A0` d0 high nibble

Cleaner than the `0x80` power-mode field (`ign_powermode_0x80.md`). `0x3A0` is MS TX **MB36**,
CS `0xFFFC42C0`, raw d0 = **`0xFFFC42C8`**. Observed: `0x1_` = Off, `0x4_` = Run. Verified across all
captures — ign-ON logs give d0 = `0x41`, the ign-OFF lock log gives `0x11`, and the off→on→off→on log
flips `0x11`↔`0x41` exactly at the `0x80`-frame ignition transitions.

Test = **`(d0 & 0xF0) == 0x40`**. Reading this **raw TX mailbox** byte is safe: it is CPU-written and
MB36 is idle while the walker packs MB1, so there is no BUSY/tear hazard (unlike an RX mailbox).

---

## 3. On-vehicle bisect — `d1 bit6` is REQUIRED

Single-frame `cansend` tests on the live bus, ignition on, doors physically observed:

| frame sent | result |
|---|---|
| `82 83 00 01 80 00 00 00` (BCM's own native-lock bytes, bit6 clear) | **no lock** |
| `82 C3 00 01 00 00 00 00` | **locks** |
| `82 C3 00 01 80 00 00 00` | **locks** ⇒ d4 irrelevant |
| `82 C3 00 02 …` | **unlocks** |

⇒ beyond d3 (the lock command), the only byte that matters is **d1 bit6 (`0x40`)**. With ignition on
the live BCM streams d1 = `0x83` (bit6 clear), so a cave that rewrites only d3 leaves the door
refusing the command. The cave therefore ORs `0x42` into d1 (bit6 execute + bit1 UB).

Also learned: a single `cansend` **alternates** with the BCM's own `0x3A` stream (lock/unlock
chatter — the "fast clicking" seen on the bench). The in-firmware cave has no such issue: it rewrites
the BCM's own mailbox *before* transmit, so exactly one frame reaches the wire.

> **Superseded understanding:** early on, `d1 bit6` was read as a "speed-quality OK" *level*. The
> interior-button capture (`mmcan_ignon_lock_interior_button.log`) later proved it is a **one-shot
> execute strobe** — see §4 and `rke-lock.md` §3.

---

## 4. The strobe discovery — why the level design failed

Ground truth: the BCM's **own** native lock, captured with the interior key (wired direct to the BCM,
ignition on, no RKE involved):

```
t+3.05  82 C3 00 01 …   d1 bit6=1, d3=01   <- exactly ONE frame with bit6 set
t+3.10  82 83 00 01 …   d1 bit6=0, d3=01   <- bit6 cleared, d3=01 held steady
t+3.15+ 82 83 00 01 …   (steady, no more bit6 pulses)  -> quietly locked
```

⇒ **`d1 bit6` is a one-shot "execute" strobe, not a level.** The latched design asserted it on every
frame for ~2 s ≈ 40 execute strobes = rapid door clicking.

**The transferable lesson (this is the one worth remembering):** before injecting a command frame,
**capture the ECU performing that action natively** and match its exact frame *shape over time*. A
static bisect tells you which bits are required; only the native capture tells you whether a bit is
a level or a strobe.

---

## 5. Discarded design iterations

Full table with on-vehicle evidence and log names: **`rke-lock.md` §7** (v1 stateless → v2 latch →
v3 one-shot → v4 shared-byte window → v5 UB-gated → **v6 shipped**). Two points worth restating
because they cost the most time:

- **v3 double-click:** the BCM emits its *own* follow-up lock execute-strobe ~0.45 s after ours
  (it learns of the external lock via DDM). The shipped design suppresses that window.
- **v5 ignored the first few presses:** the `_UB` valid bit (`0x100` d6 bit2) is asserted only after
  the RFA validates the rolling code, which can lag 3+ presses. **The UB gate was dropped** — our own
  rising-edge latch already gives reliable per-press detection.

Any pseudocode you may remember from earlier revisions of this note (including a `d6 & 0x04` UB term
in the fire condition) is **obsolete**. The shipped cave logic is in `rke-lock.md` §4.
