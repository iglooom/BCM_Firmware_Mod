# Ignition / power-state on MS-CAN `0x80` (BCM-sourced) — evidence note

> ✅ Part of the shipped **rke-lock** mod. Authoritative writeup: **`docs/rke-lock.md`** (README §5.5).
> The shipped ignition gate uses the **`0x3A0` ignition-status frame** (raw d0 `0xFFFC42C8`,
> hi-nibble==4=Run), cleaner than the `0x80` field; `0x80` below is the earlier evidence and cross-check.

Firmware: Ford BCM C1MCA (JV6T-14C094-AD). Capture: `mscan_ign_off_on.log` (off→on→off→on).
(Everything below is derived purely by decoding the referenced candump capture — byte positions and
values observed on the wire, correlated with the physical ignition action.)

## Ignition/power state is on `0x80` (BCM-composed, 60 ms periodic)

Payload `d0..d7`. The power/ignition-state field is in **d2** (low 5 bits); **d5 mirrors it**.
Secondary bits: d1 bit7, d4 bit4. The 5-bit codes observed on the bus, mapped to physical state by
correlating with what the ignition was doing at each timestamp:
0/1 = key out, 2 = off/accessory-approved (rest with key present), 3 = post-accessory,
**6 = ignition on**, 7 = running (higher codes = crank), etc. Only the two we rely on matter here.

Observed transitions (rel time) — matches physical off→on→off→on:
| t (s) | d2 | state |
|---|---|---|
| 0.00 | 0x02 | OFF (key present, not on) |
| 2.58 | 0x06 | IGNITION ON |
| 6.60 | 0x03 | post-accessory |
| 9.60 | 0x02 | OFF |
| 10.08| 0x06 | IGNITION ON |
| 14.40| 0x03 | post-accessory |

⇒ Ignition-ON discriminator = **(d2 & 0x1F) == 6**.

## ⚠ Architectural finding (critical for the patch strategy)

The BCM CAN signal layer is **100% table-driven** (a generated network-database table embedded in the
firmware image). Verified in Ghidra:
- **0 of 2048** signal-band RAM cells (`0x40000600..0x40000E00`) has ANY code xref.
- The `0x100` RKE frame image (`0x40000918..1F`) and the `0x80` power/ignition cluster
  (~`0x400008FF..0x40000960`) are referenced **only** by the F10A routing/descriptor tables, never by
  application instructions.
- No instruction in the 129,723-instruction code region resolves an address in the signal band.

⇒ Application logic (door-lock state machine, power-state supervisor) does **not** read these cells
via a static `e_lis`+displacement. It goes through a **generated signal accessor** that computes the
RAM address from a signal handle at runtime (table index). So the "lock blocked while ignition on"
gate is NOT a simple `lbz <cell>; cmpwi 6` we can grep for.

## Consequences for the goal (RKE lock with ignition on)

Two viable strategies (neither is a trivial byte-flip):
1. **Signal-accessor route:** find the generated getter (takes signal handle → loads value), identify
   the door-lock consumer that calls it for the ignition-state input AND the RKE-lock input, and patch
   the comparison. Requires decompiling the lock task; the handle→cell mapping is in the 24-byte
   signal-descriptor table (`0x15A920+`) / routing tables.
2. **Injection route (like acc-fix):** hook the TX path and force the lock command regardless of
   ignition state. More surgical; proven method pattern already exists in this repo (acc-fix
   TX-mailbox hook). ← this is what shipped.

Recommended next (historical): locate the door-lock state machine by its OUTPUT (lock/unlock relay
driver or the central-lock-status byte it produces), then walk back to the ignition test. The status
frame `0x80` also carries a central-lock-status field (d3) + last-command-origin (d5) — the producer
of those bytes IS the lock state machine.

Scripts: `rke_txwalk.py`, `rke_cellrefs.py`, `rke_bandrefs.py` (proved table-only), `rke_pmcell.py`.
