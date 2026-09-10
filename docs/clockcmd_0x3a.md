# Central-lock command on MS-CAN `0x3A` (BCM output) + full RKE→lock chain

> ✅ Part of the shipped **rke-lock** mod. Authoritative writeup: **`docs/rke-lock.md`** (README §5.5).
> This note is the `0x3A` lock-command + RKE→lock chain evidence. NOTE the final mechanism: `d1 bit6`
> is a **one-shot execute strobe** (see `docs/rke-lock.md` §3/§7); the injection fires it once per press.

Firmware: Ford BCM C1MCA (JV6T-14C094-AD).
Captures: `mscan_lock_unlock.log` (RKE lock then unlock, ignition OFF).
(Everything below is derived purely by decoding the referenced candump captures — byte positions and
values observed on the wire, correlated with the physical door action.)

## `0x3A` (BCM-composed) carries the central-lock ACTUATOR command

The door/latch modules obey the **lock-command byte = d3** (8-bit), with a valid/update flag at d1 bit1.
Observed values:
- **d3 = 0x01 → LOCK**
- **d3 = 0x02 → UNLOCK** (also the idle/rest value)
d1 low bits (0x43/0x4F/0x0F) are transient status flags that flicker during the command.

## Proven end-to-end chain (ignition OFF — works normally)

| t (s) | RKE 0x100 d7 | BCM 0x3A d3 (lock-cmd) | 0x80 d2 (power/ignition) |
|---|---|---|---|
| 0.00 | idle | 0x02 (unlock/idle) | off |
| 1.62 | **0x01 LOCK** | → **0x01 LOCK @1.64** (≈20 ms latency) | off |
| 9.60 | **0x02 UNLOCK** | → **0x02 UNLOCK @9.64** | off |

⇒ RKE button (`0x100` d7 bit0/bit1) → BCM lock state machine → `0x3A` d3 lock-command → door modules.
The default-blocked case is: **RKE LOCK while ignition is ON → BCM does NOT emit d3=0x01.**
That suppression is the target.

## Patch-strategy implication

`0x3A` d3 is the BCM's OUTPUT. A TX-mailbox hook (acc-fix pattern) on `0x3A` could rewrite an
outgoing command, but cannot ORIGINATE a lock the state machine chose not to send. The decision
("ignition on ⇒ drop RKE lock") is upstream in the lock state machine, which — like all CAN signals
here — reads its inputs via the table-driven generated accessor (no direct RAM xref; see
`ign_powermode_0x80.md` for the ignition byte).

### GATE LOCATION — RESOLVED: it is a **BCM-side gate** (PROVEN)
Capture `mscan_full_inition_on_rke_close.log` (ignition ON — `0x80` d2 low-5 = 6 = the observed
ignition-on code):
| t (s) | RKE 0x100 d7 | 0x3A d3 (lock-cmd) |
|---|---|---|
| 2.46 | 0xE1 (LOCK, bit0=1) | stays 0x02 (no lock) |
| 4.44 | 0xC1 (LOCK, bit0=1) | stays 0x02 (no lock) |

⇒ The keyfob DOES transmit the LOCK code on `0x100` d7 bit0 with ignition on, but the BCM
**suppresses** d3=0x01. The gate is inside BCM firmware → fixable by us.

### PATCH PLAN (acc-fix-style TX injection on the `0x3A` mailbox)
Behavior to install (edge/latched so it only acts on a genuine RKE press, not continuously):
```
when packing the 0x3A mailbox (MS-CAN MB1, CS = FFFC4000+0x80+1*0x10 = 0xFFFC4090):
    if (RKE 0x100 lock bit latched) AND (ignition == Run):
        force lock-command byte (0x3A d3) = 0x01  and its valid flag (d1 bit1)=1
```
Inputs the cave must read (all are RX frame-image RAM cells, same style as acc-fix 0x0C0 read):
- RKE lock bit: `0x100` d7 = image `0x4000091F`, bit0 (0x01).  (message-valid = d6 `0x4000091E` bit2.)
- Ignition: `0x80` d2 is BCM-composed (TX). Better discriminator ended up being the `0x3A0`
  ignition-status frame (see `key_outside_gate.md`); or gate on RKE-lock alone (locking on RKE is
  always desired; the stock block only bit us when ign on, so forcing it is safe in all modes).
- 0x3A frame-image / lock-command cell: the TX packer writes d3 into the MB at CS+0x8+3.

⚠ Open items before building (all later resolved): (1) confirm the exact MS-CAN 0x3A mailbox index
(=1 from the FlexCAN filter list; verify against the MS bring-up loop like acc-fix Step C did for
CAN0). (2) The MS packer uses `flexcan_tx_packer2` (FUN_000fc2f6) walking CAN1 — confirm the CS base
0xFFFC4090 gate constant. (3) A scratch RAM latch byte (like acc-fix L@0x40011000) for edge behaviour.

Scripts: `rke_3a.py`; full RKE→lock chain correlation in session notes.
