# Key-outside gate for RKE lock — MS-CAN `0x100` d1 bit7

> ⚠ HISTORICAL design/debug notes (v1→v2 era). Authoritative shipped design is **`docs/rke-lock.md`**
> (current: v6). Note the pseudocode below still shows the `d6 bit2` UB check in the fire condition —
> that gate was later **DROPPED** (RFA asserts UB only after rolling-code validation, lagging the
> first few presses; see `docs/rke-lock.md` §7). Detection now uses the d7-bit0 rising edge only.

Firmware: Ford BCM C1MCA (JV6T-14C094-AD).
Capture: `mscan_ign_on_key_out.log` — ignition ON; door open/close ×3:
(1) key inside, (2) key outside → IPC "key not in vehicle" warning, (3) key inside → warning cleared.
Door cycles read from `0x80` d4 (0x3F closed ↔ 0x3D open): open2.95/close4.33, open7.75/close9.85, open13.75/close15.61.
(Everything here is derived purely by decoding the referenced candump captures — bit positions and
values observed on the wire, correlated with the physical key-in/key-out action.)

## Empirical result: `0x100` d1 bit7 (0x80) = "key localized OUTSIDE (via door-cycle scan)"

| phase | window (rel s) | 0x100 d1 | bit7 |
|---|---|---|---|
| key INSIDE  | 0 – 7.5   | 0x17 | 0 |
| key OUTSIDE | 10.3 – 15.9 | 0x97 | **1** |
| key INSIDE  | 15.94+    | 0x17 | 0 |

- Only bit7 changes; flips ON right after the key-out door cycle, OFF after the key-in door cycle.
- `0x400` d5 also flipped but `0x400` is a rolling multiplexed counter frame (payload random) → noise.
- Nuance: bit7 reflects the **last door-triggered key localization**. In pure RKE-from-distance logs
  (`mscan_full_inition_on_rke_close`, `mscan_rke_close`) the key was outside but bit7=0 because no
  door cycle ran. For the intended use case (driving, exit vehicle → door cycle → RKE lock) this is
  the correct gate.
- The physical bit `0x40000919` bit7 is unambiguous and proven from the captures (it sits within the
  frame's passive-entry status area, but we rely only on the observed bit, not any named signal).

## Consolidated gate + inject plan (single `0x100`-fed cave)

Both inputs are in the `0x100` RX frame image the BCM already receives:
- RKE LOCK button: d7 image `0x4000091F` bit0 (valid via d6 `0x4000091E` bit2).
- Key-outside:    d1 image `0x40000919` bit7.

Injection target: MS-CAN `0x3A` TX mailbox (MB1, CS `0xFFFC4090`), force the lock-command d3 = 0x01
(+ its valid flag d1 bit1 = 1) when **RKE-lock latched AND key-outside(d1 bit7)** — edge-latched like acc-fix.

## BUILD REQUIREMENT (user): ONE firmware with BOTH acc-fix AND this RKE-lock mod
- Layer this mod on top of the acc-fix APP image, NOT OEM. Acc-fix already:
  hooks CAN0 TX packers FUN_000fc218@0xFC2C2 + FUN_000fc2f6@0xFC440; caves @0x117100/0x117300;
  scratch latch L@0x40011000 (gated on CAN0 MB0 CS=0xFFFC0080 for id 0x030).
- This mod: needs its OWN cave(s) in different in-block 0xFF padding, and its OWN scratch latch byte
  (must NOT reuse 0x40011000). Gate is CAN1 MB1 (CS 0xFFFC4090, id 0x3A) — different mailbox, so it
  coexists with acc-fix's CAN0 MB0 gate even though FUN_000fc2f6 is shared (walker sees both buses).
- Repair all 3 integrity layers (sum8 @0x13FFFE → per-block CRC16 → file CRC32) ONCE over the final
  combined image. Deliver app block byte-exact.

DECISION (user-confirmed): gate = `0x100` d1 bit7 (door-cycle localized key-outside). Matches the
drive→exit→lock use case and is on the same RX frame as the RKE button (one clean cave read).
Rejected the `0x10` passive-key scan-area frame (event-only, non-periodic → not reliably cave-readable).

## FINAL DESIGN v3 (ONE-SHOT STROBE) — v2 latch caused rapid clicking on-vehicle
Flashed v2 (latched) test `mmcan_ignon_keyout_rke_close2.log`: doors **rapidly clicked**. Root cause
found via the BCM's OWN native lock capture `mmcan_ignon_lock_interior_button.log` (interior key,
wired direct to BCM, ignition on — NO RKE involved):
```
t+3.05  82 C3 00 01 ...   d1 bit6=1, d3=01   <- exactly ONE frame with bit6 set
t+3.10  82 83 00 01 ...   d1 bit6=0, d3=01   <- bit6 cleared, d3=01 held steady
t+3.15+ 82 83 00 01 ...   (steady, no more bit6 pulses)   -> quietly locked
```
⇒ **d1 bit6 (0x40) is a ONE-SHOT "execute" STROBE, not a level.** The latch (v2) set bit6 EVERY
frame for ~2 s = ~40 execute strobes = rapid clicking. Native BCM strobes bit6 for exactly ONE frame.
Also v2 wrote d3=01 stickily into the mailbox; the event-driven walker never restored it, so d3 stayed
01 across later unlock presses (door stuck locked until interior key changed the lock-command byte).

⇒ v3: fire the strobe **once on the RKE-lock rising edge**, then leave every subsequent frame
UNTOUCHED (BCM's own bytes pass through, exactly like native). Re-arm only when the RKE-lock button
is RELEASED (0x100 d7 bit0 clears). Scratch `L2 @0x40011001`: 0=armed, 1=already-fired-this-press.

Cave logic (walker packs CAN1 MB1, CS=0xFFFC4090):
```
d7=[0x4000091F]; d6=[0x4000091E]; d1=[0x40000919]; ign=[0xFFFC42C8]; L2=[0x40011001]
if !(d7 & 0x01):   L2 = 0; return              # lock button released -> re-arm, untouched
if L2:             return                      # already fired this press -> untouched
if (d6 & 0x04) and (d1 & 0x80) and ((ign & 0xF0)==0x40):   # UB valid + key-out + ign Run
    mbreg[0xB] = 0x01                          # d3 = lock-command LOCK
    mbreg[0x9] = mbreg[0x9] | 0x42             # d1 |= bit6(execute strobe) + bit1(UB)
    L2 = 1                                     # fired; subsequent frames untouched
# else armed, conditions not yet met -> wait (untouched)
```
Result on wire = ONE `82 C3 00 01 ...` strobe then BCM's native stream — byte-for-byte the same
shape as the interior-button native lock. Unlock and everything else pass through untouched.
Register note: r0 is invalid as a load/store BASE reg on PPC → ignition address kept in r4.

## ON-VEHICLE BISECT (can1, ignition on) — d1 bit6 is REQUIRED
Single-frame `cansend` tests on the live bus (doors physically observed):
| frame sent | result |
|---|---|
| `82 83 00 01 80 00 00 00` (cave v2 output = BCM's own native-lock bytes) | **no lock** |
| `82 C3 00 01 00 00 00 00` (user's known-good) | **locks** |
| `82 C3 00 01 80 00 00 00` (d1=C3, d4=80) | **locks** ⇒ d4 irrelevant |
| `82 C3 00 02 00 00 00 00` / `82 C3 00 02 ...` | **unlocks** |

⇒ The ONLY byte that matters beyond d3(lock-command) is **d1 bit6 (0x40)** — a per-frame execute
strobe (established purely from the captures). The live BCM streams d1=`0x83` (bit6 CLEAR) with
ignition on, so a cave that only
rewrites d3 leaves the door refusing the command. Fix: cave also sets d1 bit6 → OR 0x42 into
mbreg[0x9] (bit6 + UB bit1). Emulated cave output `82 C3 00 01 ...` confirmed to LOCK on the car.
Note (superseded understanding): early on bit6 was thought to be a "speed-quality OK" level; the
later interior-button capture proved it is a one-shot EXECUTE strobe (see §"FINAL DESIGN" above and
`docs/rke-lock.md` §3). Either way, the cave asserts it as part of the lock action.
Also learned: a single 30 ms `cansend` alternates with the BCM's own 0x3A stream (lock/unlock
chatter = the "fast clicking"); the in-firmware cave has no such issue — it rewrites the BCM's own
mailbox before transmit, so exactly one steady frame goes on the wire.

Ignition read (user tip — cleaner than the `0x80` field): the `0x3A0` ignition-status frame = MS TX
**MB36**, CS `0xFFFC42C0`, raw d0 = **`0xFFFC42C8`**. Ignition status is in d0's **high nibble**
(observed): **0x1_=Off, 0x4_=Run**. Verified across all captures: ign-ON logs → d0=0x41, ign-OFF lock
log → d0=0x11, and the off→on→off→on log flips 0x11↔0x41 exactly at the `0x80`-frame ignition
transitions. Ignition-ON test = **`(d0 & 0xF0) == 0x40`**.
Reading this raw TX mailbox byte is SAFE (CPU-written, MB36 idle while we pack MB1 — no BUSY/tear).

Cave logic (runs when the walker `FUN_000fc2f6` packs CAN1 MB1, CS=0xFFFC4090):
```
d7 = [0x4000091F]; d6 = [0x4000091E]; d1 = [0x40000919]; ign = [0xFFFC42C8]
if (d7 & 0x01)          # RKE LOCK button held
   and (d6 & 0x04)      # message valid (_UB)
   and (d1 & 0x80)      # key localized outside
   and ((ign & 0xF0)==0x40):  # ignition = Run (0x3A0 d0 hi-nibble)
        mbreg[0xB] = 0x01                # lock-command (d3) = LOCK
        mbreg[0x9] = mbreg[0x9] | 0x02   # lock-command valid flag (d1 bit1) = 1
# else: leave mailbox untouched (BCM's own value stands) -> unlock & normal ops unaffected
```
Integration: extend acc-fix walker cave (`0x117300`) — after its `mbreg==0xFFFC0080` (MB0/0x030)
branch, add `cmplw mbreg,0xFFFC4090` → this RKE block → DONE. Single-frame packer cave (`0x117100`)
does NOT need it (0x3A is 30 ms periodic → walker only). No new hook, no new scratch RAM.
One combined VBF; repair sum8→CRC16→CRC32 once.

## BUILD RESULT (verified)
Artifact: `work/rke-lock/JV6T-14C094-AD_accfix-rkelock.VBF`
sha256 `ab338afe09818b91a6191940224e30157300c9ac00b498e92c907e0ed5cc6e20`.
Build/verify scripts: `work/rke-lock/build_caves.py` → `build_vbf.py` → `verify.py`.
- Caves grew 278→386 B each (acc-fix body + RKE block), still in-block 0xFF padding
  (cave1 0x117100..0x117282, cave2 0x117300..0x117482), sum8-covered.
- verify.py: block CRC16 OK, file CRC32=0x1D3777EF OK, internal sum8 0x7572→0x2C34 OK,
  both caves byte-exact, diff-vs-OEM = exactly {hook 0xFC2C2+4, hook 0xFC440+4, cave 0x117100,
  cave 0x117300, sum8 0x13FFFE+2}, RKE gate sim correct across 6 states.
- acc-fix logic preserved: instruction-identical to shipped acc-fix; only branch-displacement
  bytes changed (MB0-gate e_bne now targets the RKE block; SKIPLIM e_b targets the shared tail).
- ⚠ NOT yet flashed/on-vehicle. Worst realistic failure = no-op (gate never fires), not a brick
  (all 3 integrity layers repaired). Confirm on car: ign ON + key outside + RKE lock → doors lock;
  and unlock / normal lock-unlock unaffected.
