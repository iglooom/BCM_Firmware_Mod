# RKE-LOCK — lock car from remote key with ignition ON (BCM injection on TX MS-CAN `0x3A`)

**Status:** ✅ on-vehicle proven (v6: press-latch + independent re-strobe suppression, no UB gate). **Artifact:**
`work/rke-lock/JV6T-14C094-AD_accfix-rkelock.VBF` (APP/EXE VBF only — this is the **combined**
image carrying BOTH `acc-fix` and `rke-lock`). **Base OEM:** `JV6T-14C094-AD.VBF`.
**Patched sha256:** `ca4ccb170ec1dd6352e9ed7b0764bc4de5382310f42b3296b445db6b24892343`.

Version-agnostic porting method: **`../AGENTS.md`**. Evidence notes: `docs/rke_0x100_lock.md`
(RKE button decode), `docs/ign_powermode_0x80.md` (ignition), `docs/clockcmd_0x3a.md`
(lock command), `docs/key_outside_gate.md` (key-outside gate + full design history).

---

## 1. Problem

Stock BCM **refuses an RKE (remote key) lock command while the ignition is ON** — pressing lock on
the fob does nothing when the engine/ignition is running. Goal: allow it, but **only when the
passive key is outside the cabin** (never lock the key inside a running car).

**Proven root cause (BCM-side gate):** capture `mscan_full_inition_on_rke_close.log` (ignition ON):
the fob DOES transmit the lock code on MS-CAN `0x100` d7 bit0, but the BCM never emits the central-
lock command (`0x3A` d3=0x01) on the bus. The suppression is inside BCM firmware → fixable by us. The
BCM's CAN signal layer is 100% table-driven (0/2048 signal-RAM cells have any code xref), so the
gate can't be found/edited as a `cmp` in code — we fix it by **injecting at the TX mailbox**, the
same choke point the shipped `acc-fix` uses.

---

## 2. Signals (all derived by decoding real candump captures)

| Role | Frame / location | Bit | Notes |
|---|---|---|---|
| RKE **LOCK** button | MS-CAN `0x100` (RFA/keyless), RX image d7 = **`0x4000091F`** | bit0 (0x01) | unlock = d7 bit1; never both |
| RKE message **valid** (_UB) | `0x100` d6 = **`0x4000091E`** | bit2 (0x04) | ⚠ NOT used as a gate — it asserts only after the fob's rolling code is validated, which can lag several presses (see §7). Detection uses the d7-bit0 rising edge instead |
| **Key outside** | `0x100` d1 = **`0x40000919`** | bit7 (0x80) | set after door-cycle key localization; 0 when key inside |
| **Ignition = Run** | ignition-status frame `0x3A0` TX MB36, raw d0 = **`0xFFFC42C8`** | hi-nibble == 4 | 0x1_=Off, 0x4_=Run (observed) |
| **Central-lock command** (target) | `0x3A` (BCM→door modules) TX **CAN1 MB1**, CS **`0xFFFC4090`** | d3=lock-command, d1=flags | door obeys this |

`0x100` RX image is a verbatim byte copy (copier record @`0x1520F8`, base `0x40000918`, mask 0xFF).
`0x3A` mailbox data bytes: d0=CS+8=`0xFFFC4098`, d1=CS+9=`0xFFFC4099`, d3=CS+0xB=`0xFFFC409B`.

---

## 3. The lock command — how the BCM natively does it (ground truth)

From `mmcan_ignon_lock_interior_button.log` (interior lock button, **wired direct to BCM**, ignition
ON, NO RKE) — the BCM's own native lock-with-ignition-on sequence on `0x3A`:

```
82 C3 00 01 80 00 00 00   <- exactly ONE frame: d1 bit6=1 (execute strobe), d3=01
82 83 00 01 80 00 00 00   <- d1 bit6=0, d3=01 held steady (no further pulses)  -> quietly locked
```

**Key facts:**
- **`d3` (lock-command byte)** = the steady lock LEVEL: **01 = LOCK, 02 = UNLOCK** (idle streams 02).
- **`d1` bit6 (0x40)** = a **one-shot "execute" STROBE**, asserted for exactly ONE frame to actuate
  (the door module treats the rising pulse as "do it now" — established purely from the captures below).
- On-vehicle bisect (single `cansend` frames, doors observed): `82 83 00 01…` (bit6=0) → **no lock**;
  `82 C3 00 01…` (bit6=1) → **locks**; the other differing byte (d4) is irrelevant to locking.

So a valid lock = **one** frame with `d3=01 AND d1 bit6=1`. Repeating the strobe every frame makes the
actuator re-fire → rapid clicking (the v2 failure, below).

> **Firmware confirmation (added later).** The one-shot behaviour above was established *purely from
> captures*. It is now confirmed in the firmware itself: the Volcano TX packer
> (`VOL_tx_pack_single` @ `0x0FC218`, see `docs/owner_flash_layers.md` §14.2) ends every transmit with
>
> ```c
> for each present byte:  *img &= desc[k];      // post-TX AND-mask
> ```
>
> i.e. the packer **clears command bits in the frame image immediately after transmitting them**. That
> is the hardware-level reason a strobe bit is naturally one-shot, and why a cave that forces a mailbox
> byte produces a *sticky* value: the cave writes downstream of this loop, so nothing ever clears it.
> The capture-derived design in §4 was correct; this is the mechanism behind it.
>
> **The frame's RAM addresses are now known too** (`owner_flash_layers.md` §19.3). The MS-CAN TX
> record for `0x3A` gives MB1, **CS `0xFFFC4090`** — matching the cave's hook — and frame image base
> **`0x40000A0F`** with `present = 0xFF`, so all eight bytes are contiguous:
>
> | byte | address | role |
> |---|---|---|
> | d1 | `0x40000A10` | execute strobe, bit6 |
> | d3 | `0x40000A12` | `0x01` = LOCK, `0x02` = UNLOCK |
>
> The frame image is one stage **earlier** than the mailbox and holds the same two bytes adjacently,
> so it is a candidate hook site if this mod is ever reworked. Nothing here changes the shipped v6.

---

## 4. Cave logic — fire-once press latch + independent re-strobe suppression (v5)

Injected only when the walker packs **CAN1 MB1** (`0x3A`, CS `0xFFFC4090`). **Two** separate scratch
bytes in the proven-unused zero-ref band (`docs/scratch_ram.md`), adjacent to acc-fix's `0x40011000`:
- **`L2 @0x40011001`** = **press latch**: `0`=armed, `1`=already fired this press. Re-armed **only on
  button release** (`0x100` d7 bit0 clears) — guarantees exactly one strobe per physical press.
- **`L3 @0x40011002`** = **suppress countdown** (frames): `>0` clears `d1 bit6` on outgoing **lock**
  (`d3==01`) frames and decrements **every** `0x3A` frame (time-based, never reset), so it always
  expires on its own.

**Why two bytes (the click-count history):**
- **The double-click (v3→v4):** when *we* inject the lock with ignition on, the BCM later learns the
  doors are locked (it didn't command it) and emits **its own** lock execute-strobe ~0.45 s later →
  a 2nd actuation. Proven: `mmcan_ignon_lock_by_turn_key.log` (physical key turn — also external,
  BCM learns via DDM) emits **exactly ONE** clean strobe, whereas RKE showed two. Fix = suppress the
  BCM's follow-up strobe for a window after ours.
- **The 5-clicks (v4→v5):** v4 stuffed both jobs into one byte and closed the window whenever the
  outgoing frame was `d3!=01`. But the BCM streams its **native `d3=02`** for ~0.5 s *before* it
  accepts the lock (`mmcan_ignoon_keyout_rke_lock4.log`: our strobes at t+7.949, 8.051, 8.149, 8.250,
  8.450, BCM only switches to `d3=01` at t+8.5). Each `02` frame closed the window → re-armed the
  latch → **re-fired** ≈ once per 2 frames = ~5 clicks. v5 fixes it by keeping the latch and the
  countdown **independent**: the latch is re-armed only by button *release*, and the countdown is
  purely time-based (never keyed on `d3`).

```c
d7=[0x4000091F]; d6=[0x4000091E]; d1=[0x40000919]; ign=[0xFFFC42C8];
L2=[0x40011001];  L3=[0x40011002];
if (!(d7 & 0x01)) {                 // button released -> re-arm latch (then fall to suppression)
    L2 = 0;
} else if (L2 == 0 && (d1 & 0x80) && ((ign & 0xF0)==0x40)) {  // NOTE: UB (d6 bit2) intentionally NOT gated — see §7
    mbreg[0xB] = 0x01;             // d3 = lock-command LOCK
    mbreg[0x9] |= 0x42;           // d1 |= bit6 (execute strobe) + bit1 (UB)
    L2 = 1;  L3 = 30;             // latch this press; open suppress window (~1.2 s)
    return;                       // protect OUR strobe (skip suppression this frame)
}
if (L3 > 0) {                      // suppression window active
    if (mbreg[0xB] == 0x01) mbreg[0x9] &= ~0x40;  // kill bit6 on outgoing lock frame (BCM re-strobe)
    L3--;                          // time-based expiry (independent of d3)
}
```

Net on the wire: **exactly one** `82 C3 00 01…` strobe (ours) per press, the BCM's follow-up lock
re-strobe is neutralised, and a genuine unlock (`d3!=01`) always passes through — one clean click,
matching the physical-key-turn behavior. `SUPP=30` frames (~1.2 s at the ~40 ms `0x3A` period) covers
the ~0.45 s re-strobe with margin. Both bytes power up 0 at reset (ECC-init), inert until first lock.

<details><summary>superseded designs (kept for history)</summary>

- **v4 (one byte = latch+window):** closed the window on every native `d3=02` frame → re-armed and
  re-fired ~5 times while the button was held (BCM streams `02` before accepting the lock). Fixed in
  v5 by splitting the latch (`L2`) and the time-based countdown (`L3`).
- **v3 (one-shot, re-arm on button release):** fired one strobe per press but left the BCM's own
  follow-up re-strobe to pass → **double click**.
- **v2 (latched, force every frame):** set `d1 bit6` on every frame while latched → ~40 execute
  strobes = continuous rapid clicking. `d1 bit6` is a one-shot strobe, not a level.
- **v1 (stateless):** 0.1–0.6 s bursts lost to the BCM's continuous unlock stream; didn't hold.

</details>

**Register note (VLE/PPC):** `r0` is invalid as a load/store **base** register (reads literal 0), so
the ignition address is kept in `r4`; value scratch in `r0`; `0x100` image base in `r3`. `r4` is
reloaded with `&L2` after the ignition read (it doubles as the ign-address temp). acc-fix
already saves/restores r0/r3/r4 in the shared cave frame.

---

## 5. Implementation = extend the acc-fix caves (no new hook, no new scratch)

`0x3A` is emitted by the **periodic walker** `FUN_000fc2f6`, which is **already hooked by acc-fix**
at `0xFC440` (cave `0x117400` in the combined build). The RKE block is appended to BOTH shared caves after the acc-fix
`MB0` (`0xFFFC0080` = `0x030`) branch, gated on `cmplw mbreg, 0xFFFC4090`:

| Packer | Role | Hook | Cave | Handles |
|---|---|---|---|---|
| `FUN_000fc218` | single-frame TX | `0xFC2C2` | `0x117100` (480 B) | acc-fix `0x030` + RKE `0x3A` |
| `FUN_000fc2f6` | periodic walker | `0xFC440` | `0x117400` (480 B) | acc-fix `0x030` + RKE `0x3A` (this is the active path for `0x3A`) |

The MS-CAN `0x3A` = MB1 mapping is confirmed by the filter list (position 1) and the shared bring-up
loop `FUN_000fceb8` (programs MB[i]=list[i]); CS = CAN1 base `0xFFFC4000` + 0x80 + 1·0x10 =
`0xFFFC4090` (cross-checks acc-fix's CAN0 MB0 = `0xFFFC0080`). Both nets share the same generic codec
functions, parameterized by controller descriptor — the acc-fix walker hook already runs for CAN1.

acc-fix logic is preserved instruction-for-instruction; only branch-displacement bytes shifted (the
MB0-gate `e_bne` now targets the RKE block; the acc-fix tail branch targets the shared restore/replay).

---

## 6. Integrity (README §2.1) — all three layers repaired by the build

`build_vbf.py` repairs, in order, over the combined image: internal `sum8 @0x13FFFE`
(`0x7572 → 0x95F8`), per-block CRC-16, file CRC-32 (`0xC42ED565`). Caves live in the app block's
`0xFF` padding (`0x117100`, `0x117400`) so they are covered by sum8. APP VBF only — no F10A edit.

---

## 7. Design history (each corrected on the car — do not repeat)

| Ver | Design | On-vehicle result | Why it failed |
|---|---|---|---|
| v1 | stateless: force d3=01 every frame while lock held (~0.3 s) | didn't hold locked | 0.1–0.6 s blips lost to the BCM's continuous d3=02 stream between the ~10 ms press windows |
| v2 | latch d3=01 (+d1 bit6) every frame until an RKE-unlock press | **rapid clicking** | d1 bit6 is a one-shot execute strobe, not a level — asserting it every frame = ~40 actuations/2 s. Also d3 written stickily; walker never restored it (door stuck locked across unlocks) |
| v3 | one-shot strobe on the RKE-lock rising edge, then frames untouched | locks but **double-click** | BCM emits its OWN follow-up lock execute-strobe ~0.45 s later (it learns of the external lock via DDM) → 2nd actuation. Proven vs `mmcan_ignon_lock_by_turn_key.log` (physical key = 1 strobe) |
| v4 | one byte does both latch + suppress window (close window when outgoing d3≠01) | **~5 clicks** | BCM streams native d3=02 for ~0.5 s *before* accepting the lock; each 02 frame closed the window → re-armed the latch → re-fired ≈1/2 frames. Proven `mmcan_ignoon_keyout_rke_lock4.log` (our strobes 7.949→8.450, BCM switches to d3=01 only at 8.5) |
| v5 | as v6 but with the UB (d6 bit2) input gated | locks single-click, but **ignores first few presses** | RFA asserts UB only after it validates the rolling code — can lag 3+ presses (`mmcan_ignoon_keyout_rke_lock6.log`: presses 1–3 had lock+keyout+ign all set, UB=0 → ignored; press 4 UB=1 → locked) |
| **v6** | **v5 minus the UB gate** — fire on d7-bit0 rising edge + key-outside + ign-Run | ✅ **works** | our own rising-edge latch already gives reliable per-press detection; UB added no CAN-layer security (lock-only, key-outside, ign-on). Every press now locks, single click |

Also learned: a single 30 ms `cansend` of a lock frame **alternates** with the BCM's own `0x3A`
stream on the bus (lock/unlock chatter). The in-firmware cave has no such issue — it rewrites the
BCM's own mailbox *before* transmit, so exactly one frame goes on the wire.

---

## 8. Reproduce / rebuild

```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate
python3 work/rke-lock/build_caves.py   # assemble both caves (acc-fix + RKE), Ghidra VLE, round-trip -> patch_blobs.json
python3 work/rke-lock/build_vbf.py     # patch APP VBF (expected-byte guards) + repair all 3 integrity layers
python3 work/rke-lock/verify.py        # re-parse CRCs, sum8, cave byte-exactness, diff-vs-OEM, one-shot behavior sim
```

`verify.py` (all pass): block CRC-16, file CRC-32, internal sum8, both caves byte-exact, diff-vs-OEM
= exactly {hook `0xFC2C2`+4, hook `0xFC440`+4, cave `0x117100`, cave `0x117400`, sum8 `0x13FFFE`+2},
one-shot sim (exactly 1 strobe per press; 0 when ign off or key inside).

## 9. On-vehicle behavior (confirmed)

| Action | Condition | Result |
|---|---|---|
| RKE **lock** | ignition Run + key outside | doors lock (one clean actuation, no clicking) |
| RKE **lock** | ignition off | normal stock behavior (cave inert; ign gate fails) |
| RKE **lock** | key inside cabin (`0x100` d1 bit7=0) | ignored (safety) |
| RKE **unlock**, interior/mechanical lock, all else | any | unchanged (frames pass through untouched) |
| acc-fix cruise remap on `0x030` | any | unchanged (separate mailbox, logic byte-identical) |
