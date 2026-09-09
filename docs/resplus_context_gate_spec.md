# RES+ context-gated remap: Resume-when-paused vs Set+ otherwise

**Feature:** the combo ACC_Res_Plus button (HS-CAN 0x030 d1.6) should emit **CC_Res**
(d5.5, mask 0x20) when the PCM reports cruise/LIM **engaged-but-paused (StandBy)**, and
**CC_Set_Plus** (d5.7, mask 0x80) otherwise — extending the working injection hook.

## Paused source (user decision)
- Read the PCM's **0x0C0 byte d0** (received by the BCM on HS-CAN).
  - `bit3 (0x08) = Cruise_StandBy` (1 = paused)
  - `bits4..6 (0x70) = Cruise_Mode` (1=ACC, 3=LIM, 4=transition, 0=off)
- **Gate = StandBy(bit3) == 1 only** (user chose the simple rule; any StandBy → Resume,
  regardless of mode). Off/no-setpoint naturally has StandBy=0 → falls through to Set+.
- **Read from the decoded RAM frame-image byte** (plain RAM, ISR/task-updated) — preferred
  for safety over a raw FlexCAN MB read — **provided it preserves the raw d0 bit layout**
  (Volcano must not have unpacked/repacked d0). Address + layout confirmation pending the
  `docs/0c0_standby_read.md` trace (subagent deleg_e2dcb4b0).

## Cave logic (extends the RES+ block in caves @0x117100 / walker copy)
```c
if (d1 & 0x40) {                 // ACC_Res_Plus pressed
    c0 = *<0x0C0 d0 address>;
    if (c0 & 0x08)  d5 |= 0x20;  // StandBy -> CC_Res (d5.5)
    else            d5 |= 0x80;  // else     -> CC_Set_Plus (d5.7)
    d1 &= ~0x40;                 // clear old ACC_Res_Plus
}
// LIM block unchanged: if (d1 & 0x20) { d6 = (d6&~0x60)|0x40; d1 &= ~0x20; }
```
Extra VLE needed vs current cave: load the 0x0C0 d0 byte (e_lis/e_add16i address +
e_lbz), `e_andi. rX,rX,0x08`, and a branch selecting the 0x20 vs 0x80 OR. Both caves
(single packer + walker) get the same extension; there is ample room in the 0xFF padding.

## Test on-vehicle
- Cruise/LIM active, then paused (PCM 0x0C0 d0 bit3=1): press RES+ → expect **d5.5 set**
  (CC_Res); PCM should resume.
- Cruise not paused / off: press RES+ → expect **d5.7 set** (CC_Set_Plus), as today.
- LIM press behavior unchanged (d6[5:6]=0b10 pressed).
