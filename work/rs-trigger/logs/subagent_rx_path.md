# Subagent report — the MS-CAN `0x100` RKE receive path into `FUN_000ADADA`

Project: `ghidra_proj_fullflash` / `BCM_OwnerFlash` / `cflash.bin` (JV6T-14C094-AD), read-only.
Scripts: `work/rs-trigger/345_rx_path_decomp.py`, `346_dirty_semantics.py`,
`347_valid_flag_consumers.py`, `348_stores_and_callers.py`, `349_rx_record_raw.py`,
`350_fallthrough_climb.py`, `351_bfs_to_scheduler.py`. Raw logs: `logs/34[5-9].out`, `logs/35[01].out`.

---

## 0. Headline

**The debug service's write of `0x40003F53 = 0x01` sets a bit that NO consumer reads.**

`APP_rke_code_commit` writes `0x40003F53 = 0xFF` (`se_bmaski r0,0x8`, i.e. all eight bits).
`VOL_test_and_clear_dirty(p, n)` tests mask `0x80 >> n`. A full image sweep finds exactly **two**
consumers of this flag: bit index **1** (mask `0x40`, `APP_rke_command_demux` @ `0x099308`) and bit
index **2** (mask `0x20`, `FUN_000aeec6` @ `0x0AEEDA`). `0x01` is mask-bit index 7 — **unread**.

That is the mechanical answer to "why does holding the command code do nothing": the code cell is a
*level*, but everything downstream is edge-driven off the **dirty flag**, and the debug service
raises the wrong bit of it.

---

## 1. The ordered chain

Two independent branches converge on the consumer in the **same periodic tick**.

### 1a. Commit branch — puts the command code in RAM

| # | address | name | role |
|---|---|---|---|
| 1 | `0x0FC63E` | `VOL_rx_copy_to_image` | FlexCAN MB53 → frame image `0x40000918..0x4000091F`, copymask `0xFF`; ORs `0x80` into arrival flag `0x400004FE` |
| 2 | `0x05878C` | `FUN_0005878C` | RKE poll block; calls the arrival test then the validate/commit pair |
| 3 | `0x0580AE` | `FUN_000580AE` | arrival test-and-clear (`0x0FB0EE` test / `0x0FB0D8` clear) |
| 4 | `0x0585B8` | `FUN_000585B8` | fob-identity gate; calls validate, then commit at `0x058690`/`0x0586C4` |
| 5 | `0x0584A4` | `APP_rke_code_validate` | variant-0 arm: `get16(desc 0x142FD4)`, requires `(code & 0xF) - 2 <= 1` |
| 6 | `0x0FBB38` | `VOL_sig_get16` | `CONCAT11(mask & *d[0], *(d[0]+1))` — reads d6 **and** d7 |
| 7 | **`0x058538`** | **`APP_rke_code_commit`** | **the only writer of `0x40003F53` and `0x40002DA2`** |

### 1b. Dirty-flag branch — turns the commit into the consumer's gate

| # | address | name | role |
|---|---|---|---|
| 8 | `0x062848` | `APP_feature_periodic` | scheduler; calls (9) at `0x0628FC` |
| 9 | `0x0AEEC6` | `FUN_000aeec6` | `0x0AEEDA`: `tcd(0x40003F53, bit 2)` → `0x4000968B` → `0x0AEF14` → **`0x400095E1`** |
| 10 | `0x0AE8DC` | `FUN_000ae8dc` | called from `0x0AEF64` (tail of 9) |
| 11 | `0x0AE922`→`0x0AE958`→`0x0AEA16`→`0x0AEA22`→`0x0AEB14` | sweep-split blocks | jump/fallthrough chain |
| 12 | `0x0AD6C6` | `FUN_000ad6c6` | called at `0x0AEB18` |
| 13 | `0x0AD74A`→`0x0AD754`→`0x0AD7C8`→`0x0AD7D4`→`0x0AD888`→`0x0AD924`→`0x0AD970` | sweep-split blocks | all FALLTHROUGH |
| 14 | **`0x0AD97C`** | `FUN_000ad97c` | reads `0x400095E1`; `0x0ADA3E` **sets `0x40009680 \|= 0x08000000`** (the `(req94>>27)&7==7` term) |
| 15 | **`0x0ADADA`** | **`FUN_000adada`** | reached by FALLTHROUGH from `0x0ADAD8` — the consumer |

Verified by breadth-first backward closure over CALL + JUMP + FALLTHROUGH edges
(`351_bfs_to_scheduler.py`). `FUN_000ADADA` and `FUN_000AD97C` have **0 CALL/JUMP refs** — a
`getCallingFunctions()` climb reports "no callers" and dies (AGENTS rule 19).

**Structural consequence:** (9) writes `0x400095E1` and (14) reads it *within the same call from
`APP_feature_periodic`*, (9) → (10) being a tail call. There is no inter-tick latency; the flag is
produced and consumed in one pass.

---

## 2. Every RAM cell the receive path writes

| # | address | value | literal / computed | written at | already reproduced by debug service? |
|---|---|---|---|---|---|
| R1 | `0x40000918..0x4000091F` | the 8 raw CAN bytes | computed (copy from MB53) | `0x0FC6xx` copy loop | ❌ NOT reproduced |
| R2 | `0x400004FE` | `\|= 0x80` | literal OR-mask (from record `+0x16`) | `0x0FC6xx` / `0x0FC6BE` | ❌ NOT reproduced |
| R3 | **`0x40003F53`** | **`0xFF`** | **literal** (`se_bmaski r0,0x8`) | `0x05856A` | ⚠ **WRONG VALUE** — service writes `0x01` |
| R4 | **`0x40002DA2`** | `0x1808`/`0x1818` (16-bit) | computed (`get16`) | `0x05856E` | ✅ reproduced |
| R5 | `0x4000968B` | `tcd(0x40003F53, bit 2)` → 0/1 | computed | `0x0AEEE6` | ❌ NOT reproduced |
| R6 | **`0x400095E1`** | copy of R5 → **1** | computed | `0x0AEF14` (sole writer in image) | ❌ NOT reproduced |
| R7 | `0x4000967C` (`+0x90`) | field `0x0C000000` := 2 | literal-into-field (`e_rlwimi`, `se_li r0,0x2`) | `0x0ADA38` | ❌ NOT reproduced |
| R8 | **`0x40009680`** (`+0x94`) | `\|= 0x08000000` | literal (`se_bseti r0,0x4`) | `0x0ADA3E` | ❌ NOT reproduced |
| R9 | `0x40009672` (`+0x86`) | `0` while held, else `+= 10` | literal / computed | `0x0ADA5E`, `0x0ADA82` | ❌ NOT reproduced |
| R10 | `0x40009648` (`+0x5C`) | `0` on clear, `+= 10` per tick when armed | literal / computed | `0x0ADA7E`; `0x0ADC…` in consumer | ❌ NOT reproduced |

Reference-manager write counts (script `348`, and note the sole-writer facts):

```
0x40003F53 :  1 writer  (0x05856A)              0 absolute readers  <- read only via pointer
0x40002DA2 :  1 writer  (0x05856E)             16 readers
0x400095E1 :  1 writer  (0x0AEF14)             11 readers
0x4000968B :  1 writer  (0x0AEEE6)              1 reader
0x40009680 : 44 writers                        76 readers
0x4000967C : 65 writers                        93 readers
0x400004FE :  0 absolute refs (pointer-only, from RX record +0x08)
0x4000091E :  0 absolute refs (pointer-only, from descriptor 0x142FD4 +0x00)
```

### What a code cave must reproduce

Minimal set, in order:

1. `*(u16*)0x40002DA2 = 0x1818` — note **`0x1818`, not `0x1808`**: `FUN_000ADADA`'s guard also
   tests `(code >> 4) & 1 != 0`, and `0x1808 & 0x10 == 0`. Depth 2 currently writes `0x1808`.
2. `*(u8*)0x40003F53 = 0xFF` — **the actual fix**. `0x01` is unread. `0x20` alone would drive
   `FUN_000aeec6`; `0x60` drives both consumers; `0xFF` is what the firmware itself writes.
3. Re-assert (1)+(2) for several 10 ms ticks, because both consumers **test-and-clear** the flag.

The cave need **not** touch R5–R10: writing R3 correctly makes the stock periodic chain
(`FUN_000aeec6` → `0x400095E1` → `FUN_000ad97c` → `0x40009680` bit `0x08000000`) produce them
natively. Forcing `0x40009680` directly is actively wrong — `0x0ADA78` re-clears it within ~200 ms.

---

## 3. Controls (rule 17/27) — all passing, all scoped

| script | control | scope | result |
|---|---|---|---|
| `347` C1 | known site `0x0AEEDA` must resolve to `(0x40003F53, bit 2)` — same region, same `e_lis`/`e_add16i`/`e_addi` addressing form as every subject | 352,906 instructions, `0x000160..0x143A7C` | **PASS** |
| `347` C2 | ≥2 distinct sites resolve to `0x40003F53` | same | **PASS** (2) |
| `347` C3 | non-degeneracy: 266 distinct flag addresses, bit indices `{0..7}` — not a constant | same | **PASS** |
| `348` | climb recovers `APP_feature_periodic 0x062848` as caller of `0x0AEEC6` | reference manager | **PASS** |
| `349` | parsed RX record reproduces `rx_frame_map.json` (`0x40000918`, `0x400004FE`, mb 53, mask `0xFF`); descriptor reproduces `rx_signal_dict.json` (`0x4000091E`, mask `0x1F`) | `0x1520F8`, `0x142FD4` | **PASS** |
| `351` C1 | BFS closure from `0x0AEEC6` reaches `0x062848` | CALL+JUMP+FALLTHROUGH | **PASS** |
| `351` C2 | unrelated-site (rule 23): BFS from `0x07890A`, a different feature region, also reaches `0x062848` | same | **PASS** |
| `351` C3 | non-vacuity: BFS from `0x000200` (PBL) must **not** reach `0x062848` | same | **PASS** (not reached) |

Swept ranges are printed by each script, so every null above is explicitly scoped.

### Instrument failures caught by controls (recorded, not hidden)

1. **`347` first run:** a def-table backward walker latched the *first* definition of a register and
   reported `0x0AEEDA`'s flag as `0x40000051`. C1 caught it. Cause: this firmware uses
   **self-accumulating bases** (`e_add16i r29,r29,0x3f02`); a def-table walker never reaches the real
   base. Fixed by switching to backward **substitution**. C1 then passed and the resolved-site count
   rose 410 with 266 distinct addresses.
2. **`349` first run:** `mem.getBytes()` with a Python `bytearray` silently returns **all zeros**
   through jpype — a perfect false negative. The control failed, the cause was found (a Java
   `byte[]` is required), and both controls then passed.

Neither failure produced a negative verdict; both were treated as INCONCLUSIVE until repaired.

---

## 4. What is NOT established

- **That `0x0AD97C`'s bit-27 set is sufficient.** `FUN_000ADADA` also needs bits 28/29 of
  `0x40009680` (observed always-set on the vehicle, `vehicle_session_1.md` §1b) and
  `DAT_40003C42 < 0` as an alternative arm. Not re-derived here.
- **Runtime reachability.** The chain in §1b is a *static* closure. Rule 43: a static edge is not a
  runtime one.
- **`0x1818` vs `0x1808`.** The `>>4 & 1` term is present in the listing at `0x0ADADA`;
  `bench_session_4.md` records it as "refuted" from the wire side. The static read and that note
  disagree — flagged, not adjudicated.
- **Whether `0x20` alone suffices, or `0x60` is needed.** `APP_rke_command_demux` (bit 1, mask
  `0x40`) is a *different* consumer whose one-hot outputs feed the lock module, not `0x0AD97C`.
  Writing `0xFF` sidesteps the question by matching the firmware exactly.
