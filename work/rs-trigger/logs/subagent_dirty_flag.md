# Subagent report — the RKE "new command arrived" dirty flag

Firmware: Ford BCM `JV6T-14C094-AD`, PowerPC VLE. Project `ghidra_proj_fullflash` /
`BCM_OwnerFlash` / `cflash.bin`, opened **read-only** throughout.
Scripts: `work/rs-trigger/339..347`, logs in `work/rs-trigger/logs/339.out .. 347.out`.

---

## 0. Answer

```json
{
  "dirty_flag_address": "0x40003F53",
  "dirty_flag_symbol": "APP_rke_code_valid",
  "dirty_flag_bit": 2,
  "dirty_flag_bit_numbering": "Volcano codec index n, MSB-FIRST: mask = (uint8)(0x80 >> n). n=2 => mask 0x20 => LSB-first hardware bit 5. Derived from the primitive body itself, not assumed.",
  "dirty_flag_mask": "0x20",
  "set_by": "0x05856A  (e_stb r0,0x51(r30) in APP_rke_code_commit @0x058538; r30 = 0x40003F02, so 0x40003F02+0x51 = 0x40003F53; the store writes 0xFF — ALL EIGHT bits at once)",
  "test_and_clears": {
    "primary_remote_start_path": "0x0AEEDA  (bit n=2) in FUN_000AEEC6 @0x0AEEC6",
    "other_consumer_different_bit": "0x099308  (bit n=1) in FUN_000992FE @0x0992FE — the RKE one-hot demux, NOT the remote-start path"
  },
  "code_cave_vle_sequence": {
    "recommended_variant": "C (read-modify-write, sets only n=2)",
    "lines": [
      "e_lis    r3,0x4000        ; 7068e000",
      "e_add16i r3,r3,0x3f53     ; 1c633f53",
      "se_lbz   r0,0x0(r3)       ; 8003",
      "se_bseti r0,0x5           ; 6450    (LSB bit 5 == codec n=2 == mask 0x20)",
      "se_stb   r0,0x0(r3)       ; 9003"
    ],
    "bytes": "7068e000 1c633f53 8003 6450 9003",
    "length_bytes": 14,
    "clobbers": ["r0", "r3", "no CR, no LR, no memory other than 0x40003F53"]
  },
  "confidence": "HIGH for address/bit/setter/clearers and encodings (static, multiply controlled). MEDIUM-HIGH that setting this bit alone is sufficient to make the remote-start consumer act — that last step is unverified on the vehicle."
}
```

---

## 1. The mechanism, end to end

`APP_rke_code_commit` @ `0x058538`, variant-0 branch (disassembly, `340.out`):

```
0005855c  e_lis    r3,0x14
00058560  e_add16i r3,r3,0x2fd4        -> descriptor 0x00142FD4  (MS 0x100 d6, 16-bit)
00058564  e_bl     0x000fbb38          -> VOL_sig_get16
00058568  se_bmaski r0,0x8             ; r0 = 0xFF
0005856a  e_stb    r0,0x51(r30)        -> 0x40003F53 = 0xFF     <<< THE SET
0005856e  e_sth    r3,0x82(r31)        -> 0x40002DA2 = the code  <<< THE VALUE
```

`r30 = 0x40003F02` (`0005854a e_add16i r30,r30,0x3f02`), `r31 = 0x40002D20`
(`00058546`). The value store and the flag store are **two adjacent instructions**
— this is unambiguously the announce-on-arrival pair for `APP_rke_command_code`.

`0xFF` sets *all eight* dirty bits of the byte at once: one producer, up to eight
independent consumers, each owning one bit and clearing only its own.

The primitive (`VOL_test_and_clear_dirty` @ `0x031360`, decompiled):

```c
bool VOL_test_and_clear_dirty(byte *p, byte n) {
    byte old  = *p;
    byte mask = (byte)(0x80 >> (n & 0x1f));
    *p = old & ~mask;
    return (old & mask) != 0;
}
```

⇒ **n is MSB-first.** n=2 → mask `0x20` → LSB-first bit 5. Stated explicitly
because the task asked for it; `347.out` prints the whole table.

### Exactly two consumers of `0x40003F53` exist in the image (`341.out`)

| site | bit n | mask | form | function | subsystem |
|---|---|---|---|---|---|
| `0x099308` | **1** | `0x40` | absolute | `FUN_000992FE` | RKE one-hot demux (`0x40009034/38`) |
| `0x0AEEDA` | **2** | `0x20` | base+disp | `FUN_000AEEC6` | **remote-start feature block (`0x0AD…/0x0AE…`)** |

### The remote-start path, closed (`342.out`, `343.out`)

```
0x40003F53 bit n=2
  └ 0x0AEEDA  VOL_test_and_clear_dirty(&APP_rke_code_valid, 2)
      └ 0x0AEEE6  se_stb r3,0x3(r30)   -> 0x4000968B   (staging)
          └ 0x0AEF0A  se_lbz r0,0x3(r30) ; 0x0AEF14 se_stb r0,0x5(r25) -> 0x400095E1
              └ 0x0ADA24  se_lbz r0,0x5(r3)  -> reads 0x400095E1
                  0x0ADA26  se_cmpi r0,0x1
                  0x0ADA28  se_bne  -> skip
                  0x0ADA3E  e_stw r0,0x94(r31)   <<< SETS BIT 27 of 0x40009680
```

`0x0ADA3E` setting bit 27 is precisely the remote-start setter already identified
in `docs/vehicle_session_1.md` §7.4, whose documented guard is
`DAT_400095E1 == 1`. **That guard is fed, through exactly one write, by the
test-and-clear of `0x40003F53` bit 2.** This is the missing edge-trigger.

`FUN_000AEEC6` is called once, from `APP_feature_periodic` @ `0x000628FC`
(`345.out`) — it is on the main feature tick, so it runs every cycle and the
announcement is consumed on the very next tick after the set.

This also explains the vehicle observation exactly: writing `0x1808` into
`0x40002DA2` by debug service leaves `0x40003F53` untouched, so
`0x0AEEDA` returns 0 → `0x400095E1 = 0` → `0x0ADA28` always branches away →
no remote start, no matter how long the level persists.

---

## 2. Encodings — assembled and independently round-tripped

Assembled with Ghidra's assembler under the mandatory VLE context
(`contextreg = 0x20000000`, `AssemblyPatternBlock.fromBytes(0, [0x20,0,0,0])`).
The first attempt (`344`, first run) failed with "Incompatible context" on
*every* line — a toolchain error caught by the controls, not a finding.

**Assembler controls (`344.out`) — reproduce OEM bytes read out of the image:**

| line | OEM bytes @ | want | got | |
|---|---|---|---|---|
| `se_bmaski r0,0x8` | `0x058568` | `2c80` | `2c80` | PASS |
| `e_stb r0,0x51(r30)` | `0x05856A` | `341e0051` | `341e0051` | PASS |
| `e_add16i r3,r3,0x2fd4` | `0x058560` | `1c632fd4` | `1c632fd4` | PASS |

**Independent round trip (`346`/`347`)** — every assembled byte string was
searched across CFLASH `0x000000..0x17FFFF` at 2-byte alignment and compared
against *Ghidra's own disassembly* of a pre-existing occurrence (assembler and
disassembler are independent paths):

| line | bytes | Ghidra's disassembly elsewhere |
|---|---|---|
| `e_lis r3,0x4000` | `7068e000` | MATCH @`0x0231E0` |
| `e_add16i r3,r3,0x3f53` | `1c633f53` | MATCH @`0x099302` (the other consumer!) |
| `se_lbz r0,0x0(r3)` | `8003` | MATCH @`0x030038` |
| `se_bseti r0,0x5` | `6450` | MATCH @`0x0650DC` |
| `se_stb r0,0x0(r3)` | `9003` | MATCH @`0x022E80` |
| `se_bmaski r0,0x8` | `2c80` | MATCH @`0x023646` |
| `e_stb r0,0x51(r30)` | `341e0051` | MATCH @`0x05856A` (control) |

`e_ori r0,r0,0x20` (`1800d020`) and `e_stb r0,0x0(r3)` (`34030000`) do not occur
in the image, so they are *unconfirmed by this method* — that is why the
recommended variant uses `se_bseti`/`se_stb`, which are both confirmed.

### Three usable variants

**C — recommended (14 bytes, sets only n=2, preserves other pending bits):**
```
7068e000   e_lis    r3,0x4000
1c633f53   e_add16i r3,r3,0x3f53
8003       se_lbz   r0,0x0(r3)
6450       se_bseti r0,0x5          ; LSB bit 5 = codec n=2 = mask 0x20
9003       se_stb   r0,0x0(r3)
```

**B — announce to ALL consumers (12 bytes), byte-for-byte what the OEM commit does:**
```
7068e000   e_lis    r3,0x4000
1c633f53   e_add16i r3,r3,0x3f53
2c80       se_bmaski r0,0x8         ; r0 = 0xFF
9003       se_stb   r0,0x0(r3)
```

**A — exact OEM mirror (14 bytes), if r30 is already the 0x40003F02 base:**
```
73c8e000   e_lis    r30,0x4000
1fde3f02   e_add16i r30,r30,0x3f02
2c80       se_bmaski r0,0x8
341e0051   e_stb    r0,0x51(r30)
```

For a cave that also injects the code value, emit the value store first
(`0x40002DA2`, 16-bit) then the flag, mirroring `0x05856E`/`0x05856A`'s ordering
intent — set the flag **last** so the consumer never sees a dirty flag against a
stale code.

---

## 3. Controls and method adjudication (mandatory section)

**Swept scopes, stated explicitly.** All scans covered every memory block of
`BCM_OwnerFlash`: CFLASH `0x000000–0x17FFFF`, SHADOW `0x200000–0x203FFF`,
DFLASH `0x800000–0x80FFFF`, SRAM `0x40000000–0x40017FFF`, PBRIDGE_A/B.
The "exactly two consumers" claim is a claim about that scope.

**Method disagreement, adjudicated — do not skip this.**
Script `339` resolved the flag pointer by backwards constant-folding r3 over the
40 instructions before each call. It resolved 605/782 sites and reported
`CONTROL C1 (0x40003FC0 bit 4) FAIL`. **That was a method blindness, not an
absence** — exactly the failure AGENTS.md warns about. The lock-command site at
`0x04C630` materialises its flag as `e_addi r3,r28,0xbe` (**struct field off a
prologue base**), which constant-folding over a bounded window cannot see.

Script `341` switched to reading **Ghidra's own resolved PARAM references** on
the instructions preceding each call, which the constant-propagation analyser
has already resolved through the base register. Result: **753/782 resolved
(96.3 %), 366 absolute + 387 base+disp**, and *both* controls pass:

- C1 absolute form: `0x40003FF1` bit 2 @ `0x0AE92C` — **PASS**
- C2 base+disp form: `0x40003FC0` bit 4 @ `0x04C630` — **PASS**

Controls were required in **both addressing forms** because the subject appears
in both (`0x099308` absolute, `0x0AEEDA` base+disp) — a control in only one form
would have certified nothing about the other, and would have silently lost the
remote-start consumer, which is the one that matters.

6 sites remain unresolved and are listed in `341.out` rather than hidden. None
is in `0x40003F4x–0x40003F6x`.

**Reference scan control (`343.out`).** `0x400095E1` (subject, 12 refs) was
checked against `0x400095E2` (control) — the adjacent byte, written by the *same
function* from the *same* test-and-clear idiom through the *same* addressing form
(`se_stb rX,disp(r25)`). The control returned 6 refs, so the scan is not blind
in that region/form. Same pairing for `0x4000968B` (2 refs) vs `0x4000968C`
(2 refs).

**Only one writer.** `0x40003F53` has exactly one WRITE reference in the whole
image: `0x05856A`. No other code path announces this signal.

---

## 4. Caveats / what is NOT proven

1. **Sufficiency is unverified on the vehicle.** Setting bit 2 drives
   `0x400095E1 = 1`, which satisfies *one* guard at `0x0ADA24`. `0x0ADA24` is
   only reached when the `0x4000967C` sub-state field (`e_rlwinm r0,r0,0x6,0x1e,0x1f`,
   i.e. `(w >> 26) & 3`) equals 1, and `FUN_000AD97C`'s enum-8 test
   `(*(ushort*)(r30+0x82) & 0xF) == 8` on `0x40002DA2` must also hold. The
   arrival flag is *necessary* and is the piece that was missing; whether it is
   *sufficient* needs a depth-5 flash + candump.
2. **`FUN_000AD97C` and `FUN_000ADE12` have 0 callers by reference** — they sit
   in unswept-adjacent territory and are reached by fallthrough. Their reachability
   was not re-derived here; the byte-level guard evidence at `0x0ADA24` stands
   independently of it.
3. `e_ori r0,r0,0x20` and `e_stb r0,0x0(r3)` assemble cleanly but have no
   in-image occurrence to round-trip against. Prefer the confirmed variants.
4. Nothing was flashed, no VBF touched, no project opened writable.
