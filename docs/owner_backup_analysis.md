# Owner firmware backup (2026-09-11) — what the full-flash dump adds

Analysis of `backups/owner-backup-20260911T090300Z/` against everything previously known.
Scripts: `work/rke_backup_analyze.py`, `work/rke_pbl_deep.py`, `work/rke_backup_diff.py`
(all read-only, pure static decode).

**Headline: the dump closes the coverage gap identified in `interior_button_gpio_trace.md` §2f, and
it does NOT contain a hidden PI15/PF12 reader.** The previously-unseen regions turn out to contain
no pad configuration at all. It does, however, reveal two genuinely new things (a PBL identity and
an owner-specific gateway calibration record) documented in §4–§5.

> ### ⚠ §2 IS PARTLY SUPERSEDED — read `docs/owner_flash_layers.md` §3
> The claim below that the PBL references **zero SIUL pad registers** is **WRONG**, and wrong in
> exactly the way this document's own caveat predicted. It came from a 4-byte *literal* scan; the
> PBL builds its SIUL addresses with `e_lis`+`e_add16i`, so they never appear as literals.
> An instruction-level xref scan in the Ghidra project (`work/owner/02_periph_scan.py`) finds
> **48 SIUL accesses across 24 distinct pads**, including a three-pin programming interlock
> (PB10/PD9/PD0) that force-resets the module on a rising edge.
>
> **The PI15/PF12 conclusion itself is unaffected** — neither pad appears in the 48 accesses, nor in
> the application's 3 — so §5's verdict stands, now on much stronger evidence.

## 1. Provenance verified independently

`sha256sum -c SHA256SUMS` → all three files **OK**. Region-by-region against the OEM VBFs:

| Region | Range | vs OEM |
|---|---|---|
| PBL | `0x000000–0x00BFFF` | **no OEM file exists** — newly recovered |
| Cal F124 | `0x00C000–0x00FFFF` | **byte-identical** to `JV6T-14C095-AB` |
| Application | `0x010000–0x13FFFF` | **5 bytes differ** (§5) |
| Cal F10A | `0x140000–0x15BF4B` | 13 bytes differ (§5) |
| tail | `0x15BF4C–0x17FFFF` | 100 % `0xFF` (erased, beyond all VBFs) |
| shadow | `0x200000–0x203FFF` | no OEM file — 17 non-`0xFF` bytes (§3) |
| DFlash | `0x800000–0x80FFFF` | no OEM file — 32 non-`0xFF` bytes (§3) |

The F124 block matching byte-for-byte is strong independent evidence the capture is faithful.

## 2. The PBL configures NO pins — the §2f gap is closed

The 48 KB primary bootloader is real code (`FF`-fill only 2.9 % in `L0/L1`) with a **valid RCHW at
`0x000000`: halfword `0x005A`, entry `0x00000160`** — so the BAM boots the PBL first, exactly as
predicted. Identity strings at `0x006B10`:

```
009640039386
FORD-PBL-V013
DV6T-14C245-FF
DV6T-14A073-FK      <- 14A073 = the bootloader part number seen in the app's version records
WF0AXXWPMAEL32600   <- vehicle VIN (at 0x00800B)
```

This **confirms the §2f inference**: `14A073` is the separately-flashed bootloader, and the app was
merely reporting its version.

> **Follow-up (see `owner_flash_layers.md` §21):** these four strings are not merely informational —
> they are the **live source** for diagnostic identifiers `F18C`, `F180`, `F111` and `F113`
> respectively. The readers are *application* code (`0x0E3xxx`) reaching below `0xC000`; exactly 4 of
> 476 app DID readers do so. Consequences: reflashing the PBL changes the module's reported identity,
> and since no OEM VBF ships the bootloader, these values plus the VIN are **restorable only from this
> backup**. The module's `F111`/`F113` also disagree with the vehicle's as-built data, consistent with
> a replacement unit.

**Decisive for the pin question — the peripherals the PBL references at all:**

| Peripheral | literal refs |
|---|---|
| FlexCAN_0–5 | 13 |
| LINFlex_0–7 | 9 |
| DSPI_0–5 | 6 |
| ADC_0/1 | 4 |
| eDMA | 4 |
| ECSM | 1 |
| **SIUL (any pad register)** | **0** |
| **WKPU / eMIOS / CTU / PSMI** | **0** |

- **No SIUL pad register appears anywhere in the PBL** — not PI15's, not PF12's, not *any* pad's
  PCR/GPDO/GPDI/PGPDI/MPGPDO.
- Target-register scan across PBL + shadow + DFlash for `PI15 PCR143/GPDI/GPDO`,
  `PF12 PCR92/GPDI/GPDO`, `ADC0 CDR55`, `PSMI36_39`, `PSMI48_51`, `eMIOS_1 CCR25`:
  **zero hits in all three regions.**

A programming loader only needs flash-controller, CAN, clocks and a serial link — which is precisely
what it references. It configures no pads, so it cannot be the missing pin reader. (The 4 ADC and
6 DSPI literals are sparse/unaligned values like `0xFFE0572B`, `0xFFF9F101` — almost certainly
coincidental byte patterns in code, not register addresses.)

⚠ Caveat stated honestly: this is a **literal** scan of the PBL, the same method that previously
missed the WKPU and the PWM driver in the app. It is weaker evidence than the app-side audits. But
it is corroborated by the structural argument (a PBL has no reason to read a lock button) and by
§2f's proof that **no interrupt vector and no call reaches low flash** while the app runs.

## 3. Shadow array and DFlash — nothing pin-related, and the MCU is unlocked

**Shadow array** (`0x200000`): all standard NV words are erased —
`NVHWOPT`, `NVPWD0/1` (censorship password), `NVSCC0/1`, `NVBIU0/1` all `0xFFFFFFFF`.

> **The MCU is NOT censored.** With `NVPWD`/`NVSCC` erased, the debug port is not password-locked,
> so a **JTAG/Nexus dump is possible** — the alternative route noted in §2f is open. (Only 17
> non-`0xFF` bytes exist in the whole 16 KB: a `feedfacecafebeef55aa55aa55aa55aa` pattern at
> `0x00203DD8` and one `0xDF` at `0x00203E18`.)

**DFlash** (`0x800000`, EEPROM emulation): only **32 of 65536 bytes** are used (0.0 %), as four
8-byte records at `0x800000/0x801000/0x802000/0x803000`:

```
f1 00 01 00 05 01 d6 4d
f1 00 01 00 06 01 d6 bd
f1 00 01 00 07 01 d7 2d
f1 00 01 00 08 01 d2 dd
```
Uniform `F1000100` header, an incrementing counter (`05,06,07,08`) and a trailing checksum — the
classic **EEPROM-emulation wear-levelling/erase-cycle log**, not configuration data.

> This retires the concern raised at the end of §2f that variant coding might live in unread data
> flash. **There is no variant coding in DFlash** — it holds a flash-management counter. Nothing
> here can enable a pin.

## 4. New: the owner module's calibration differs from OEM (not pin-related)

The app's 5 differing bytes are **not** in the ADC, EIRQ/WKUP, PWM or INTC-vector tables. They sit
in a `0x20`-stride record array at `~0x17C50`, one field of which is a pointer into the F10A
calibration block:

| record | field | OEM | owner |
|---|---|---|---|
| `0x017C90` | `+0x1C` pointer | `0x00141C74` | **`0x0015BE00`** |
| `0x017CB0` | `+0x08` RAM state | `0x40007AF9` | **`0x40007AFD`** |
| — | `0x13FFFF` | `0x72` | `0xA5` (internal `sum8`, consistent) |

The owner's module points at `0x0015BE00`, which **in the OEM image is erased (all zeros)** and in
the owner's is populated with a gateway routing record:

```
owner @0x15BE00 : 4000081C 4000081C 400002E0 00000080 80080200 00000000 ...
oem   @0x141C74 : 4000081C 4000081C 400002E0 00000040 40080200 40000824 ...
```

`0x4000081C` / `0x400002E0` are **gateway signal RAM cells** (cf. `docs/gateway_map.md` §6), so
this is a **relocated, single-entry gateway routing list** replacing the OEM's longer one — the mask
changes `0x40`→`0x80` and the list terminates early. This is CAN signal routing / variant
configuration, unrelated to pad input.

*(Unexplained: whether this is factory variant coding or a prior modification. It is internally
consistent — `sum8` matches — so the module accepts it. Worth knowing before reflashing this module
with stock `-AD`, since doing so would revert this routing record.)*

## 5. Effect on the PI15 / PF12 investigation

| Previously-open gap (§2f) | Now |
|---|---|
| 48 KB PBL unread — might init pins | **Read. References zero SIUL pad registers.** |
| Shadow array unread | **Read. All-erased NV config; MCU uncensored.** |
| DFlash unread — might hold variant coding | **Read. 32 bytes of wear-level log; no config.** |
| BAM mask ROM | Still unreadable by anyone; cannot own a vector or be called by the app (§2f). |

**Conclusion: the full-flash dump adds no mechanism by which PI15 or PF12 could be read.** Every
input route enumerated in `interior_button_gpio_trace.md` §2d remains closed, and the two regions
that could have hidden a reader contain no pad configuration whatsoever.

The remaining hypothesis is unchanged and now better supported by elimination: **the traced wires do
not reach the MCU as digital/analog inputs** — they land on a companion device (UJA1078 SBC or an
analog mux) which reports state over SPI/LIN, or the press is detected elsewhere and relayed on the
bus. A scope on PI15 during a press remains the decisive next measurement.

## 6. Bonus capability unlocked

Because the shadow array shows **no censorship password**, the debug interface should be open. That
provides an *independent* way to verify the SBL-based dump (and to read TestFlash/OTP, which the
backup deliberately skipped) without relying on the SRAM reader at all.
