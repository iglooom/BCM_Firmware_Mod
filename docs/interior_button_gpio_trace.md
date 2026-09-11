# Interior lock/unlock button pins (PI15 / PF12) — GPIO trace investigation

**Question:** interior LOCK is wired to **PI15** (pkg pin 75, PCR143), UNLOCK to **PF12** (pkg pin 43,
PCR92). Can we find where firmware reads these pins, locate the central-lock logic cluster, and just
trigger the lock pin instead of injecting CAN frames?

> ## ⚠ STATUS: REOPENED AND REVERSED (2026-09-11)
>
> **The verdict below was WRONG. Both pins are configured AND polled by this firmware.**
>
> | | |
> |---|---|
> | Configured by | the **149-record pad table** @ `0x00017380`, applied at boot by `FUN_0003F3E0` ← `APP_mcu_driver_init` |
> | PI15 record | `8f 41 0100` → pad 143, **PCR `0x0100` = IBE** (digital input, buffer ON) |
> | PF12 record | `5c 82 0100` → pad 92, **PCR `0x0100` = IBE** (digital input, buffer ON) |
> | Read by | `FUN_0003B4AE(pad)` — a **generic reader taking the pad number as an argument** |
> | Read sites | `FUN_0003B4AE(0x8F)` = PI15 (**9×**), `FUN_0003B4AE(0x5C)` = PF12 (**5×**) |
> | Debounced into | PI15 → `0x40004300` → state `0x40003AA5` **bit 5**; PF12 → `0x400042A4` → state `0x40003AA5` **bit 4** |
> | Consumed by | `FUN_00050726`, which repacks bits 4/5 into the signal plane |
>
> **Why every previous scan missed it — the negatives were all methodologically void.**
> Both the pad number *and* the PCR value live in **data**; the addresses are computed as
> `&SIUL_PCR_PA0 + pad` / `&SIUL_GPDI_PA0 + pad`. **No PI15/PF12 register address exists anywhere in
> the image** — which is exactly what §2 measured and misread as "not serviced". An address scan
> cannot see a table-driven HAL. The same blind spot hid the LIN0 pads (`owner_flash_layers.md` §28.6)
> and the WKPU driver (§2a below) — this document had *already* been corrected once for precisely
> this reason, and the lesson was not applied to its own main conclusion.
>
> The §3.1 "only three pads touched" and §5 "no pad configuration whatsoever" cross-checks were the
> *same* method re-run, so they added confidence without adding independence.
>
> Evidence: `work/owner/136`–`145`, `owner_flash_layers.md` §30. The active-low debounce
> (`LZCOUNT(v)>>5` = "pin == 0") and the two adjacent state bits fed through identical gates are the
> signature of a paired LOCK/UNLOCK switch to ground.
>
> **Consequence:** the "trigger the lock pin" shortcut is **not** ruled out. Note it is an *input*,
> so one does not "drive" it — the exploitable move is to force the debounced state bit or its
> consumer. Not yet attempted; no bench measurement is required to proceed.

<details>
<summary><b>Superseded original verdict (kept for the method lesson)</b></summary>

**~~Verdict: neither pin is serviced by this firmware.~~** ~~They are not polled through SIUL GPIO, and
neither pin is eligible for EIRQ/WKPU wakeup. The other plausible input-peripheral routes are also
closed: PI15's `ADC0_S[23]` (absolute channel 55) is absent from every ADC conversion mask, and
PF12's eMIOS1 channel 25 is not read. The "trigger the lock pin" shortcut is therefore unavailable on this image. The
bus-injection approach (rke-lock on `0x3A`) remains the correct firmware mechanism.~~

> **Correction (wakeup/interrupt route re-audited).** An earlier revision of this doc implied the
> WKPU peripheral was untouched. **That was wrong** — the firmware *does* drive WKPU at
> `0xC3F94000`, but through a **generic table-driven driver**, so the exact-constant scan of §2
> never saw a WKPU base. The wakeup path is now enumerated positively rather than assumed absent,
> and the PI15/PF12 conclusion is unchanged. See §2a.

> ~~**Status: CLOSED (negative result), and later re-confirmed on the full flash.**~~ This document is
> the exhaustive enumeration that ruled the GPIO route out. Two follow-ups have since strengthened
> it, so **do not re-open it from the firmware side**:
> - `owner_flash_layers.md` §3.1 — an instruction-level scan that provably resolves `e_lis`-built
>   addresses finds only **three** pads touched in the whole image (PA0, PB2, PB3). Neither PI15 nor
>   PF12 appears in the PBL's 48 SIUL accesses either. A materially stronger negative than the
>   literal scan below.
> - `owner_backup_analysis.md` §5 — the §2f coverage gap is **closed**: the 48 KB PBL, the shadow
>   array and DFlash were all read and contain **no pad configuration whatsoever**.
>
> **Remaining hypothesis (single, by elimination):** the traced wires do not reach the MCU as
> digital/analog inputs — they land on a companion device (UJA1078 SBC or an analog mux) reporting
> over SPI/LIN, or the press is detected elsewhere and relayed on the bus. **The only remaining step
> is a bench measurement** (scope PI15 during a press); no further static analysis can decide it.

**The ADC/eMIOS/WKPU eliminations in §2–§2b below remain valid** — those routes genuinely are unused.
The error was concluding "therefore the pin is unserviced" when the plain-GPIO route had only been
tested by address scanning.

</details>


## Register addresses (SPC560B64, SIUL base 0xC3F90000 — confirmed)

| Pin | pad | GPDI (input) | GPDO (output) | PCR (config) |
|---|---|---|---|---|
| PI15 (LOCK)   | 143 | `0xC3F9088F` | `0xC3F9068F` | `0xC3F9015E` |
| PF12 (UNLOCK) | 92  | `0xC3F9085C` | `0xC3F9065C` | `0xC3F900F8` |
Parallel-port inputs: PGPDI port I = `0xC3F90C50`, port F = `0xC3F90C4A`.

The device pin-function table gives these alternatives:

| Pin | AF0 | Other digital AF | Analog input |
|---|---|---|---|
| PI15 | GPIO143 | AF1 = DSPI4 `CS0_4` (output) | `ADC0_S[23]` = absolute channel 55 |
| PF12 | GPIO92 | AF1 = eMIOS1 channel 25; AF2 = LINFlex5 TX | none |

Neither row offers EIRQ or WKPU.

## Method + evidence (all cross-checks agree)

1. **SIUL base proven right.** The only SIUL accesses in the whole image are the external-interrupt
   config block — ISR `+0x14`, IRER `+0x18`, IREER `+0x28`, IFEER `+0x2C`, IFER `+0x30` — plus a few
   low PCRs, all at `0xC3F90000`-relative offsets that decode sensibly. FlexCAN/eMIOS/ADC bases all
   resolve correctly too, so the address model is sound. (`work/rke_siul_map.py`)
2. **Full-image 32-bit constant scan covers table-driven peripheral-address use.**
   Proof: the FlexCAN bases each appear exactly once — `0xFFFC0000`@`0x1464f0`, `0xFFFC4000`@`0x146910`,
   `0xFFFC8000`@`0x146c60` — i.e. the runtime loads them from descriptor tables (which is why an
   inline-constant tracer misses all runtime CAN access). Using that same scan:
   - **No SIUL/GPIO register address for PI15 or PF12 exists anywhere** in the 1.4 MB image — not
     inline, not in any table, not in a literal pool. `0xC3F9088F/085C/068F/065C/015E/00F8`: **0
     occurrences each.** SIUL base `0xC3F90000`: 0. All PGPDI/PGPDO: 0. (`work/rke_gpio_raw.py`)
3. **No parallel-port, eMIOS, ADC, EIRQ, or WKPU path either.**
   - PGPDI/PGPDO of every port is absent.
   - The only directly processed eMIOS channels are {0,8,16,23,24} on both modules. PF12 would be
     eMIOS1 channel 25, which has no channel-register read or write. The generic indexed eMIOS
     accesses only manipulate module-level channel masks; the runtime channel-data consumers are
     fixed to the listed channels. (`work/rke_emios.py`)
   - PI15 could alternatively be `ADC0_S[23]`, which is **absolute ADC channel 55**, not channel 23.
     Because conversion is selected by NCMR/JCMR masks and may be transferred through eDMA, an
     address/CDR-consumer search alone is insufficient. The complete mask and DMA audit is in §2b.
   - **Interrupt/wakeup hypothesis:** the reference-manual WKPU source table contains neither PI15
     nor PF12, and the device pin-function table gives neither pin an EIRQ alternate function.
     Therefore no edge-interrupt or wakeup route exists for these two pads. (`work/rke_pdf_wkpu.py`)

## 2a. The wakeup/interrupt route, enumerated positively (not merely assumed absent)

The §2 exact-constant scan cannot see a peripheral base built with `e_lis`+`e_add16i`, which is
exactly how the WKPU base is formed here. Re-run with a **constant-propagating** pass over the whole
`0xC3F9_xxxx` page (`work/rke_wkpu_scan.py`, read-only Ghidra) — this resolves both SIUL *and* WKPU:

| Register | Accesses | Meaning |
|---|---|---|
| `0xC3F90014/18/28/2C/30` | 4/6/12/4/2 | SIUL EIRQ ISR / IRER / IREER / IFEER / IFER |
| `0xC3F90040/58/5C` | 2/1/2 | SIUL PCR[0], PCR[12], PCR[14] — **only three PCRs in the image** |
| `0xC3F94014/18/1C/28/2C/30/34` | 4/20/9/23/8/6/4 | **WKPU** WISR / IRER / WRER / WIREER / WIFEER / WIFER / WIPUER |

So the WKPU **is** live. The pads it serves are then read directly out of the driver's config table
rather than guessed:

- `FUN_00034d16` — WKPU cold-init (clears IRER/WRER/WIREER/WIFEER/WIFER, writes `WISR=0x1FFFFFFF`).
- `FUN_0003c4cc` — reads a config header at **`0x00017050`** (`count=4`, record array at
  **`0x00017150`**, 32 B/record) and calls `FUN_0003c88c` per record.
- `FUN_0003c88c` — the generic router. Record byte[0] is a **source id**: `<0x40` → `0xC3FA_xxxx`
  peripheral block; `0x40..0x57` → **SIUL EIRQ** channel `id-0x40`; `>=0x58` → **WKPU** channel
  `id-0x58`. Flags at `+4`: bit0 filter (WIFER), bit1 pullup (WIPUER), bit7 rising, bit8 both/level.

Decoding that table (`work/rke_eirq_table.py`) gives the firmware's **complete** wakeup/interrupt set:

| idx | src id | route | edge / opts |
|---|---|---|---|
| 0 | `0x6B` | **WKUP19 = PA0** (PCR0) | falling, filter |
| 1 | `0x0A` | periph `0xC3FA_xxxx` block 10 | rising |
| 2 | `0x61` | **WKUP9 = PA4** (PCR4, LIN5RX) | falling |
| 3 | `0x67` | **WKUP15 = PF11** (PCR91, LIN4RX) | falling |

**EIRQ channels armed: none. WKUP channels armed: {9, 15, 19} → pads PA4, PF11, PA0 only.**
(WKUP9/WKUP15 are the LIN5RX/LIN4RX pins — i.e. LIN bus-activity wakeup, consistent with the
LIN-transceiver GPIO cluster in §4. WKUP19/PA0 is a discrete wake input.)

Independently, the **RM wakeup-source table is exhaustive** — all 29 channels WKUP0..WKUP28 map to
`API, RTC, PA1, PA2, PB1, PC11, PE0, PE9, PB10, PA4, PA15, PB3, PC7, PC9, PE11, PF11, PF13, PG3,
PG5, PA0, PG7, PG9, PF9, PI3, PI1, PB8, PB9, PD0, PD1`. **Neither PI15 nor PF12 appears**, so no
table record could route them even if one existed. Note how close the misses are: PF12's neighbour
**PF11** *is* WKUP15, and port I contributes only **PI1/PI3** — not PI15.

The datasheet pin-function rows were re-read from the extracted tables to confirm no EIRQ alternate:

```
PI[15], PCR[143] : AF0=GPIO[143]  AF1=CS0_4 (DSPI, output)  AF2/AF3=—   ADC0_S[23]
PF[12], PCR[92]  : AF0=GPIO[92]   AF1=E1UC[25] (eMIOS_1)    AF2=LIN5TX  AF3=—
```
(`DS_spc560b64l7_tables/page52_table0.csv`, `page41_table0.csv` — pdfplumber-extracted.)
`CS0_4` and `LIN5TX` are **outputs**; they cannot deliver a button state.

**Conclusion of the wakeup audit:** the "not polled — maybe it's an interrupt/wakeup" hypothesis is
now *disproved by enumeration*, not by absence of evidence. The firmware arms exactly three wakeup
pads and zero EIRQ channels, and the silicon offers PI15/PF12 no wakeup or interrupt route at all.

## 2b. The ADC (and ADC→eDMA) route — re-tested correctly

Two prerequisites had to be fixed before the ADC question could even be asked properly.

**Fix 1 — the channel number.** The datasheet signal is `ADC0_S[23]`, a *Standard*-bank channel.
On SPC560B64 the banks map to absolute channel numbers as
`ADC0_P[0..15]→0..15`, `ADC0_S[0..27]→32..59`, `ADC0_X[0..3]→64..67`. Therefore:

> **PI15 = ADC0_S[23] = absolute channel 55**, whose data register is **CDR55 `0xFFE001DC`**.

The earlier check tested channel 23 / `0xFFE0015C`, which the RM register map shows is inside
`0x0140...0x017F Reserved` — **not a register at all**. That negative was meaningless.

**Fix 2 — the method.** A channel is enabled by a **bitmask in NCMR**, never by an address, so no
address scan can detect it. And if the ADC feeds **eDMA**, results are written to RAM with **no CDR
load anywhere in the code** — so "no consumer reads CDR55" is not evidence either. The only decisive
artifact is the mask value actually programmed into the hardware.

**Where the masks come from.** The real ADC init is `FUN_0003a402` (not `FUN_00039374`). It does not
hardcode masks; it copies them out of a **group-config record** (array @`0x16B8C`, 7 records, stride
`0x58`) into the hardware — `record[+0x24]→NCMR0/JCMR0`, `record[+0x28]→NCMR1/JCMR1`,
`record[+0x2C]→JCMR2`, `record[+0x30/+0x34]→PSR0/PSR1`. Channel 55 is **NCMR1/JCMR1 bit 23 =
`0x00800000`**. Decoding all seven records (`work/rke_adc_groups.py`):

| group | NCMR0 (+0x24) | NCMR1 (+0x28) | channels | signals |
|---|---|---|---|---|
| 0 | `0x00000000` | `0x00018000` | 47, 48 | S[15], S[16] |
| 1 | `0x00000000` | `0x0C000008` | 35, 58, 59 | S[3], S[26], S[27] |
| 2 | `0x00000003` | `0x00000000` | 0, 1 | P[0], P[1] |
| 3 | `0x00000100` | `0x00000000` | 8 | P[8] |
| 4 | `0x00003030` | `0x00000040` | 4, 5, 12, 13, 38 | P[4], P[5], P[12], P[13], S[6] |
| 5 | `0x00000004` | `0x00000000` | 2 | P[2] |
| 6 | `0x00000000` | `0x00000400` | 42 | S[10] |

Union of every channel this firmware ever converts: **{0,1,2,4,5,8,12,13,35,38,42,47,48,58,59}**.
**Bit 23 of NCMR1/JCMR1 is clear in all seven groups → channel 55 / PI15 is never sampled.**
`NCMR2/JCMR2` (channels 64+) are also irrelevant to PI15. This matches the channel-config table
independently, and the decompiled consumers in `FUN_00040998` read exactly CDR35/47/48/58/59
(`0xFFE0018C/1BC/1C0/1E8/1EC`) — no CDR55.

**The eDMA path is closed too.** `FUN_0003a402` writes only MCR / IMR / CIMR / NCMR / JCMR / PSR /
CTR — it **never writes `DMAE` (+0x40) or `DMAR0/1/2` (+0x44/48/4C)**, and a constant-propagating
resolve of every ADC access in the image (`work/rke_adc_ncmr.py`) finds no DMAE/DMAR touch and no
indexed/dynamic ADC addressing. With `DMAE` never set, ADC results never reach eDMA, so the
"DMA hides the consumer" escape hatch does not apply.

**On the wire-fault/resistance-diagnostics theory:** it is exactly right as a *design pattern* — a
resistor-ladder switch input read by ADC is how such buttons are usually done, and it would have
defeated a GPIO-only search. It just isn't wired to this MCU's ADC here: the ADC's 15 converted
channels are all accounted for and none is PI15. If the button really is on a resistor ladder, the
ladder is being read by **another device** (see §"What this means").

## 2c. The CTU (Cross Triggering Unit) route — the ADC audit's real blind spot

§2b tested the **NCMR/JCMR** masks. That is *not* sufficient on its own: **CTU-triggered conversions
bypass NCMR entirely.** Each `CTU_EVTCFGR` register names an ADC channel directly and triggers it,
so a CTU-sampled pad can be converted without ever appearing in a normal-conversion mask. This was a
genuine gap — and unlike the WKPU case, **the CTU really is in use here.**

`CTU @ 0xFFE6_4000..0xFFE6_7FFF` (RM p76). `CTU_EVTCFGR0..63` at offsets `0x030..0x12C`, 4 B each.
`EVTCFGR` fields (RM p817): **TM** = bit15 (trigger enable), **CLR_FLAG** = bit14,
**ADC_SEL** = bit7 (0 = ADC0, 1 = ADC1), **CHANNEL_VALUE** = bits 6..0 (0..95).

The same ADC init `FUN_0003a402` programs it (verified by disassembly, `work/rke_ctu_verify.py`):

```
0003a690  e_lis   r7,0xffe6
0003a694  e_lwz   r7,0x4000(r7)      ; read  CTU 0xFFE64000
0003a6a8  se_bseti r7,0x18
0003a6aa  e_stw   r7,0x4000(r30)     ; write CTU 0xFFE64000  (enable bit)
0003a698  e_slwi  r4,r31,0x2
0003a69c  e_add16i r4,r4,0x4030
0003a6a0  e_add2is r4,-0x1a          ; r4 = 0xFFE64030 + r31*4 = &EVTCFGR[r31]
0003a6ae  se_cmpi r31,0x17           ; event 23
0003a6bc  e_cmpi  cr0,r31,0x37       ; event 55
```

> ⚠ **Trap — `0x37` here is NOT ADC channel 55.** `r31` indexes `EVTCFGR[]`, so `0x17`/`0x37` are
> **CTU event numbers**. It is pure coincidence that PI15's absolute channel is also 55. Reading
> that compare as "the firmware special-cases channel 55" would be exactly the wrong conclusion.

The converted channel is `CHANNEL_VALUE`, written as `chan | 0x8000` where `chan` comes from the
6-byte channel-config records via the group's channel-index list (`group[+0x04]`), while the event
index comes from `group[+0x20]`. Decoding all 7 groups (`work/rke_ctu_events.py`):

| group | event ptr | CTU event | EVTCFGR addr | channel written | signal |
|---|---|---|---|---|---|
| 0–4 | `0x00000000` | — | — | *no CTU event* | — |
| 5 | `0x16E62` | **7** | `0xFFE6404C` | ADC1 ch **2** (`0x8002`) | `ADC1_P[2]` |
| 6 | `0x16E66` | **49** | `0xFFE640F4` | ADC0 ch **42** (`0x802A`) | `ADC0_S[10]` |

**Only two CTU events exist, converting channels 2 and 42. Neither is 55.** Moreover
`CHANNEL_VALUE` is always sourced from the channel-config table, whose complete channel set is
ADC0 `{35,42,47,48,58,59}` / ADC1 `{0,1,2,4,5,8,12,13,38}` — **55 is absent**, so no CTU event can
name PI15 even in principle.

**Net effect:** the CTU is the one peripheral that *was* genuinely under-examined, it *is* active,
and checking it still returns PI15 = not sampled. The ADC conclusion in §2b now rests on both the
NCMR masks **and** the CTU event table, which together cover every way this ADC can be triggered
(software scan, injected, and cross-trigger).

## 2d. Systematic RM sweep — the input-mux route, and every remaining peripheral

Previous sections chased peripherals one at a time (a guessing game). This section works **top-down
from the RM's own peripheral memory map** so nothing is left unexamined
(`work/rke_rm_full_map.py` → `work/rm_periph_map.json`, `work/rke_gap_sweep.py`).

### The real gap: SIUL PSMI input multiplexing

Every earlier audit asked *"does firmware touch PI15's own PCR/GPDI address?"*. **PSMI defeats that
question entirely** — it is the documented SIUL mechanism by which a *peripheral input* is sourced
from one of several pads. The pad is never named by its own register; the peripheral is simply told
which pad to listen to. This is precisely the "configured via some mux" path.

`PSMI0_3..PSMI60_63` @ SIUL `0x0500–0x053C` (16 registers × four 8-bit `PADSEL` fields;
`PADSELn` = byte `0x500+n`). RM Table 182 contains **both our pins**:

| PADSEL | offset | function | options |
|---|---|---|---|
| **PADSEL37** | `0x525` | `CS0_4` / DSPI_4 | `00`:PCR107 `01`:PCR123 `10`:PCR134 **`11`:PCR143 = PI15** |
| **PADSEL51** | `0x533` | `E1UC[25]` / eMIOS_1 | **`00`:PCR92 = PF12** `01`:PCR124 |

**Result: the PSMI block is never written** — 0 literals, 0 constant-propagated accesses
(`work/rke_psmi.py`). So every `PADSEL` stays at its reset value `0`:

- `PADSEL37 = 00` → `CS0_4` is sourced from **PCR107, not PI15**. PI15 is *not* muxed in.
- `PADSEL51 = 00` → **PF12 *is* the reset-default source for eMIOS_1 channel 25.** ⚠ This one is
  selected *by default, without firmware doing anything* — the single most plausible remaining route,
  and it made the eMIOS ch25 question load-bearing rather than incidental.

### Closing eMIOS_1 channel 25 properly

The earlier note ("runtime consumers use only channels {0,8,16,23,24}") was a *consumer* argument.
The decisive question is whether channel 25 is **enabled**: eMIOS ch*n* registers sit at
`base + 0x20 + n*0x20`, so ch25 = `0xC3FA4340..0xC3FA435F`, and `CCR.MODE[6:0] == 0` means disabled.

- Resolved accesses to any channel-25 register: **0**
- `CADR25/CBDR25/CCNTR25/CCR25/CSR25` as literals: **0 each**
- Every resolved eMIOS_1 address: `+0x000` (global), `+0x02C`, `+0x12C`, `+0x22C`, `+0x30C`, `+0x32C`
  → channels **0, 8, 16, 23, 24** only.

`CCR25` is never written, so MODE stays `0` → **channel 25 is disabled**. PF12 is wired to a
peripheral input that is muxed in by default but never turned on. Dead end confirmed, not assumed.

### Full peripheral sweep — what this firmware touches

| Touched | Never touched |
|---|---|
| SIUL(37) WKPU(76) eMIOS_0(45+14idx) eMIOS_1(12) MC_ME(101) MC_CGM(62) MC_RGM(20) MC_PCU(4) RTC/API(60) PIT(16) ADC_0(39) ADC_1(1) CTU(2) MPU(6) SWT(12) STM(43) ECSM(8) eDMA(5) INTC(16) DMA_MUX(4) BAM(12) flash-cfg(40) | **SSCM, I2C_0, CAN sampler, DSPI_0–5, LINFlex_0–9, FlexCAN_0–5** |

⚠ The "never touched" column is by *resolved access* only; table-driven peripherals legitimately
show 0 (FlexCAN is the proof). So it must be cross-checked with the literal/positive-control scan:

```
positive control : FlexCAN_0/1/2  -> 0x1464f0 / 0x146910 / 0x146c60   (table-driven, found)
DSPI_0..3        -> 0x115e18/1c/20/24  (a 4-entry DSPI base table)
DSPI_4           -> ABSENT      LINFlex_5 -> ABSENT
DSPI_5           -> ABSENT      I2C_0     -> ABSENT     CAN sampler -> ABSENT
```

**This closes the two alternate functions of our pins directly:**
- **PI15 AF1 = `CS0_4` / DSPI_4** — the DSPI base table holds only DSPI_0–3; **DSPI_4 appears
  nowhere**, so the controller is never instantiated. (This also settles the check deferred in §2a.)
- **PF12 AF2 = `LIN5TX`** — **LINFlex_5 appears nowhere** either.
- The **CAN sampler** (`0xFFE70000`, a peripheral that samples a CAN RX pin directly) is likewise
  entirely absent — worth stating explicitly since it is an easy-to-miss input block.

### Every input route for PI15 / PF12, enumerated

| Route | PI15 | PF12 | Evidence |
|---|---|---|---|
| GPIO GPDI / PGPDI | ✗ | ✗ | address absent (§2) |
| PCR pad config | ✗ | ✗ | only PCR0/12/14 configured (§2a) |
| EIRQ | ✗ (no AF) | ✗ (no AF) | pin table; 0 EIRQ armed (§2a) |
| WKPU wakeup | ✗ (not a source) | ✗ (not a source) | RM WKUP0–28 table (§2a) |
| ADC normal/injected | ✗ ch55 clear | n/a | all 7 NCMR/JCMR masks (§2b) |
| ADC via eDMA | ✗ | n/a | DMAE/DMAR never written (§2b) |
| ADC via CTU | ✗ | n/a | only events→ch2, ch42 (§2c) |
| **PSMI input mux** | **✗ PADSEL37=00** | **⚠ PADSEL51=00 selects PF12** | PSMI never written (§2d) |
| eMIOS channel | n/a | **✗ ch25 MODE=0** | CCR25 never written (§2d) |
| DSPI / LINFlex AF | ✗ DSPI_4 absent | ✗ LINFlex_5 absent | base-literal scan (§2d) |

All routes closed. PF12's PSMI default is the only place either pin is *selected* by hardware, and
the peripheral behind it is disabled.

## 2e. The output drivers — found: 11 eMIOS PWM channels (not GPIO)

§4 below reports only **five** GPDO output pads, which is implausibly few for a BCM that drives
multiple transistors into relays/MOSFETs. That number was an artefact of scanning for **GPDO
addresses**: this firmware does not drive its loads through SIUL GPIO at all. It drives them with
**eMIOS PWM channels**, whose registers are formed as `base + 0x20 + ch*0x20` at runtime — so they
appear as **zero literals** and were invisible to every address scan so far (the eMIOS literal scan
returns "channels referenced = none", while 14 indexed accesses existed).

**Driver chain** (all decompiled, `work/rke_pwm_outputs.py`):

```
FUN_0003f54a  DAT_4000421c = cfg  (defaults to &LAB_000175d4 when NULL)
              -> FUN_0003fd3e(cfg[+4])
FUN_0003fd3e  DAT_40004220 = record array ; for i < *DAT_4000421c:
                 rec  = DAT_40004220 + i*0x24
                 ch   = rec[0]        ; <0x20 -> eMIOS_0, >=0x20 -> eMIOS_1
                 ccr  = rec[1]        ; -> CCR(ch) = base + 0x2C + ch*0x20
FUN_0003f836  runtime duty-cycle setter (dispatches on the same channel id)
```

**Config table:** header @`0x175D4` (`count = 11`), records @`0x175DC`, stride `0x24`.
Every record has `CCR MODE = 0x26` = **OPWMB — Output PWM, Buffered** → all genuine outputs.

| rec | ch id | module/channel | candidate package pads |
|---|---|---|---|
| 0 | 51 | eMIOS_1 ch19 | PE12 (PCR76) |
| 1 | 22 | eMIOS_0 ch22 | PE6 (PCR70), PE8 (PCR72), PF5 (PCR85) |
| 2 | 21 | eMIOS_0 ch21 | PE5 (PCR69) |
| 3 | 20 | eMIOS_0 ch20 | PE4 (PCR68) |
| 4 | 49 | eMIOS_1 ch17 | PG8 (PCR104), PH15 (PCR127) |
| 5 | 28 | eMIOS_0 ch28 | PA12 (PCR12), PI0 (PCR128) |
| 6 | 30 | eMIOS_0 ch30 | PB0 (PCR16), PB2 (PCR18), PI2 (PCR130) |
| 7 | 7 | eMIOS_0 ch7 | PA7 (PCR7), PB15 (PCR31), PC9 (PCR41) |
| 8 | 54 | eMIOS_1 ch22 | PE15 (PCR79) |
| 9 | 18 | eMIOS_0 ch18 | PE2 (PCR66) |
| 10 | 53 | eMIOS_1 ch21 | PE14 (PCR78) |

**These 11 PWM outputs are the transistor/MOSFET gate drivers.** PWM (rather than plain GPIO) is
exactly what you'd expect for BCM loads: lamp dimming, soft-start on bulbs, current-limited holds on
relay coils, motor drive.

⚠ **Honest limits of this table.** It gives the eMIOS *channel*, and each channel is available on
2–3 alternate pads. Static analysis cannot tell which of those pads is bonded on this board, because
**the PCR writes that select the pad's AF are not in this image** (only PCR0/12/14 are configured —
see §2a). Single-candidate rows (PE12, PE5, PE4, PE15, PE2, PE14) are unambiguous; multi-candidate
rows are not. Mapping a channel to a *specific load* (lock relay vs lamp) requires the schematic or
bench probing — the firmware only proves "these channels are PWM outputs".

### Why the earlier "5 outputs" figure was misleading

The five GPDO pads (PA5, PA7, PB2, PC6, PC8) are **not** load drivers. The descriptor records at
`0x146840/0x146874/0x1468A8/0x1468DC/0x1AE68` pair each output+input pad with a **LINFlex base**:

```
rec@0x146840  +0x08 0xFFE50000 LINFlex_4  +0x18 GPDO[5]=PA5   +0x1C GPDI[6]=PA6
rec@0x146874  +0x08 0xFFE48000 LINFlex_2  +0x18 GPDO[40]=PC8  +0x1C GPDI[41]=PC9
rec@0x1468A8  +0x08 0xFFE4C000 LINFlex_3  +0x18 GPDO[7]=PA7   +0x1C GPDI[8]=PA8
rec@0x1468DC  +0x08 0xFFE44000 LINFlex_1  +0x18 GPDO[38]=PC6  +0x1C GPDI[39]=PC7
rec@0x01AE68  +0x0C 0xFFE40000 LINFlex_0  +0x18 GPDO[18]=PB2  +0x1C GPDI[19]=PB3
```

i.e. **LIN transceiver enable (out) + status/report (in)** per LIN bus — confirming §4's reading,
and explaining why they are the *only* GPDO pads. (Note PA7/PC9 also appear as eMIOS candidates
above; the LIN pairing is the firmware's actual use of PA7.)

**No parallel/masked GPIO writes exist** (`PGPDO`/`MPGPDO`: **0 occurrences**), so there is no hidden
bank of GPIO outputs being driven 16-at-a-time — the output set really is "11 PWM + 5 LIN control".

**For PI15 / PF12:** PI15 has **no eMIOS function at all** (its only AFs are `CS0_4` and `ADC0_S[23]`),
so it cannot be a PWM output. PF12 is `E1UC[25]`, which is **not among the 11 configured channels**
(and §2d showed ch25 has MODE=0). Neither pin is an output driver.

## 2f. Boot, the un-flashed bootloader region, and "is there other code?"

**The concern is legitimate and §5's old claim was wrong.** The OEM VBF set does **not** cover the
whole device. Comparing VBF blocks against the SPC560B64 flash map (`work/rke_boot_coverage.py`):

| Device region | Range | Covered by VBFs |
|---|---|---|
| code flash boot sectors L0–L3 | `0x000000–0x00BFFF` | **NONE — 48 KB unflashed** |
| code flash L4.. (Cal F124 + app) | `0x00C000–0x13FFFF` | full |
| code flash array 2 (Cal F10A) | `0x140000–0x15BF4B` | partial (rest erased) |
| **flash shadow array** | `0x200000–0x203FFF` | **NONE** |
| **data flash (EEPROM emulation)** | `0x800000–0x80FFFF` | **NONE** |
| **BAM (boot assist ROM)** | `0xFFFFC000+` | **mask ROM — not flashable at all** |

So yes: **there is code on this MCU we have never seen** — a ~48 KB bootloader in low flash, plus
ST's mask-ROM BAM. The app even carries the bootloader's version strings (`0x0134BC`):

```
@(#)BL110502.2200.v1.0(V408 E4)      <- SCCS "what" marker
BL190614.1400.v12.9                   <- bootloader build 2019-06-14 v12.9
DS-JV6T-14A073-BB                     <- its Ford part number (14A073 = bootloader)
```
`14A073` is a *different part number* from the app (`14C094`), confirming the bootloader is a
separately-flashed component that the OEM app files simply never touch.

### But it cannot be servicing PI15/PF12 at runtime

Three independent checks (`work/rke_boot_path.py`, `work/rke_vectors.py`):

1. **Boot order.** The BAM scans boot sectors for an RCHW (halfword with `0x5A` in bits 8–15). Low
   flash `0x0/0x4000/0x8000` read `0xFFFF` **in our image because we don't have them** — but the app
   block carries a **valid RCHW at `0x10000`**: halfword `0x005A`, **entry `0x0010F4A0`**, VLE bit set.
   Typical Ford flow: BAM → bootloader (low flash) → jumps to the app entry.
2. **No control transfer into low flash.** Of **17,656** branch/call targets in the entire
   application, **0** land below `0xC000`.
3. **No interrupt can reach it either.** `FUN_0003594e` programs INTC `IACKR = 0x00011800`, so the
   vector table is at `0x11800` — *inside the app*. All **256** entries decode as VLE `e_b`
   instructions (opcode `0x78xxxxxx`, target = `PC + sign_extend(BD24<<1)`) and **every one targets
   the app** (`0x0010E0B6`, `0x0010E0CE`, …). **0 vectors point into low flash.**

   ⚠ Method note: these words are **instructions, not addresses**. Reading them as pointers gives
   garbage like "`0x780FC8B6` → app" by accident; they must be decoded as branches.

Since the bootloader owns no vector and is never called, it runs **before** the application and
hands over. It cannot be polling a button behind the app's back. (A bootloader also has no reason
to: its job is UDS reprogramming.)

### Startup path and "is there an RTOS?"

`reset_entry @0x0010F4A0` is a classic bare-metal C runtime, **not** an RTOS boot:

```
mtmsr 0x21200              ; enable ME/SPE
e_bl 0x0010F570            ; core/MMU early init
e_bl 0x0002FDF2            ; clocks / MC_ME / peripheral bring-up
e_lwz r1,0x15F38(r3)       ; load initial STACK POINTER
e_lis r13,0x4001 ... 0x7920 ; r13/r2 = SDA small-data base (0x40017920)
e_bl 0x0002FEC8
<loop> e_stbu r5,0x1(r3)   ; .bss zero-fill  0x4000549F..0x4001306B
<loop> e_lbzu/e_stbu       ; .data copy from flash 0x1156BF -> 0x40003A5F..0x40005492
e_bl 0x0002FF70
e_bl 0x0002F12E            ; main()
e_b  0x0010F4A0            ; if main returns, reset
```

**No RTOS signature found.** A string scan for `OSEK`, `AUTOSAR`, `MICROSAR`, `FreeRTOS`, `ERCOSEK`,
`RTA-OS`, `Rte_`, `EcuM`, `Dem_`, `CanIf`, `Os_`, toolchain banners etc. returns **zero hits**
(`work/rke_os_id.py`). Combined with the single-stack startup and the cooperative
init-then-dispatch structure seen throughout (table-driven drivers, a periodic walker for CAN TX),
this is a **bare-metal / static-cyclic-scheduler** design, not a preemptive RTOS with per-task
stacks. That is consistent with the earlier scratch-RAM analysis (`docs/scratch_ram.md`) finding a
single stack at `0x4000CAC8`.

### What this does and does not change

- It **does** correct the record: ~48 KB of bootloader code, the shadow block, and data flash are
  genuinely outside our view, and the BAM is permanently outside anyone's view.
- It **does not** reopen the PI15/PF12 question: the application's own runtime is closed (no calls,
  no vectors into low flash), so any pin servicing that affects normal operation must appear in the
  app — and it does not.
- The one thing that *would* change the picture is if the interior button were handled by the
  **bootloader**, which is implausible (bootloaders do UDS reprogramming, not body functions) and
  would not explain a `0x3A` strobe during normal driving.
- Reading the bootloader would require a **debug-port dump** (JTAG/Nexus) or a Ford `14A073` VBF;
  it cannot be recovered from the files in this repo.

> ### ✅ RESOLVED by the owner full-flash backup — see `docs/owner_backup_analysis.md`
> `backups/owner-backup-20260911T090300Z/` (captured via the SBL + SRAM reader) supplies **all**
> the regions this section listed as unread: the 48 KB PBL, the shadow array and DFlash.
> Result for the pin question: **nothing new enables PI15/PF12.**
> - The PBL is real code with a valid RCHW at `0x0` (entry `0x160`) and identifies itself as
>   `FORD-PBL-V013` / `DV6T-14A073-FK` — confirming this section's inference about part `14A073`.
> - **The PBL references ZERO SIUL pad registers** (it touches only FlexCAN, LINFlex, DSPI, eDMA,
>   ECSM) — it configures no pins at all. Target-register scans for PI15/PF12 PCR/GPDI/GPDO,
>   ADC0 CDR55, both PSMI words and eMIOS_1 CCR25 return **zero hits across PBL + shadow + DFlash**.
> - **DFlash holds no variant coding** — just 32 bytes of EEPROM-emulation wear-level log, retiring
>   the concern below that pin behaviour might be variant-coded in unread data flash.
> - **The MCU is not censored** (`NVPWD0/1`, `NVSCC0/1` all erased), so a JTAG/Nexus dump is
>   available as an independent cross-check, including TestFlash/OTP which the backup skipped.
> - The backup's app region matches OEM `-AD` in all but 5 bytes, none of which lie in the ADC,
>   EIRQ/WKUP, PWM or INTC-vector tables (they select a different gateway calibration record).

## Method + evidence (continued)

4. **The firmware's discrete-GPIO footprint** (pads whose GPDO/GPDI registers appear as
   constants) is **PA5/PA6, PA7/PA8, PB2/PB3, PC6/PC7, PC8/PC9** — five **output+input pairs**, each
   paired in a config descriptor table (`~0x146850`) with a peripheral base in the `0xFFE4_x000` /
   `0xFFE5_0000` range. Those bases are **LINFlex_0..7** (LIN UART controllers) — **confirmed** from
   the ref-manual peripheral memory map (p.76, pdfplumber): `0xFFE4_0000`=LINFlex_0, `+0x4000` each up
   to `0xFFE5_C000`=LINFlex_7. So these pins are **LIN-transceiver enable/status control**, not
   lock-actuator drivers. PI15/PF12 are not among them.
5. **Image coverage — CORRECTED.** An earlier revision claimed the image was "complete, no unmapped
   region". **That was wrong**: it described the *merged file*, which simply starts at `0xC000`.
   Against the real device map, the OEM VBF set leaves several regions unflashed — see §2f.

6. **All three BCM VBFs were checked — including the network/config files.**
   `work/build_image.py` merges *four* regions into `flash_merged.bin`, so every scan above already
   covered the calibration/network VBFs, not just the APP:

   | Region | Source VBF | Contents |
   |---|---|---|
   | `0x0000C000..0x0000FFFF` | **`JV6T-14C095-AB`** | Cal Data F124 (16 KB) |
   | `0x00010000..0x0001001F` | `JV6T-14C094-AD` | RCHW / header |
   | `0x00010020..0x0013FFFF` | `JV6T-14C094-AD` | main application |
   | `0x00140000..0x0015BF4B` | **`JV6T-14C403-AB`** | Cal Config F10A (~112 KB) |

   All blocks re-verified CRC-16 + CRC-32 OK (`work/vbf_crc_validate.py`). Separate scans of F124 and
   F10A find no PI15 GPIO/PCR address, ADC0 CDR55/DMA register address, ADC channel-55 record, or
   pointer to the application's ADC configuration (`work/rke_cal_blocks.py`). The many raw
   `0x00800000` words in those blocks are generic calibration/CAN bit masks; none is consumed as an
   ADC NCMR/JCMR value.

   Importantly, the actual ADC and EIRQ/WKPU tables are **not** in F124/F10A: they are at
   `0x16B28..0x171CF` inside the `JV6T-14C094-AD` application block. `FUN_00032358` passes the
   application-local pointer `0x16B28` directly to `FUN_00039374`; neither network/config VBF can
   substitute another ADC table on this build.

## What this means

- There is **no discrete lock-actuator GPIO pin** driven by this MCU. The firmware's real load
  drivers are **11 eMIOS PWM (OPWMB) channels** (§2e) plus 5 LIN-transceiver control GPDOs; central
  lock is commanded over the bus (MS-CAN `0x3A` lock-command → door-latch modules), exactly as the
  rke-lock mod does. The door lock motors live in the doors, not on a BCM pin. This *validates* the
  CAN-injection design. (If a future task needs a physical load driven, §2e's table is the list of
  candidates — but see its caveat on channel→pad ambiguity.)
- The interior LOCK/UNLOCK buttons are **not read on PI15/PF12 by this firmware**, yet the BCM
  demonstrably reacts to the interior button (`mmcan_ignon_lock_interior_button.log` → `0x3A` strobe).
  Two possibilities remain (need one more datum to decide):
  1. **The traced pins feed a companion device, not the MCU core logic.** e.g. routed to the UJA1078
     SBC (repo `DS_UJA1078A.pdf`) or an analog switch-mux, whose state reaches the BCM another way.
  2. **The pins physically land on the MCU but this firmware variant leaves them unused**, and the
     interior-button lock we observed is actually detected by a door module and relayed over the bus
     (i.e. "wired directly to BCM" was an assumption).

## Recommended next steps (if pursuing the GPIO angle further)

⚠ **Only the bench measurement can still change the answer** — every static route below has been
enumerated and closed (see the status note at the top).

- **Verify on the bench (decisive):** with a multimeter/scope, check whether PI15/PF12 actually
  toggle when the interior button is pressed, and whether they connect to the MCU or to the SBC. If
  they never reach the MCU, the companion-device hypothesis is confirmed and the route is closed
  for good.
- **If a discrete lock trigger is still wanted:** the only firmware-drivable discrete outputs are the
  LIN-control GPDOs (PA5/PA7/PB2/PC6/PC8) — none is a lock relay, so there is nothing simpler than
  the existing `0x3A` bus command to actuate the locks from this MCU.

**Bottom line:** the CAN-injection rke-lock mod is not just *a* way — on this hardware it is
essentially the *only* firmware-side way to actuate the central lock. There is no lock pin to trigger.

Scripts: `work/rke_gpio_raw.py`, `work/rke_siul_map.py`, `work/rke_periph_resolve.py`,
`work/rke_emios.py`, `work/rke_adc.py`,
`work/rke_wkpu_scan.py` (constant-propagating SIUL+WKPU page scan),
`work/rke_wkpu_chans.py` (wakeup-enable callers/channels),
`work/rke_eirq_table.py` (decode the EIRQ/WKUP config table @`0x17050`),
`work/rke_adc2.py` (corrected channel numbering + config table + DMA literals),
`work/rke_adc_ncmr.py` (constant-propagating ADC register resolve incl. DMAE/DMAR),
`work/rke_adc_groups.py` (**decisive** — decode all 7 NCMR/JCMR group masks),
`work/rke_cal_blocks.py` (separate F124/F10A target scan),
`work/rke_ctu.py` (CTU window literal + constant-propagating scan),
`work/rke_ctu_verify.py` (ground-truth disassembly of the CTU accesses),
`work/rke_ctu_events.py` (**decode CTU EVTCFGR events → real ADC channels**),
`work/rke_ctu_rm.py` (RM CTU base + EVTCFGR field layout),
`work/rke_rm_full_map.py` (**RM peripheral memory map + SIUL/PSMI tables** → `work/rm_periph_map.json`),
`work/rke_psmi.py` (**PSMI input-mux audit — PADSEL37/PADSEL51**),
`work/rke_gap_sweep.py` (eMIOS_1 ch25 enable check + full peripheral touch sweep),
`work/rke_outputs.py` (**all SIUL pad literals decoded to pad names + descriptor records**),
`work/rke_dynpad.py` (functions materialising SIUL/eMIOS page bases — finds dynamic drivers),
`work/rke_pwm_table.py` / `work/rke_pwm_pins.py` (locate the PWM config table; eMIOS→pad map),
`work/rke_emios_chans.py` (resolve eMIOS accesses per hardware channel),
`work/rke_pwm_outputs.py` (**decisive — decode the 11 OPWMB output channels + candidate pads**),
`work/rke_boot_coverage.py` (**VBF coverage vs device flash map + RCHW scan**),
`work/rke_boot_path.py` (control transfers / pointers into the un-flashed low 48 KB),
`work/rke_vectors.py` (**decode the 256 INTC vectors as VLE `e_b` branches**),
`work/rke_os_id.py` (RTOS/toolchain string scan + INTC IACKR + startup callees),
`work/rke_backup_analyze.py` (**owner backup: target registers in PBL/shadow/DFlash**),
`work/rke_pbl_deep.py` (**PBL structure, strings, peripheral-page census; shadow NV words**),
`work/rke_backup_diff.py` (backup-vs-OEM per region + the 5 differing app bytes),
`work/rke_rm_regmap.py` (pdfplumber ADC/eDMA register maps from the RM) — all read-only analysis.
