# JTAG on the Ford BCM (MPC5607B / e200z0) — bring-up, findings, and dead ends

**Status: the JTAG link is fully proven; a debug session is NOT achieved.**
Zero verified memory reads over JTAG after ~10 on-bench power cycles. The working live-RAM
instrument remains the **UDS probe bank on bench #1** (`docs/live_debug_uds.md`).

This document is the consolidated JTAG record. It is organised by *what is true* rather than by the
order things were discovered; §8 lists the wrong turns deliberately, because several were confidently
reasoned and wrong, and the failure modes are reusable.

| | |
|---|---|
| Target | **bench #2** — Ford BCM, MPC5607B (Bolero), e200z0h core, serial `007670223726` |
| Probe | Raspberry Pi Pico 2 (RP2350) running `lonehog/JTAGprobe`, USB `2e8a:000c` |
| Hosts | stock OpenOCD 0.12.0; `calandoa/openocd` xpc56 fork (`work/jtag/openocd-xpc56/`) |
| Reference | e200z0 Core RM (`docs/refs/e200z0.pdf`), NXP AN4365, AN3787 |

> ⚠ **Bench #2 is a hybrid unit**: JV6T application flashed over GV6T calibration and GV6T hardware,
> **partially disassembled, no relays fitted**. Code addresses match the Ghidra DB; *behaviour* is
> not comparable to bench #1, and absent actuation there is not evidence of anything.
> (AGENTS.md rule 32.)

---

## 1. The link is proven

**IDCODE `0x4AE43041`** — `manuf=0x020` (STMicroelectronics, correct for the ST-branded Bolero die),
`part=0xAE43`, `ver=0x4`. OpenOCD independently inferred `irlen 5`, matching the documented MPC560xB
JTAGC instruction register.

Four independent proofs:

1. **Repeatability** — 20/20 identical reads. A floating line does not repeat.
2. **BYPASS shift** — `in 0xA5A5A5A5 → out 0x4B4B4B4A == (in << 1)`. A one-TCK delay through the
   1-bit bypass register; a stuck or disconnected TDO cannot reproduce a shifted pattern.
3. **Clock sweep** — stable at 100 kHz, 500 kHz, 1, 2, 4, 8 and **15 MHz**, 10/10 identical at each.
   Signal integrity is not a constraint.
4. **IDCODE at varying scan lengths** — the strongest test, because ground truth is silicon-defined:
   the low 32 bits must equal `0x4AE43041` at *any* length.

   | scan length | low 32 bits |
   |---|---|
   | 32 / 40 / 64 / 96 / 128 / **192** / 256 | `0x4AE43041` — correct at every length |
   | 192 × 3 repeats | identical each time |

   **10/10 correct, including at exactly the 192-bit CPUSCR width.** The transport is healthy; long
   scans are not corrupted. (`work/jtag/scanlen_idcode.cfg`)

**Wiring is complete.** The MPC5607B data sheet (Rev 10, full text searched) has **0 hits for
`TRST`** and **0 for `JCOMP`** — JTAGC exposes exactly `TDI, TDO, TCK, TMS`. There is no fifth pin to
connect. The only dedicated reset is **`RESET`**, *"Bidirectional … Input weak pull-up after RGM
PHASE2"* (100LQFP pin 17 / 144LQFP 21 / 176LQFP 29 / 208BGA J1). Bidirectional ⇒ the MCU drives it
low itself ⇒ **open-drain is mandatory: assert low, release to high-Z, never drive high.**

(Unrelated but from the same table: TDO wants a 47–100 kΩ pull-up to VDD, else it floats in STANDBY
and wastes current.)

## 2. Censorship is definitively excluded

Measured on **this** device — censorship is a per-device fuse, so bench #1's dump would not have
answered it (AGENTS.md rule 32).

```
0x203DD8  FEEDFACE CAFEBEEF   serial password (public default)
0x203DE0  55AA55AA            NVSCC0
0x203DE4  55AA55AA            NVSCC1
```

Per **AN3787**, `0x55AA_55AA` is the factory value: **not censored — internal flash enabled,
Nexus/JTAG debug enabled, no password required.** Only 17 non-`0xFF` bytes exist in the whole 16 KB
shadow array.

Full verified backup: `backups/bench2-backup-20260912T104909Z/` (`cflash.bin` 1.5 MiB, `shadow.bin`
16 KiB, `dflash.bin` 64 KiB). **Verified against independent ground truth** — both app blocks of
`JV6T-14C094-AD.VBF` match the capture byte-exact, proving the CAN/SBL reader returns real flash.
⇒ JTAG experimentation is low-risk: worst case, reflash from `cflash.bin`.

First direct comparison of the two units: `shadow.bin` **byte-identical**; `cflash.bin` differs by
11,330 bytes (0.72 %, clustered at `0x6B12–0x77EF` and `0xC000–0xF127` = calibration `-AB` vs `-AK`,
plus the `0x13FFFF` sum8 byte); `dflash.bin` differs by 16 bytes (per-unit EEPROM).

## 3. Probe firmware — three real bugs found and fixed

Upstream `lonehog/JTAGprobe` built for Pico 2. Artifacts in `work/jtag/firmware/`.

| bug | effect | fix |
|---|---|---|
| `DAP_SWJ_Pins` indexed `select`/`value` by **RP2350 GPIO number** (14–21) instead of CMSIS-DAP **protocol bit** (0–7) | fields are single bytes, so `select & (1<<16)` never matches ⇒ **`PIN_nRESET_OUT` was unreachable dead code**; readback always `0x00` | use spec bit positions (TCK=0, TMS=1, TDI=2, TDO=3, nTRST=5, nRESET=7) |
| `PIN_nRESET_OUT` ended with the pad an **output in both branches** and never called `gpio_put()` | "release" drove low exactly like "assert" | proper open-drain: drive low / release to high-Z |
| RP2350 pads reset with **`PDE=1`** (pull-down on); `gpio_init()` never clears pulls | "high-Z" still pulled the line **down** against the MCU's weak pull-up | `gpio_set_pulls(pin, true, false)` on release |

Also rebuilt as **CMSIS-DAP v1/HID** (`PROBE_DEBUG_PROTOCOL=1`, `#ifndef`-guarded, one line in
`CMakeLists.txt`) because the xpc56 fork's CMSIS-DAP driver is **HID-only** (2 hidapi calls, 0
libusb) while the stock firmware is **v2/bulk-only** — they physically could not connect.

**Diagnostic worth reusing:** patching `PIN_nRESET_OUT` produced a **byte-identical binary even
after `make clean`**. Only dead code does that — that is what exposed bug #1.

Current firmware: `JTAGprobe-pico2-v1HID-RespLenFix.uf2` (sha256 `c2030a46…`).
Flash: hold BOOTSEL, plug in, copy the `.uf2` to the `RP2350` drive.

## 4. nRESET — works, but is NOT a reliable escape hatch

After the firmware fixes the pin behaves correctly: `0x8F` idle → `0x0F` asserted → `0x8F` released,
stable at +0.01/0.05/0.2/1.0 s.

**A 50 ms pulse recovered a core halted by a bare `init`** — 0 → 14/14 UDS responses, `F188` intact.

**But it does not recover a deep halt.** After any session that ran `mdw` or the CPUSCR/GPR sweep,
pulses of 250 ms / 1 s / 3 s all failed and a **physical power cycle was required** — observed
repeatedly. The pin still measured correctly throughout, so this is not a wiring regression.

> **Operational rule: keep physical power access available before attaching any debugger.**
> Do not rely on nRESET.

⚠ A pin readback of `1` after release does **not** prove a target connection once our own pull-up is
enabled — the probe can read its own output. The *functional* proof (a pulse reviving a halted ECU)
is what counts.

## 5. Host tooling

**Stock OpenOCD 0.12** has **no PowerPC/e200/Nexus target type** (`strings` finds no such driver).
`transport select jtag` gives raw `irscan`/`drscan` only — no halt, registers, memory, breakpoints or
GDB. It *cannot* halt the core, which makes it the safe tool for scan-level experiments.

**`calandoa/openocd`** (`work/jtag/openocd-xpc56/`) adds a real `xpc56` target (e200z0, CPUSCR-based
halt/step/`mdw`). Built with `--enable-cmsis-dap`; uses legacy `interface`/`adapter_khz` syntax
(`adapter driver …` does not exist there). Configs: `work/jtag/xpc56_hid.cfg`.

> ☠ **The fork halts the ECU on `init`.** `xpc56_examine()` calls `xpc56_debug_enter()`, so merely
> *connecting* stops the CPU; its state tracking then makes `resume` a silent no-op
> (`Already running`) and `exit` leaves the core halted. `-c 'init; resume; exit'` cannot help —
> `init` re-halts first. **Never attach it without power access ready.**

**Fork bug fixed here:** `xpc56_e200_ir_rw()` skipped the 10-bit IR scan whenever its cached value
matched. In a read-only session (`val == 0x210` every time) the scan was issued **once and skipped
forever**, so each subsequent 192-bit data scan ran against whatever instruction the hardware had
latched. Now forced every access (`XPC56_CACHE_IR=1` restores the old behaviour). *This was not the
root cause* — data reads stayed zero — but it invalidated everything downstream until fixed.

## 6. Addressing the OnCE TAP

Per **AN4365 Table 2** (explicitly "the same on all MPC56xx devices"):

```
0b10000 = 0x10  ACCESS_AUX_TAP_NPC     (Nexus Port Controller)
0b10001 = 0x11  ACCESS_AUX_TAP_ONCE    (e200 OnCE)
0b10010 = 0x12  ACCESS_AUX_TAP_eTPU
```

**The fork reaches the OnCE TAP; stock OpenOCD does not.** The discriminator is an echo test: a
1-bit BYPASS register returns `(cmd << 1) & 0x3FF`.

| approach | result |
|---|---|
| stock OpenOCD, command shifted via `drscan` | **7 of 8 match the echo prediction** ⇒ pure BYPASS |
| fork, genuine 10-bit `jtag_add_ir_scan` | **0 of 7 match** ⇒ real OnCE access |

Stock OpenOCD re-inserts BYPASS on every scan after the select, because it still manages the chain as
the declared 5-bit JTAGC tap. Only the **first** scan after `irscan 0x11` captures anything real
(`0x001D`, input-independent and repeatable across four selects) — everything after it is echo.

**Constant-bit check (the decisive validator).** RM Figure 8-8 fixes OSR `b8=0, b9=1`. So:

| source | value | verdict |
|---|---|---|
| stock OpenOCD first-capture | `0x001D` | **b9=0 ⇒ cannot be an OSR at all** |
| fork's OnCE IR capture | `0x201` | b9=1, b8=0 ⇒ consistent with the RM |

Apply this check to any claimed OSR before decoding it.

## 7. Where it stands: the core never enters DEBUG mode

**Register layouts (e200z0 RM, authoritative):**

- **OSR** (Figure 8-8, shifted LSB first): `b0 MCLK, b1 ERR, b2 CHKSTOP, b3 RESET, b4 HALT,
  b5 STOP, b6 DEBUG, b7 WAIT, b8=0, b9=1`
- **OCR** (Table 8-9, MSB-first bit numbering): bit29 `WKUP`, bit30 `FDB`, bit31 `DR`
  ⇒ `DR=0x1`, `FDB=0x2`, `WKUP=0x4`

Polling OSR immediately after `xpc56_debug_enter()`, with nothing else happening:

```
poll 0 : osr=0x221  MCLK=1 ERR=0 CHKSTOP=0 RESET=0 HALT=0 STOP=1 DEBUG=0 WAIT=0
poll 1 : osr=0x201  MCLK=1 ERR=0 CHKSTOP=0 RESET=0 HALT=0 STOP=0 DEBUG=0 WAIT=0
poll 2..7 : identical to poll 1
=== DEBUG(b6) 0/8, STOP(b5) 1/8 ===
```

**DEBUG is never set — not once.** The core *stops* but does not enter debug mode. CPUSCR is only
valid in debug mode, which is exactly why every data read returns zeros:

```
CPUSCR WR ir=0x010 : ... f8000958 00000004   <- e_sync        } writes are
CPUSCR WR ir=0x010 : ... 3001a000 00000004   <- e_ori r0      } textbook: the
CPUSCR WR ir=0x010 : ... 33dfa000 00000004   <- e_ori r31     } GPR sweep steps
CPUSCR RD ir=0x210 : 00000000 ×6                              <- ALWAYS zero
```

**The RM-exact sequence also fails.** RM §8.6 step 2 says writing `OCR[DR]|OCR[WKUP]` "places the CPU
in a debug state", and step 3 says verify via OSR *before* setting `DBCR0[EDM]`:

```
=== OCR written = 0x00000005 ===
=== RM step3 (before DBCR0[EDM]): DEBUG(b6) 0/4, osr=0x201 ===
```

A 34-value in-session sweep (`0`, `0x7`, every `1<<b` for b=0..31) gives **DEBUG 0/4 for every
value**. *(Sweeping inside one session was deliberate — each separate `openocd` run leaves the ECU
halted and costs a power cycle; 34 runs would have cost 34 cycles.)*

Note the fork's `OCR=0x7` already contains `DR|FDB|WKUP` and its `DBCR0=0x80000000` is correctly
`EDM`. **The values were never wrong.**

### 7.1 The unresolved contradiction

With the ECU **provably dead on CAN** (0 UDS responses), the fork's genuine OSR reads `0x201` — no
RESET, HALT, STOP, DEBUG, CHKSTOP or ERR, i.e. **a core running normally**. A truly executing core
would keep serving UDS. Both cannot be true.

Two readings:

- **(i)** the core is stopped in a way OSR does not report — e.g. held in reset at chip level with
  `m_clk` still supplied
- **(ii)** OnCE shifts fine, but the CPU status inputs feeding OSR are not valid because
  **`jd_en_once` (RM §8.6 step 1) is not actually asserted** — it is a *signal into the core* driven
  by chip-level logic, not an OnCE register bit. The fork sends OnCE command `0x7E` and assumes that
  suffices.

**(ii) is favoured**: it explains readable-but-stale OSR, plausible bit patterns, and why no OCR
write reaches the core.

### 7.2 Refuted candidates

- **DR-PAUSE teardown** — AN4365 §1.3.2 says the JTAGC reclaims the chain during UPDATE-DR if
  PAUSE-DR was entered, and `xpc56_jtagc_reset()` does exactly `TAP_DRPAUSE → TAP_IDLE`.
  Instrumented: **all invocations occur *after* the poll loop**, never between poll 0 and poll 1
  (`xpc56_jtagc_ir_rw()` early-outs when `jtagc_ir` is already `0x11`). Real mechanism, not the one
  operating here.
- **OCR bit** — refuted twice: by the 34-value sweep, and by the RM showing the fork's value already
  correct.
- **Censorship** — excluded by measurement (§2).
- **Transport / fork's USB driver** — excluded by the IDCODE-length test (§1).

## 8. Wrong turns — four confidently-reasoned, wrong mechanisms

Recorded because the *failure modes* are reusable, and because the pattern is consistent enough to
warrant suspicion of any future "I found it" claim from this line of work.

1. **`out == in << 1` called "invented arithmetic" and retracted.** It was **correct** — the scans
   matched because the chain genuinely *was* in BYPASS, which is what the test detects. The error was
   the *inference* (blaming the fork's driver), not the arithmetic. Retracting a true result to
   protect a false conclusion is its own failure mode.
2. **"The fork's CMSIS-DAP driver corrupts JTAG scans."** Two variables were changed at once (host
   driver *and* probe firmware v2→v1) and the difference attributed to the host. Holding firmware
   fixed and swapping only the host showed **stock OpenOCD failing byte-for-byte identically**.
3. **"The OnCE command/status path works."** Those `0x1D`/`0x04`/`0x24`/`0x20` "status" values were
   the commands shifted back one TCK. The script's own comments flagged the echo risk; the conclusion
   was asserted anyway. (AGENTS.md rule 9.)
4. **"The core enters debug mode, then falls out after one scan."** The polled bit was `BIT(5)` =
   **STOP**, not `BIT(6)` = DEBUG. The `0x221 → 0x201` transition is the core stopping and
   un-stopping; it was never about debug mode.

Common thread: **an unverified bit index or arithmetic prediction, built into a full mechanism before
being checked against the reference manual.** Same family as AGENTS.md rules 21 and 24. Mitigations
now in place — decode every field *by name* in the instrumentation rather than printing a derived
verdict, and apply the constant-bit check (§6) before trusting any register decode.

A fifth, milder case: `0x001D` was decoded as an OSR and used to "retro-explain" the
`0x0D`/`0x1D`/`0xC01D`/`0x07C1C01D` series. The constant-bit check later showed it cannot be an OSR.
That check should have been applied the moment the RM was in hand.

## 9. What is NOT established

- **Any JTAG memory read.** Zero verified, after all of the above.
- Whether `jd_en_once` is asserted on this part, and how a debugger is meant to assert it.
- Why OSR reports a running core while the ECU is dead on CAN (§7.1).
- Whether a watchdog/SWT interferes with debug entry (untested).
- Whether an e200z0-vs-e200z0h difference from the SPC560D/B parts the fork targets is involved.
- What `0x07C1C01D` and the `0x04`/`0x06` DRs are; `0x1059555E` is *assumed* to be a boundary-scan
  snapshot — its layout is unmapped and no BSDL was consulted.

## 10. If this is resumed

1. **Find how MPC560xB asserts `jd_en_once`.** This is the top lead and it is a *chip-level* JTAGC
   detail — look in the **MPC5607B reference manual**, not the e200z0 core RM.
2. Cheap, safe checks first: stock OpenOCD cannot halt the core, so scan-level experiments cost
   nothing. Reserve the fork (and power cycles) for tests that genuinely need a halt.
3. **Acceptance test, fixed and unambiguous:** `mdw 0x000DE278` must return
   `70e8e000 30e719c4 90730143 000470e8` — bytes from the VBF flashed into this unit. Never again
   accept a plausible-looking `0x00000000` from an unvalidated read path.
4. Weigh it against the alternative: the **UDS probe bank** (`docs/live_debug_uds.md`) already
   delivers 17 live RAM cells at ~32 Hz on bench #1 and is proven against the RKE chain. JTAG's
   advantage would be arbitrary addresses without a reflash — real, but not yet obtained.

## 11. File map

| path | purpose |
|---|---|
| `work/jtag/firmware/*.uf2` | probe firmware builds (current: `…RespLenFix.uf2`) |
| `work/jtag/xpc56_hid.cfg` | fork + CMSIS-DAP v1/HID target config |
| `work/jtag/scanlen_idcode.cfg` | IDCODE-at-length transport proof (§1) |
| `work/jtag/once_echo_test.cfg` | BYPASS-echo discriminator (§6) |
| `work/jtag/once_irlen10.cfg` | aux-TAP select / first-capture vs echo (§6) |
| `work/jtag/ocr_sweep.sh` | OCR sweep harness, with a CAN liveness gate between trials |
| `work/jtag/cpuscr_probe.sh` | halt + CPUSCR capture + unconditional nRESET recovery |
| `work/jtag/reset_release.py` | verified nRESET assert/release sequence (§4) |
| `work/jtag/dap_reset_hid.py`, `dap_hid_control.py` | direct CMSIS-DAP pin control / transport check |
| `work/jtag/openocd-xpc56/` | the fork, with the IR-cache fix and instrumentation |
| `work/bench/canchk.sh` | ECU liveness check — the ground-truth instrument for "is it halted" |
| `docs/refs/e200z0.pdf` | e200z0 Core RM (OSR Fig 8-8, OCR Table 8-9, procedure §8.6) |
| `backups/bench2-backup-*/` | verified full backup of this unit |
