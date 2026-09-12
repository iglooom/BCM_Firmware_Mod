# `peek` — arbitrary memory read over UDS (operator guide)

**Status: BUILT, FLASHED, AND PROVEN on bench #1** (`JV6T-14C094-AD`, serial `009640039386`).

This is the **how-to-use** document. For *why it is built this way* and the evidence chain, see
[`uds_peek_design.md`](uds_peek_design.md). For the older fixed-address alternative, see
[`live_debug_uds.md`](live_debug_uds.md).

---

## 1. What you get

A live debugger for the running application: read **any** memory address while the BCM operates
normally, over ordinary UDS on HS-CAN, with no JTAG and no reflash per experiment.

```
request :  22 DE AD <A3> <A2> <A1> <A0>      (7 bytes, one CAN frame)
response:  62 DE AD <4 bytes read from 0xA3A2A1A0>
```

| property | value |
|---|---|
| service | `0x22` ReadDataByIdentifier, **default session, no `0x27` security** |
| tester → BCM / BCM → tester | `0x726` / `0x72E` on `can0` (HS-CAN, 500 kbit) |
| MAGIC DID | `0xDEAD` |
| bytes per read | **4** (fixed) |
| readable ranges | CFlash `0x00000000..0x0017FFFF`, SRAM `0x40000000..0x40017FFF` |
| out of range | returns `EE EE EE EE` — never dereferences |
| stock behaviour | **unchanged** — any other DID takes the OEM path |

⚠ **Read-only.** The cave contains no store to anything except its own 4-byte scratch cell. There is
no write/poke capability, by design.

---

## 2. Quick start

```bash
cd /home/gl/Projects/ford/BCM/Research && . .venv/bin/activate

# ALWAYS run this first on a fresh session -- see §3
python3 work/bench/peek_read.py accept

# single 4-byte read
python3 work/bench/peek_read.py read 40008E74
#   0x40008E74: 00100000

# hex dump a range
python3 work/bench/peek_read.py dump 40008DE8 48
#   0x40008DE8  00 00 00 00 ...
```

Addresses are hex **without** `0x`. The BCM sleeps; the tool wakes it with ~5 s of `3E 80` keepalive
before every run, so the first read takes a few seconds.

---

## 3. ⚠ Run `accept` first, every session — it is not a formality

`accept` runs four controls and **refuses to endorse the service if any fails**. If it fails, treat
every subsequent reading as void.

| # | control | what it catches |
|---|---|---|
| 1 | two **known-truth** addresses vs the owner backup (`0x000DE278` → `70 E8 E0 00`, `0x00100000` → `E2 2A 48 0C`) | wrong firmware, wrong unit, broken decode |
| 2 | **out-of-range** `0xFFFFFFFF` must return `EE EE EE EE` | the range check silently not firing |
| 3 | `22 0631` still works | the hook displaced OEM behaviour |
| 4 | `22 0631 401B` still works | the multi-DID loop broken by our `r28 += 4` |

Control 1 is the important one: it compares against `backups/owner-backup-*/cflash.bin`, which is
**external ground truth** that no amount of reasoning can distort (AGENTS.md rule 31). A peek service
that returns plausible-looking garbage is far more dangerous than one that is plainly dead.

---

## 4. ⚠ Two traps specific to this tool

### 4.1 A constant reading is NOT evidence the cell is idle (rule 8)

Four SRAM cells sampled 12× over 3 s returned **one distinct value each**. That looks like "nothing
is happening" and is indistinguishable from **a frozen snapshot, a stale cache, or a broken read**.

The control that settles it is **self-referential**: peek the request buffer, whose contents are the
very request doing the peeking.

```bash
python3 work/bench/peek_read.py read 4000538C   # -> 4000A9E2  (request data pointer)
python3 work/bench/peek_read.py read 4000A9E5   # -> 4000A9E5  the value IS the address asked for
python3 work/bench/peek_read.py read 4000A9E6   # -> 00A9E600  the window slides byte-for-byte
```

No cache or snapshot can produce that. Run it whenever you doubt a static-looking result.

### 4.2 Your own receiver will lie to you before the ECU does

Three separate instrument bugs during this work each produced a confident, wrong reading:

- **`drain()` looping until a socket timeout never returns on a live bus** (the BCM transmits
  `0x030`/`0x0C8` every few ms) → reported a **dead ECU** that was answering fine.
- **Unanswered multi-frame replies leave consecutive frames pending**, so the *next* probe reads the
  *previous* answer → six `0x31`/`0x23` probes returned a counter climbing by exactly +20. A
  suspiciously regular series is an instrument artifact until proven otherwise.
- **A `candump` subprocess per read caps at 1.3 Hz**; a persistent `AF_CAN` socket does 100 Hz
  (`live_debug_uds.md` §8.8.1).

`peek_read.py` handles all three (bounded drain, flow control, one persistent socket). If you write
your own client, reproduce them.

---

## 5. Worked uses

```bash
# the whole APP_body_cmd_bus struct in one go (AGENTS.md rule 30)
python3 work/bench/peek_read.py dump 40008DE8 160

# named cells
python3 work/bench/peek_read.py read 40008E74   # APP_req_word_74   (open item 41)
python3 work/bench/peek_read.py read 40002E70   # APP_lock_command
python3 work/bench/peek_read.py read 40008D2C   # the tx_pack_stage cell (rule 14)

# peripheral / verification reads
python3 work/bench/peek_read.py read 000DE278   # flash, cross-checkable vs cflash.bin
```

**Finding an address:** `work/owner/rx_frame_map.json` gives the RAM address of every byte of all 279
RX frames; `did_readers.json` binds each DID to its reader; the Ghidra projects hold the named cells.

---

## 6. How to correlate a peek against the bus (the pattern that matters)

Reading a cell is weak evidence on its own. The strong form is **peek + wire simultaneously**:

1. Poll the cell with `peek_read.py` in a loop.
2. Capture the related CAN frame with `candump` at the same time.
3. Drive a stimulus (`work/bench/rfa_sim.py`, a fob press, an ignition change).
4. Require the two channels to **agree on the transitions**.

Two rules from painful experience: **verify the stimulus actually fired** before recording a
baseline (`live_debug_uds.md` §8.6 — an argparse error made "nothing changed" look like a result),
and **pair events with their nearest neighbour, not the next rising edge**, then re-run at a
different inter-press gap before calling any offset causal (AGENTS.md rule 26).

---

## 7. Rebuilding / porting

| step | script |
|---|---|
| 1. prereqs — pick a MAGIC absent from the DID array, locate the hook | `work/owner/280_peek_build_prereq.py` |
| 2. confirm the carrier on **stock** firmware before building | `work/bench/peek_format_probe.py`, `peek_carrier_probe.py`, `peek_carrier_raw.py` |
| 3. probe assembler spellings against OEM bytes | `work/peek/asm_probe.py` |
| 4. assemble + round-trip the cave | `work/peek/build_cave.py` → `peek_blobs.json` |
| 5. patch the VBF + repair all three integrity layers | `work/peek/build_vbf.py` |
| 6. verify independently from the artifact on disk | `work/peek/verify.py` |
| 7. flash | `work/flash/bcmflash.py flash <vbf> --sbl DV6T-14C097-AB.vbf --execute` |
| 8. accept on hardware | `work/bench/peek_read.py accept` |

**Step 2 is not optional.** The original wire format (`22 <DID> <addr32>` as a trailing-byte
extension) was **refuted 5/5 on stock firmware** before a line of VLE was written — the stock handler
*loops* over DID pairs, so trailing bytes parse as bogus DIDs and earn `7F 22 31`. Skipping that test
would have cost a full 1.2 MiB build-verify-flash cycle to learn the same thing.

**Step 3 saved two more cycles:** `e_cmpli` cannot encode `0xDEAD` (scaled IMM8), and the mnemonic is
`e_cmpl16i.` **with the trailing dot**. Both were settled by reproducing OEM bytes at `0x10B7CC`
(`73DAABFF`) rather than guessing.

### Porting to another firmware version

Every address below is version-specific and must be re-derived (AGENTS.md rule 1):

| what | this build | how to re-derive |
|---|---|---|
| service handler | `FUN_0010B65E` @ `0x10B65E` | SID-climb from the DID-serving chain (`276`) |
| request / response objects | `0x4000538C` / `0x400053A4` | read them out of the handler's decompile (`277`) |
| accessors | `0x1098DE` get-byte, `0x109916` append-byte | decompile them and confirm the struct (`278`) |
| hook site | `0x10B764` (`e_cmpli cr0,r26,0xee00`) | `280` — find the DID-assembly site, note which regs hold DID/len/index |
| rejoin point | `0x10B992` | the stock "DID handled, continue" path |
| cave | `0x118000` | `0xFF` padding **inside** the app block, clear of acc-fix `0x117100`/`0x117300` |
| MAGIC | `0xDEAD` | any 16-bit value absent from the identifier array |

---

## 8. Safety and limits

- **Read-only**; worst realistic failure is a wrong *reading*, not a brick — provided all three
  integrity layers are repaired (`build_vbf.py` does this and `verify.py` re-checks it).
- The range check means a bad address returns `EE EE EE EE` instead of faulting the diagnostic task.
- The BCM boots normally with this build (no safe mode) and all stock DIDs still answer.
- **Do not put this on a vehicle build.** It is a bench debugging instrument.
- **Bench #2 is a different module** (`GV6T-14C094-AJ`) — this VBF does not belong on it
  (AGENTS.md rule 32).

---

## 9. What is NOT established

- **The fob positive control has not been run** — peeking `APP_lock_command` while pressing
  lock/unlock with a simultaneous MS `0x3A` d3 capture. §4.1 proves the read is *live*; it does not
  prove any particular cell *tracks the bus*.
- **No cell has yet been observed changing.** Every value read so far was static in-window.
- Reads are **fixed at 4 bytes**; a length parameter was designed but dropped.
- **Peek rate is unmeasured**, as is whether heavy polling perturbs the behaviour under study.
- The **write/poke** counterpart is designed (`uds_peek_design.md` §4) but **unbuilt** — and it is
  genuinely dangerous, since a wrong store is not a wrong reading.
- `0x31` RoutineControl as an alternative carrier is **INCONCLUSIVE** — the probe that tested it was
  contaminated by stale multi-frame state (§4.2) and was never re-run.
