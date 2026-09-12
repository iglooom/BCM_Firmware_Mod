# Arbitrary memory read over UDS — design, evidence, and options

**Question:** add a *read arbitrary memory address* capability to the bench BCM for live debugging.

**Answer: yes — a genuine `0x23`-equivalent peek service is buildable in the application, and the
one blocker that previously stopped it (`live_debug_uds.md` §7: "where the app's request buffer is")
is now resolved.** The application's UDS layer passes an inbound-request message object as an
absolute RAM global, with a byte accessor. That is everything a cave needs.

Scripts: `work/owner/272`–`279`. Image/project: `ghidra_proj_fullflash` / `cflash.bin` (whole image).
Prior art this builds on: `docs/live_debug_uds.md` (the 17-probe static bank), `docs/sbl-upload-patch.md`
(SRAM payload execution), `docs/owner_flash_layers.md` §2 (PBL), `docs/scratch_ram.md`.

---

## 1. What already exists (and its ceiling)

| Route | Status | Ceiling |
|---|---|---|
| `0x23` in PBL | **absent** from the 12-entry permission table @`0x43C` and the dispatcher | — |
| `0x23` in SBL | live `7F 23 7F` | — |
| `0x35` upload, SBL | live `7F 35 11`; statically routes to the flash **program** path | — |
| `0x35` upload, PBL | real 32-byte read-out, but `PBL_upload_address_filter` @`0x76EC` vetoes everything outside `0x008000–0x00BFFF` and `0x140000–0x17FFFF` | **application block excluded**; flash only, never SRAM |
| Custom SRAM payload via SBL | **proven on hardware** — read all 1.5 MiB CFlash + shadow + DFlash twice, byte-identical | **the application is not running**; cannot observe live state |
| `probe-bank` (17 static DIDs) | VBF built + verified, not yet flashed | **addresses fixed at flash time**; 1 byte each |

The gap is precise: everything that can read arbitrary memory today either runs **instead of** the
application (SBL payload) or reads a **fixed** address chosen before the flash (probe bank). Live
debugging needs arbitrary address *while the app runs*.

---

## 2. ✅ The blocker is resolved: the request PDU is an absolute global

`docs/live_debug_uds.md` §4 proposed "Option B — point a DID handler at a cave that takes the address
from the request buffer" and recorded the blocker as *"where the inbound request bytes live at that
moment is not established"*. Two facts now settle it, and the first **refutes Option B as framed**.

### 2.1 The DID reader ABI carries no request pointer (272)

`APP_did_read_dispatch` @ `0x107C1A`:

```c
ulonglong APP_did_read_dispatch(uint idx, void *buf, ulonglong len, ulonglong offset)
```

and the per-DID readers below it are `(response_buffer, context)` — e.g. the 14-byte template
`APP_did_did_0631_read(undefined1 *param_1, undefined8 param_2) { *param_1 = DAT_400019C4; }`.
**No parameter is the request.** A DID handler cannot see caller bytes through its own signature.
So Option B is dead *as a DID-handler patch* — but only because there is a better layer.

### 2.2 The service layer holds the request as a global (277, 278)

The application's service handler `FUN_0010B65E` @ `0x10B65E` (1062 bytes, reached from unswept
`0xDE24A`; SID compares for both `0x22` and `0x31`) operates on **two absolute globals**:

| global | role | refs |
|---|---|---|
| `0x4000538C` | **inbound request** message object | 108 |
| `0x400053A4` | **outbound response** message object | 203 |

Decompiling the accessors (278) gives the struct and the complete API:

```
struct uds_msg {              // 0x4000538C = request, 0x400053A4 = response
  +0x00 u32  data;            // byte buffer
  +0x04 u16  len;             // bytes used
  +0x06 u16  cap;             // capacity
  +0x0C u32  flags/state;
};
```

| function | signature | meaning (from the decompile, not guessed) |
|---|---|---|
| `FUN_001098D0` | `(msg) -> u16` | `return msg->len` |
| `FUN_001098DE` | `(msg, i) -> u8` | `i < msg->len ? msg->data[i] : 0` — **request byte accessor** |
| `FUN_00109916` | `(msg, b) -> ok` | append byte, bounds-checked against `cap` — **response emit** |
| `FUN_001098B2` | `(msg, b)` | write byte 0 (the response SID) |
| `FUN_00109AD0` | `(msg)` | reset the object before composing a response |
| `FUN_00109D26` | `(nrc)` | `0x4000ABE8 = nrc` — **set negative response code** |
| `FUN_00109C4C` | `(x)` | `0x4000ABE4 = x` |

`FUN_0010B65E` itself proves the usage pattern, reading the DID out of the request two bytes at a
time exactly the way a peek handler would read an address:

```c
uVar4 = FUN_001098D0(&DAT_4000538C);              // request length
FUN_00109AD0(&DAT_400053A4);                      // begin response
FUN_001098B2(&DAT_400053A4, 0x22);                // positive response SID
sVar6 = FUN_001098DE(&DAT_4000538C, uVar9);       // request byte i
uVar5 = FUN_001098DE(&DAT_4000538C, uVar9 + 1);   // request byte i+1
ppuVar7 = (uVar5 & 0xffff) | (ushort)(sVar6 << 8); // -> the DID
```

**That is a complete, self-contained toolkit for a real peek service**, all at absolute addresses a
VLE cave can reach with `e_lis` + `e_add16i`.

---

## 3. Recommended design — Option C: a true peek handler in a cave

### 3.1 Wire format — ⚠ the first version was REFUTED on the bench

**Original proposal (WRONG, recorded so nobody retries it):**

```
22 <DIDhi> <DIDlo> <A3> <A2> <A1> <A0> [N]     <- trailing-byte extension
```

The assumption was that the stock handler ignores bytes after the DID. `work/bench/peek_format_probe.py`
tested it on **stock** firmware before anything was built: **5/5 REJECTED**, every baseline positive.

| DID | 3-byte baseline | 7-byte extended |
|---|---|---|
| `0x0631` `0x401B` `0x4099` `0x40BE` `0x4125` | POSITIVE | `7F 22 31` requestOutOfRange |

The NRC is the tell: **`0x31` requestOutOfRange, not `0x13` incorrectMessageLength**. It is not a
length check — `FUN_0010B65E` *loops* over the request reading DID pairs (§2.2), so a 7-byte request
is parsed as **three DIDs** (`0x0631`, `0xDEAD`, `0xBEEF`) and refused because `0xDEAD` is not in the
identifier array. The refutation and the decompile agree on mechanism.

**Shipped format — the address rides AS TWO SYNTHETIC DIDs:**

```
request :  22 DE AD <A3> <A2> <A1> <A0>
           (parsed by the stock loop as 3 DIDs: DEAD, A3A2, A1A0)
response:  62 DE AD <4 bytes read from 0xA3A2A1A0>
```

Multi-DID `0x22` is **served** — measured, not assumed (`work/bench/peek_carrier_raw.py`):

```
22 0631            -> 04 62 063100                 1 DID,  1 byte
22 0631 401B 4099  -> 10 0A 62 063100 401B...      3 DIDs, total=10 = 62 + 3x(2+1)
```

`0xDEAD` is absent from the 492-entry identifier array (`280_peek_build_prereq.py`, with 3/3
bench-served DIDs present as a control), so the stock path would refuse it and **no OEM behaviour is
displaced**. Seven request bytes fit one CAN frame exactly (PCI `0x07` + 7).

Also measured: `0x23` is absent on this unit (`23 44 000DE278 04` → `7F 23 7F`, twice), so there is
no collision with a real service.

### 3.2 Cave logic (pseudo-VLE)

```
  len = FUN_001098D0(0x4000538C)
  if (len < 7) goto ORIGINAL                 ; not a peek request -> OEM path
  did = (FUN_001098DE(req,1) << 8) | FUN_001098DE(req,2)
  if (did != MAGIC_DID) goto ORIGINAL        ; only our DID is extended
  addr = bytes 3..6 assembled
  n    = (len >= 8) ? FUN_001098DE(req,7) : 4
  clamp n to <= 32 and to the response object's cap
  FUN_00109AD0(resp); FUN_001098B2(resp, 0x62)
  FUN_00109916(resp, did>>8); FUN_00109916(resp, did&0xFF)
  for i in 0..n-1: FUN_00109916(resp, *(u8*)(addr + i))
  return "handled"
```

Roughly **90–140 bytes** of VLE. No new RAM cell is required (unlike acc-fix's edge latch) because
the whole transaction is stateless within one request.

### 3.3 Resources — all confirmed available (279)

| need | measured |
|---|---|
| cave space | **167,661 contiguous `0xFF` bytes at `0x1170F3`** inside the app block (sum8-covered). acc-fix's caves at `0x117100`/`0x117300` sit inside this run — **place the peek cave well clear, e.g. `0x118000`**, and re-assert the OEM bytes at build time |
| hook site | `0x10B65E` prologue is `se_mflr r0` (2B) + `e_stwu r1,-0x38(r1)` (4B) — a 4-byte `e_b` displaces cleanly if placed at `0x10B660`, replaying the `e_stwu`; or hook the `0x22` branch target inside |
| reach | `e_b` is ±16 MB, in-block always fine |
| globals | `0x4000538C` / `0x400053A4` absolute, `e_lis`+`e_add16i` reachable |

### 3.4 Safety

- **Read-only.** No store outside the response object.
- **Worst case is a bus error**, not a brick — an unmapped address faults the diagnostic task. Bound
  the address to known-good spaces (SRAM `0x40000000..0x40017FFF`, CFlash `0x00000000..0x0017FFFF`,
  DFlash `0x00800000..0x0080FFFF`, peripherals `0xC3F00000+`/`0xFFF00000+`) and return NRC `0x31`
  otherwise. A whitelist is ~20 extra bytes and converts a reset into a clean refusal.
- All three integrity layers must be repaired (`sum8` → CRC-16 → CRC-32); reuse
  `work/acc-fix/build_vbf.py` / `work/probe-bank/build_vbf.py` verbatim.

### 3.5 Why this beats the existing probe bank

| | probe bank | peek handler |
|---|---|---|
| addresses per flash | 17, fixed | **unlimited** |
| bytes per read | 1 | up to ~32 |
| re-target cost | a reflash | a different request |
| code cost | 17 × 4-byte edits | 1 hook + ~1 cave |
| peripheral registers (SIUL/FlexCAN/eMIOS live state) | possible but burns a slot each | **free** |

It also retires several standing open items at once: `req_word_74`, the `0x1E0` enum guard, the
`APP_body_cmd_bus` struct (rule 30 — the *whole* struct at `0x40008DE8` becomes dumpable in one
request instead of four probe slots), and it makes the `0x40008D2C` writer question directly
observable.

---

## 4. A stronger companion: `0x3D`-equivalent poke (optional)

The same accessors give a write primitive for free: `22 <DID> <addr> <n> <bytes>` → store. This turns
the bench BCM into a live patch target — flip a gate cell, force a state, watch the bus — without a
reflash per experiment. It is genuinely dangerous (a wrong store into the FlexCAN region or the
flash controller is not a wrong *reading*), so if built it should be a **separate DID**, clamped to
SRAM only, and never shipped on a vehicle build. Recommend building the read first and proving it.

---

## 5. The SBL / resident-loader idea — analysed, and mostly a dead end

The proposal was: load a custom SBL, make it **resident**, hand control to the application, and use
it as a debug monitor. Three independent facts kill the simple form.

### 5.1 The download window is tiny and the app owns it (275)

`PBL_region_permission_table` @ `0x1C0` permits RAM download **only** into
`0x40002000..0x4000F7FF` (flag 1). Everything else in SRAM is flag 0 = refused. So a resident helper
must live in that 54 KB window.

Measured whether the application avoids the sub-window `0x40002000..0x400039A0` (inside the download
region, outside the documented ECC/zero-init `0x400039A0..0x40014000`):

| scan | flash-origin refs | distinct targets |
|---|---|---|
| **WINDOW `0x40002000..0x400039A0`** | **15,221** | **2,141** |
| positive control `0x40000600..0x40000700` (CAN RX images) | 594 | 98 |

**Refuted, with a passing control.** The application uses that window densely (`0x40002268` alone is
read by `APP_did_prot_C1A1_read` and a dozen others). There is no quiet corner of the download window
for a resident payload; anything parked there is overwritten within milliseconds of app start.

### 5.2 The application and the SBL are mutually exclusive by design

`PBL_boot_mode_arbitration` @ `0x750` either **stays in the loader** (on `0x40013FFC == 0x5555AAAA`)
or boots the app. The SBL is loaded by the PBL, into RAM, as the *replacement* for normal operation —
it is not a co-resident supervisor, and the app's own startup ECC-paints
`0x400039A0..0x40014000` and re-initialises the world. Handing control from a custom SBL to the app
means the app's reset vector runs, which wipes the SBL's state and its stack.

### 5.3 What the SBL route *is* still good for

Not useless — just the wrong tool for *live* debugging:

- **Snapshot debugging.** The proven chain (`docs/sbl-upload-patch.md`) can dump all of SRAM after
  a fault: provoke a condition on the app, then warm-reset into the loader via the now-known handoff
  (`0x40013FFC = 0x5555AAAA`, or the `PBLG` whitelist magics `0xAAE01751` / `0xAAE01741` /
  `0xAADA0100`, plus `0x40000028 = 0x78945612`) — **a warm reset does NOT wipe SRAM** (only a
  power-on does, `owner_flash_layers.md` §2.1). So the app's entire live RAM state survives into a
  loader that can already read and transmit it. That is a genuine **post-mortem core dump**
  capability and it needs **no firmware patch at all**.
- **Flashing the peek build** — which is its normal job.

⚠ The warm-reset-preserves-SRAM claim is inferred from the documented cold/warm discrimination
(`RGM_DES & 0x800B`) and has **not** been tested on the bench. It is the cheapest experiment in this
document and should be run before relying on it: write a pattern into an unused cell, warm-reset into
the loader, dump, compare.

---

## 6. Other options considered

| option | verdict |
|---|---|
| **Add SID `0x23` properly** to the app dispatcher | Possible but strictly worse than §3: needs the service-permission/dispatch table located and edited, plus session/security semantics re-derived. The `0x22`-extension achieves the same with one hook. The 19 `0x23` immediate-compare sites found in `live_debug_uds.md` §2 remain **uncontextualised integers** — not evidence a handler exists (rule 9). |
| **JTAG / Nexus OnCE** | The real debugger, and the right long-term answer — but `docs/jtag_bringup.md` records the fork halting the CPU on `init`, `mdw` returning all-zero, and a deep halt needing a **physical power cycle**. High cost, and it takes the module off the bus, which is exactly what we don't want while watching CAN. Revisit only if a validated probe stack appears. |
| **`0x2E` WriteDataByIdentifier → set a pointer, then `0x22` to read through it** | Would work, but needs the app's *write* dispatcher located; §2.2 makes it unnecessary. |
| **Periodic-task RAM streamer** (cave in the 10 ms task that broadcasts a window on a spare CAN ID) | Complementary, and **better than UDS polling for transients**: `probe_read.py` tops out at 100 Hz host-side, while a TX cave emits at the task rate with no request overhead. Good follow-on once the peek handler proves the cave. |
| **Keep extending the static probe bank** | Cheapest per probe, but 17 fixed bytes; superseded. |

---

## 7. Recommended order of work

1. **Build the peek handler** (§3) against `ghidra_proj/BCM_C1MCA` — the project the shipped VBFs are
   built and verified against (rule 5). Cross-assert every OEM byte from the fullflash addresses
   against the VBF app block first, exactly as `work/probe-bank/build_vbf.py` did (17/17 matched).
2. **Verify** with an independent re-disassembly from the rebuilt image (round-trip every
   instruction; rule 3) and the OEM diff showing only the expected clusters.
3. **Acceptance test on the bench, positive control first.** Peek `0x40002E70` (`APP_lock_command`)
   while pressing lock/unlock and simultaneously capture MS `0x3A` d3 — *the same cell on the wire*.
   If peek and bus disagree, the build is void and nothing else it returns may be believed. This is
   the same discipline as `probe_read.py control`, and §8.6/§8.8.1 of `live_debug_uds.md` are the
   record of what happens without it.
4. Then a **negative control**: peek an address whose content is known from the owner backup
   (`cflash.bin`) — e.g. `0x000DE278` should return `70 E8 E0 00`. Ground truth that no reasoning can
   distort (rule 31).
5. Only then use it for the open items.

---

## 9. ✅ BUILT, FLASHED, AND PROVEN ON THE BENCH

Artifact: **`work/peek/JV6T-14C094-AD_peek.VBF`**
sha256 `7b9ff1add5ba7250c58a330aee8ca8a5df35a43d4f91acda5a74a2adff1994fe`

### 9.1 What shipped

| item | value |
|---|---|
| hook | `0x0010B764`, 4 B: `e_cmpli cr0,r26,0xee00` → `e_b 0x00118000` |
| cave | `0x00118000`, **438 B**, 113 instructions |
| MAGIC DID | `0xDEAD` (absent from the identifier array) |
| scratch | `0x40011010..13` (clear of acc-fix `0x40011000` / rke-lock `0x40011001`) |
| integrity | sum8 `0x7572 → 0x5EE6`, CRC-16 `0xC08F`/`0x52E7`, CRC-32 `0x6D35C1FB` |

At the hook `r26` = assembled DID, `r27` = request length, `r28` = byte index. On a non-match the
cave replays the displaced compare and returns to `0x10B768` (stock behaviour untouched); on a match
it reads the address, range-checks it, appends the bytes via `FUN_00109916`, advances `r28` by 4 to
consume the two synthetic DIDs, and rejoins the stock continue path at `0x10B992`.

### 9.2 Static verification (`work/peek/verify.py`) — ALL PASSED

Re-reads the artifact **from disk**, and the decisive check writes the file's bytes into a scratch
program and reconstructs the behaviour from **Ghidra's decode**, not from the bytes we wrote:

| check | result |
|---|---|
| both block CRC-16, file CRC-32, internal sum8, guard half-word | PASS |
| diff vs OEM | **19 clusters, 19 explained** (hook + cave + sum8) |
| hook decodes as `e_b 0x00118000` | PASS |
| exactly 4 request-byte reads / 10 response appends | PASS |
| reads `0x4000538C`, writes `0x400053A4`, rejoins `0x10B992` | PASS |
| no store outside the scratch cell (read-only) | PASS |

### 9.3 Flash (bench #1, identity READ not inferred — rule 32)

`22 F188` = **`JV6T-14C094-AD`**, serial `009640039386` — the part this VBF targets (bench #2 is
`GV6T-14C094-AJ` / `007670223726`). 11 erase regions, 1.2 MiB written; both transfer-exit responses
echoed the VBF's own CRC-16 (`77 C08F`, `77 52E7`). **The BCM booted and serves DIDs — no safe mode**,
so the three-layer integrity repair held.

### 9.4 Acceptance on the flashed unit (`work/bench/peek_read.py accept`) — PASSED

```
peek 0x000DE278 -> 70 E8 E0 00    owner backup: 70 E8 E0 00   ✓
peek 0x00100000 -> E2 2A 48 0C    owner backup: E2 2A 48 0C   ✓
peek 0xFFFFFFFF -> EE EE EE EE    range check fired, no dereference
22 0631          -> 62 063100     stock single-DID intact
22 0631 401B     -> 62 063100 401B00   stock multi-DID intact
```

Two **independent** known-truth addresses, checked against `backups/.../cflash.bin` — ground truth
external to the tool, so this cannot be self-confirmation (rule 31).

### 9.5 ⚠ Liveness needed a better control than "does the value change?"

Sampling four SRAM cells 12× over 3 s gave **1 distinct value each**. Per rule 8 that is *suspect*,
not proof of idle cells — a frozen snapshot would look identical. The decisive control is
**self-referential**: peek the request buffer itself, whose contents are *this very request*.

```
req obj 0x4000538C +0x00 -> 4000A9E2   (data pointer)
peek 0x4000A9E5          -> 4000A9E5   <- the value IS the address asked for
peek 0x4000A9E6          -> 00A9E600   <- window slides byte-for-byte
peek 0x4000A9E7          -> A9E70000
```

The buffer held `22 DE AD 40 00 A9 E5`, i.e. the request's own address field. A cached or stale read
cannot produce this. **The peek reads current RAM.**

### 9.6 Live cells now readable

```
0x40008DE8  the APP_body_cmd_bus struct (rule 30) — whole struct in one dump
0x40008E74  APP_req_word_74 = 00100000   (open item 41)
0x40002E70  APP_lock_command = 00001F00
```

### 9.7 Still NOT established

- **The lock/unlock positive control has not been run** — peeking `APP_lock_command` while pressing
  the fob and capturing MS `0x3A` d3 simultaneously, to confirm probe and wire agree on a *changing*
  cell. §9.5 proves the read is live; it does not prove this cell tracks the bus.
- All four cells read so far were **static during the sample window**; none has been observed to change.
- Reads are fixed at **4 bytes**; the `[N]` length byte in §3.1's original sketch was dropped.
- Peek rate under load, and whether heavy polling perturbs behaviour, is unmeasured.
- The **poke** (write) variant of §4 remains unbuilt.

### 9.8 Superseded — §8's open items, resolved

The list below was written *before* the build. Retained for history; §9.7 is the live list.

- ~~**Nothing has been built or flashed.**~~ → built, flashed, accepted (§9.1–9.4).
- ~~The **exact hook point** inside `FUN_0010B65E` is not chosen.~~ → `0x10B764`, the `0xEE00`
  compare, with `r26`/`r27`/`r28` identified (`280_peek_build_prereq.py`).
- ~~Whether the response object's **capacity** admits the extra bytes.~~ → it does; multi-frame
  replies carrying 3 DIDs were observed on the wire.
- ~~Whether `FUN_001098DE` is reached with the request already **consumed/advanced**.~~ → it is not;
  byte index 3 is still the 4th request byte, proven by §9.5.
- Still open from §8: **warm-reset SRAM retention (§5.3) is inferred, not measured.**

---

## 8. What was NOT established *before the build* (historical)
- **Nothing has been built or flashed.** §3 is a design derived from static evidence; every address
  in it is from `ghidra_proj_fullflash` and must be re-asserted against the VBF app block.
- The **exact hook point** inside `FUN_0010B65E` is not chosen — `0x10B660` is a candidate from the
  prologue, but the branch that actually handles a served DID (versus the `0xEE00` / `0xF200..0xF400`
  special ranges visible in the decompile) has not been isolated.
- `FUN_0010B65E`'s **caller is an unswept block** (`0xDE24A`), so its invocation context — which
  session/protocol states reach it — is not mapped.
- Whether the response object's **capacity** at `+0x06` admits 32 payload bytes in the default
  session is unread; ISO-TP multi-frame is presumed but unverified for this path.
- Whether `FUN_001098DE` is reached with the request object already **consumed/advanced** by the time
  a peek handler runs (i.e. whether byte index 3 is still the 4th request byte at that point).
- **Warm-reset SRAM retention (§5.3) is inferred, not measured.**
- Whether peeking at >10 Hz **perturbs** the behaviour under study (same caveat as the probe bank).
- The `0x2E`/poke variant (§4) is a sketch; its dispatcher has not been located.
