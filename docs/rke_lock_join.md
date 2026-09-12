# Layer 36 — the RKE→lock join: open item 38 refuted, and the hop relocated

**Scope.** Everything layer 36 established about the last unresolved hop in the RKE chain
(`central_locking_chain.md` §5, open item 38). Image
`backups/owner-backup-20260911T090300Z/cflash.bin`, project `ghidra_proj_fullflash` /
`BCM_OwnerFlash`. Scripts `247`–`256` in `work/owner/`.

> **Confidence:** **(a)** proven — multiple independent methods agree, controls passed;
> **(b)** strong — one controlled method; **(c)** plausible; **(open)** — not established.

---

## 1. Headline

**Open item 38 asked the wrong question, and the answer is a refutation.**

Item 38 read: *"`APP_body_cmd_bus` bits 11..13 → `APP_lock_command`: the last RKE hop —
blocked on a broken decoder."* Layer 36 fixed the decoder, and the fixed decoder shows the
field **does not go there at all**:

| Claim | Status after layer 36 |
|---|---|
| bits 11..13 are "3 write, **0 read**" (`235`) | **FALSE** (a) — decoder bug, as rule 21 predicted. There are 4 writes and **1 read** |
| that field reaches `APP_lock_command` | **FALSE** (a) — its sole reader emits nothing on any path to the lock command |
| the RKE chain joins the lock module through that field | **FALSE** (a) — at bit resolution the two sides share **no bits at all** |

The RKE chain hands off on **`APP_req_word_74` bits 15..20**, not on the command bus. Those
bits have 9 consumer sites image-wide (a). **Which consumer performs the lock actuation
remains open** — see §6, and read §5 before trying to close it, because two plausible-looking
answers were generated and both were destroyed by their own controls.

---

## 2. The decoder, fixed (a)

`235` decoded `rlwinm`/`rlwimi` from `mb`/`me` alone. Three modelling facts it missed, each of
which independently corrupts the result:

1. **Rotate.** `e_rlwinm rD,rS,sh,mb,me` = `ROTL32(rS,sh) & mask(mb,me)`. Ignoring `sh` files
   an insert and the matching extract of the *same* field under *different* ranges — which is
   exactly how a live field came out "write-only".
2. **Wrapping masks.** PowerPC allows `mb > me`; the mask wraps. With `sh=0` the idiom
   `e_rlwinm r0,r0,0x0,0x12,0xe` is a masked **clear** — a WRITE. `248` first read five of
   these as reads of an impossible field "bits 17..13".
3. **RMW shape.** `e_lwz` / `e_rlwimi` / `e_stw` produces **three** reference sites for **one**
   logical access. Keying events by reference site double-counts; and `rlwimi`'s operand[1] is
   the *source*, not the loaded register, so a naive tracker loses the load site entirely.

A fourth trap appeared in `253` and was caught by its own control: crediting a masked clear's
complement to the write-set turns `x &= ~field` (a bulk reset) into a claim on ~28 bits, which
degenerated `APP_req_word_74` to all-32-bits-written. Bulk resets (`> 8` bits) are now tagged
`CLEAR` and excluded from field write-sets.

Decoder controls (`248`, `253`, `254` — all pass):

| Control | Instruction | Must decode as |
|---|---|---|
| C1 | `0x8D56C e_rlwimi r0,r7,0xb,0x12,0x14` | WRITE bits 11..13 |
| C2a | `0x874A6 e_rlwimi r6,r0,0x11,0xc,0xe` | WRITE bits 17..19 |
| C2b | `0x87496 e_rlwinm r0,r0,0xf,0x1d,0x1f` | READ bits 17..19 — **same bucket as C2a** |
| C3 | `0x8B3AC e_rlwinm r0,r0,0x0,0x12,0xe` | WRITE (clear) bits 14..16, **not** a read |

C2 is the one that matters: it is a complementary insert/extract pair on one field, and it is
precisely what `235` could not put in the same bucket.

### 2.1 The field map of `APP_body_cmd_bus` `0x40008E58` (a)

118 distinct field operations from 226 reference sites (29 sites carry no field op; the
mnemonic breakdown is printed by the script, not hidden):

| bits | write | read |
|---|---|---|
| 2..4 | 5 | 2 |
| 5..7 | 12 | 6 |
| 8..10 | 22 | 2 |
| **11..13** | **4** | **1** ← the RKE command field |
| 14..16 | 13 | 2 |
| 17..19 | 6 | 4 |
| 20..23 | 27 | 8 |

---

## 3. The field's one reader, and what it does (a)

Two structurally independent instruments agree, each with a passing positive control:

| Instrument | Principle | Blind where | Result |
|---|---|---|---|
| `248` reference manager | Ghidra xrefs | unswept blocks (layer 33) | reader at `0x8D500` |
| `249` linear sweep | sweeps all **352,906** instructions for the extract idiom `e_rlwinm rD,rS,0x15,0x1d,0x1f`; uses no references, functions or symbols | nothing reference-related | reader at `0x8D500` |

The sweep's positive control (it must find `0x8D500`) passes, so its "only one" is meaningful.

The reader sits in **`FUN_0008D4DA`**, a state machine on the 3-bit command enum:

```c
if (!(APP_req_word_78 >> 9 & 1)) return;
uVar6 = APP_body_cmd_bus >> 0xb & 7;         // <- 0x8D500, the field
switch (uVar6) {
  case 0: case default: APP_body_cmd_bus &= 0xffffc7ff;          break;  // clear field
  case 1:  ... APP_rke_command_code ... -> field = 1 or 3;              // RKE arm
  case 3:  DAT_40002E44 |= 0x40; APP_req_word_74 |= 0x80000;
           DAT_40008DF0 = 0; DAT_40008E46 = DAT_4000588F * 0x32;        // starts a timer
  case 4:  if (APP_req_word_74 >> 0x13 & 1) { ...countdown... }         // runs the timer
}
```

`250` resolved every cell this function writes through `tx_signal_dict.json` +
`net_frame_maps.json`, with a positive control that `APP_lock_command 0x40002E70` **must**
resolve to MS-CAN `0x3A` d3 (it does — the byte `rke-lock` injects into, reproduced
independently):

| cell written | resolves to |
|---|---|
| `0x40002E44` | HS `0x380` d4 · MS `0x1A8` d0 · MS `0x1B0` d2 · MS `0x290` d0 · MS `0x370` d4 |
| `0x40003CE6` | internal state (no pack descriptor) |
| `0x40008DF0`, `0x40008E46` | internal (timer accumulator + limit) |
| `0x40008E58`, `0x40008E74` | the request bus itself |

**Nothing it writes reaches `APP_lock_command`.** It is a *timed* body feature driven by the
command enum — with a duration of `DAT_4000588F × 50`, the shape of a lamp/relay timer — not
the lock actuator.

> ⚠ `250`'s first run used `f.getBody()` and reported only 2 written cells, silently dropping
> the `0x40003CE6` / `0x40002E44` writes the decompiler plainly shows: the Ghidra function body
> does not contain the decompiler-reachable blocks below the entry. Rule 18 — the script now
> scans an explicit address range and **prints both the body extent and the scanned range**.

---

## 4. Where the RKE chain actually hands off (a)

`252` intersected the RKE chain's write-set with the lock-command writers' read-set at **word**
level: 5 shared cells — and all 5 are shared buses of 172–467 references. Rule 9: that is
coverage, not agreement.

`253` repeated it at **bit** level, where a bus becomes discriminating:

| shared word | RKE writes bits | lock writers read bits | overlap |
|---|---|---|---|
| `0x40008E58` `APP_body_cmd_bus` | 11..13 | 2..4 | **none** |
| `0x40008E5C` | 3..4 | — | **none** |
| `0x40008E68` `APP_req_word_68` | 15 | 17, 22 | **none** |
| `0x40008E6C` `APP_req_word_6C` | 20 | 21, 28 | **none** |
| `0x40008E74` `APP_req_word_74` | 15..20 | 10 | **none** |

**0 of 5 words carry a bit-level join** — a clean controlled negative (C2 positive: the RKE
write-set does contain bits 11..13; C3: no cell degenerates to all-32-bits). Note bit 10 of
`req_word_74` is Path A's edge-event bit from layer 33, and it is confirmed *absent* from the
RKE write-set — consistent with layer 35's "the two paths are disjoint".

`254` then swept the full image forward for consumers of the bits the RKE chain **does** write
(positive control: it must find the known reader at `0x8D542`, `e_li r0,0x68000` / `se_and.`;
it does):

| cell | RKE bits | consumer sites |
|---|---|---|
| `0x40008E58` | 11..13 | `0x8D500` |
| `0x40008E5C` | 3..4 | `0x8859C`, `0x8D896`, `0x8F5E8` |
| `0x40008E68` | 15 | `0x87372`, `0x8D942` |
| `0x40008E6C` | 20 | `0x8D690`, `0x8D79A` |
| **`0x40008E74`** | **15..20** | `0x8D542`, `0x884FC`, `0x88598`, `0x88670`, `0x8C4DE`, `0x8D464`, `0x8B3D6`, `0x8D5B0`, `0x8FEE8` |

**None of the 17 consumer sites writes `APP_lock_command` itself.**

---

## 5. ⚠ Two answers generated, two destroyed by their own controls

This is the most transferable part of layer 36. Both candidate answers looked good and both
were wrong; in each case an existing golden rule caught it.

### 5.1 The control-flow climb that saturated (rule 9)

`251` climbed backwards from all 32 `APP_lock_command` writers and reported **27 of 32** as
"RKE in the ancestry". Every one of those hits was via `APP_body_cmd_bus` — a cell with **226
references** spanning the whole body layer. Touching it is true of almost any body function.

Excluding the shared bus and adding a negative control (the acc-fix cruise-status byte
`0x40000707` must *not* appear) flipped the result to **0 of 32** — but 29 of the 32 climbs
hit the block bound, so that zero is a **lower bound, not a negative**, and is recorded as
such. It is also the wrong instrument: layer 35 already proved the two sides are disjoint *in
code*, so they can only be joined by shared RAM.

### 5.2 The forward walk that looked like the answer (rule 9 again)

`255` walked forward from each of the 17 consumer sites to the 32 lock-write sites, with three
passing controls (self-reachability, a cross-block walk reproducing layer 35's 15-block chain,
and a negative from the RX copier). 15 of 17 walks completed. Exactly two reached a lock write:

```
0x8B3D6  APP_req_word_74 bit 17  ->  1 write site   [ 38 blocks, COMPLETE]
0x8FEE8  APP_req_word_74 bit 18  -> 10 write sites  [1201 blocks, PARTIAL]
```

`0x8B3D6` looked like the answer: a tight, complete, 7-instruction path into
`FUN_00087566`'s `APP_lock_command = 3`:

```
0x8b3d6  se_btsti r0,0xe            ; test req_word_74 bit 17
0x8b3d8  e_bne cr0,0x0008b72a
0x8b78a  e_bl 0x00087474
0x87490  se_beq cr0,0x000874c0
0x874d6  se_bne cr0,0x000874e8
0x87506  se_bne cr0,0x00087534
0x8756a  e_stb r0,0x2e70(r6)        ; APP_lock_command = 3
```

**It is not evidence.** `256` ran the identical walker from ten sites with **no** RKE
relationship (RX copier, both acc-fix TX hook sites, `APP_tx_compose`, `APP_rx_unpack_main`, a
DID reader, and four body functions). Three of them reach a lock write too — and
`FUN_00087486` and `FUN_0008B382` reach **`0x8756A`, the very same site**:

```
targets reachable from UNRELATED code (generic, no power): 0x8756a, 0x8b276
```

So reaching `0x8756A` is a generic property of that code region, not an RKE fact. Counting
alone would have missed this: the hit's score (1) *ties* the worst unrelated control (1), and
my first version of the verdict logic printed "SIGNAL" on that tie. The fix is to compare
**which** targets are reached, not how many — a target also reachable from unrelated code has
no discriminating power. `0x8FEE8` is separately inconclusive: its walk hit the bound and
reached 10 targets, the shape of an unbounded sweep.

**Both candidate answers are therefore withdrawn before publication**, and the honest state is
"the consumer set is known, the actuating consumer is not".

---

## 6. What is NOT established

| # | Question | Status |
|---|---|---|
| 38 | ~~bits 11..13 → `APP_lock_command`~~ | **CLOSED by refutation** (a) — the field's sole reader is a timed feature, and the bit-level join is empty |
| 41 | Which of the 9 `req_word_74` bit-15..20 consumers performs the lock | **open** — control-flow reachability is saturated in this region (§5) and cannot answer it |
| 42 | What `FUN_0008D4DA` actually actuates | **open** (c) — timed, duration `DAT_4000588F × 50`; writes `0x40002E44` which packs into 5 frames |
| 43 | Meaning of the individual `req_word_74` bits 15..20 | open — 15, 17, 18 are tested together as `0x68000` at `0x8D542`/`0x884FC` |
| — | `APP_rke_join_gate` `0x40008D3A` | open — read at `0x884E0` and `0x8D526`; only its role as an arm selector is known |

**The method that should close 41 is not a static one.** Every static instrument available in
this region is now either saturated (control flow) or empty (bit-level data flow). Per golden
rule 7, the next step is a **bench/vehicle measurement**: press the fob and watch which of the
9 consumer sites' observable side effects change — or set a breakpoint-equivalent by patching
each candidate and observing MS `0x3A` d3.

---

## 7. Bearing on the shipped mods

**None.** `acc-fix` and `rke-lock` both inject at the FlexCAN TX mailbox, downstream of every
mechanism here, and are indifferent to which request bit actuates the lock. The two absences
that make them safe still hold: HS `0x030` d5 and MS `0x3A` d1 bit 6 have no pack setter
anywhere in the image.

Layer 36 does strengthen one thing: `250`'s control independently re-derives
`APP_lock_command → MS 0x3A d3 → 0x40000A12` from the decoded tables, which is the byte
`rke-lock` writes. That is now a third independent confirmation of that address.

---

## 8. Reproducing

```bash
cd BCM/Research && . .venv/bin/activate
python3 work/owner/247_bus_sites_dump.py          # raw idiom dump, no decode claims
python3 work/owner/248_bus_field_decode_fixed.py  # fixed field decoder, 4 controls
python3 work/owner/249_reader_sweep_and_lockcmd.py # independent sweep + 32 lock writers
python3 work/owner/250_rke_consumer_outputs.py    # consumer outputs -> CAN frames
python3 work/owner/251_lock_rke_ancestry.py       # backward climb (saturated - see §5.1)
python3 work/owner/252_rke_lock_datajoin.py       # word-level join
python3 work/owner/253_rke_lock_bitjoin.py        # bit-level join (the negative)
python3 work/owner/254_rke_bit_consumers.py       # forward bit propagation
python3 work/owner/255_rke_consumer_flow.py       # forward flow walk
python3 work/owner/256_flow_saturation_and_path.py # ⚠ the adjudicator - run this before
                                                   #   believing 255's hits
```

Outputs: `bus_cmd_sites.txt`, `bus_cmd_field.json`, `lockcmd_writers.json`,
`rke_consumer_outputs.json`, `lock_rke_ancestry.json`, `rke_lock_datajoin.json`,
`rke_lock_bitjoin.json`, `rke_bit_consumers.json`, `rke_consumer_flow.json`,
`flow_saturation.json`.
