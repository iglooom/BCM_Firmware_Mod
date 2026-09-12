#!/usr/bin/env python3
"""Analyse every e_lwz/…/e_stw read-modify-write of struct field +0x94 in the
gate_disasm.txt dump, computing SET and CLEAR masks per site.

Bit numbering: all masks are printed as literal 32-bit hex constants.
PowerPC mb/me are MSB-numbered (bit0 = 0x80000000).  Mask wraps when mb > me.
"""
import re
import sys

SRC = "/home/gl/Projects/ford/BCM/Research/work/rs-trigger/logs/gate_disasm.txt"

LINE = re.compile(r"^([0-9A-F]{6}) (\S+)\s+(\S+)\s+(.*?)\s+; (\S+)$")


def ppc_mask(mb, me):
    """MSB-numbered mask from mb..me inclusive, wrapping if mb > me."""
    m = 0
    if mb <= me:
        for b in range(mb, me + 1):
            m |= 1 << (31 - b)
    else:
        for b in list(range(mb, 32)) + list(range(0, me + 1)):
            m |= 1 << (31 - b)
    return m & 0xFFFFFFFF


def rol32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def parse():
    rows = []
    for ln in open(SRC):
        ln = ln.rstrip("\n")
        m = LINE.match(ln)
        if not m:
            rows.append(None)
            continue
        addr, hexb, mn, ops, fn = m.groups()
        rows.append({
            "addr": int(addr, 16), "hex": hexb, "mn": mn,
            "ops": [o.strip() for o in ops.split(",")] if ops else [],
            "fn": fn, "raw": ln,
        })
    return rows


def num(s):
    s = s.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except Exception:
        return None


def main():
    rows = parse()
    idx = {}
    for i, r in enumerate(rows):
        if r:
            idx[r["addr"]] = i

    # find all stores of 0x94
    stores = [(i, r) for i, r in enumerate(rows)
              if r and r["mn"].endswith("stw") and len(r["ops"]) == 2
              and r["ops"][1].startswith("0x94(")]
    print("== %d store sites to +0x94 ==\n" % len(stores))

    for si, st in stores:
        dst_reg = st["ops"][0]
        base = st["ops"][1][st["ops"][1].index("(") + 1:-1]
        # walk backwards up to 60 instructions within same function, find the
        # e_lwz of 0x94(base) that feeds it
        window = []
        lwz_i = None
        for j in range(si - 1, max(-1, si - 80), -1):
            r = rows[j]
            if r is None:
                continue
            if r["fn"] != st["fn"] and st["fn"] != "UNSWEPT" and r["fn"] != "UNSWEPT":
                pass  # allow: unswept blocks split functions
            window.append(r)
            if r["mn"].endswith("lwz") and len(r["ops"]) == 2 \
               and r["ops"][1] == "0x94(%s)" % base:
                lwz_i = j
                break
        window.reverse()
        print("--- STORE 0x%06X  (%s)  reg=%s base=%s  fn=%s"
              % (st["addr"], st["hex"], dst_reg, base, st["fn"]))
        if lwz_i is None:
            print("    !! no matching e_lwz of 0x94(%s) found within 80 insns"
                  % base)
        setm = 0
        clrm = 0
        notes = []
        # Only consider insns between lwz and stw that write dst_reg
        seq = [r for r in window if lwz_i is not None
               and r["addr"] >= rows[lwz_i]["addr"]]
        for r in seq:
            mn = r["mn"]
            ops = r["ops"]
            if mn in ("e_lwz",):
                continue
            tgt = ops[0] if ops else None
            if mn in ("e_or2i", "e_ori", "e_or2is", "e_oris", "se_or"):
                v = num(ops[-1])
                if v is not None:
                    if mn in ("e_or2is", "e_oris"):
                        v <<= 16
                    notes.append("%06X %s %s -> SET 0x%08X"
                                 % (r["addr"], mn, ",".join(ops), v))
                    if tgt == dst_reg or tgt == rows[lwz_i]["ops"][0]:
                        setm |= v
            elif mn in ("e_andi", "e_and2i", "e_and2is", "e_andis"):
                v = num(ops[-1])
                if v is not None:
                    if mn in ("e_and2is", "e_andis"):
                        v <<= 16
                    notes.append("%06X %s %s -> AND keep 0x%08X"
                                 % (r["addr"], mn, ",".join(ops), v))
            elif mn in ("e_rlwinm", "rlwinm", "e_rlwimi", "rlwimi"):
                # ops: rA, rS, sh, mb, me
                try:
                    sh = num(ops[2]); mb = num(ops[3]); me = num(ops[4])
                except Exception:
                    notes.append("%06X %s %s (unparsed)" % (r["addr"], mn, ops))
                    continue
                mask = ppc_mask(mb, me)
                if mn in ("e_rlwimi", "rlwimi"):
                    notes.append("%06X %-9s %-28s  INSERT dst=%s src=%s "
                                 "sh=%d mb=%d me=%d mask=0x%08X"
                                 % (r["addr"], mn, ",".join(ops), ops[0],
                                    ops[1], sh, mb, me, mask))
                else:
                    notes.append("%06X %-9s %-28s  ROTMASK dst=%s src=%s "
                                 "sh=%d mb=%d me=%d mask=0x%08X %s"
                                 % (r["addr"], mn, ",".join(ops), ops[0],
                                    ops[1], sh, mb, me, mask,
                                    "(CLEAR of 0x%08X)" % ((~mask) & 0xFFFFFFFF)
                                    if sh == 0 else ""))
            elif mn in ("e_li", "se_li", "e_lis", "e_add16i", "se_mr",
                        "e_andc", "se_andc", "e_xori"):
                notes.append("%06X %s %s" % (r["addr"], mn, ",".join(ops)))
            elif mn.startswith("e_b") or mn.startswith("se_b"):
                notes.append("%06X BRANCH %s %s" % (r["addr"], mn, ",".join(ops)))
            elif mn in ("e_cmpi", "e_cmp16i", "se_cmpi", "e_cmpli",
                        "e_cmpl16i", "se_cmp", "se_cmpl", "e_cmph16i"):
                notes.append("%06X CMP %s %s" % (r["addr"], mn, ",".join(ops)))
        for n in notes:
            print("      " + n)
        print()


if __name__ == "__main__":
    main()
