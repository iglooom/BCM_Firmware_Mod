#!/usr/bin/env python3
"""Exact SET/CLEAR/INSERT mask computation for every read-modify-write of
struct field +0x94 (= 0x40009680).

BIT NUMBERING (stated everywhere, per task requirement):
  * All results are reported as LITERAL 32-bit masks.
  * se_bseti/se_bclri/se_btsti operand N  ->  mask = 1 << (31 - N).
    Verified against Ghidra p-code: INT_RIGHT(0x80000000, N).
  * rlwinm/rlwimi mb/me are MSB-numbered (bit 0 = 0x80000000); the mask is
    bits (31-mb) .. (31-me) and WRAPS when mb > me.
  * e_andi rA,rS,-X as rendered by Ghidra means  rA = rS & ~(X-1)
    (verified: 0x0AD99E `e_andi r0,r0,-0x420001` decompiles to `& 0xffbdffff`).

Method: for each e_stw of 0x94(base), walk backwards to the feeding
e_lwz of 0x94(same base), then forward-simulate the straight-line
instructions in between symbolically as  value = (word & KEEP) | SET,
tracking only the register chain rooted at the loaded register.
The whole e_lwz .. e_stw run is ONE event.
"""
import re
import sys

SRC = "/home/gl/Projects/ford/BCM/Research/work/rs-trigger/logs/gate_disasm.txt"
LINE = re.compile(r"^([0-9A-F]{6}) (\S+)\s+(\S+)\s+(.*?)\s+; (\S+)$")
M = 0xFFFFFFFF

BITS = {
    0x00800000: "0x00800000 (LSB bit23)",
    0x04000000: "0x04000000 (LSB bit26)",
    0x08000000: "0x08000000 (LSB bit27)",
}


def ppc_mask(mb, me):
    m = 0
    rng = range(mb, me + 1) if mb <= me else \
        list(range(mb, 32)) + list(range(0, me + 1))
    for b in rng:
        m |= 1 << (31 - b)
    return m & M


def rol(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & M


def imm(s):
    s = s.strip()
    neg = s.startswith("-")
    v = int(s.lstrip("-"), 16)
    return -v if neg else v


def load():
    rows = []
    for ln in open(SRC):
        m = LINE.match(ln.rstrip("\n"))
        if m:
            a, h, mn, ops, fn = m.groups()
            rows.append({"a": int(a, 16), "h": h, "mn": mn, "fn": fn,
                         "ops": [o.strip() for o in ops.split(",")] if ops
                         else [], "raw": ln.rstrip()})
    return rows


def main():
    rows = load()
    out = []
    for i, r in enumerate(rows):
        if not (r["mn"] in ("e_stw", "se_stw") and len(r["ops"]) == 2
                and r["ops"][1].startswith("0x94(")):
            continue
        dst = r["ops"][0]
        base = r["ops"][1][5:-1]
        # backward search for feeding load
        j = None
        for k in range(i - 1, max(-1, i - 90), -1):
            q = rows[k]
            if q["mn"] in ("e_lwz", "se_lwz") and len(q["ops"]) == 2 \
               and q["ops"][1] == "0x94(%s)" % base:
                j = k
                break
        if j is None:
            out.append((r["a"], r["fn"], None, None,
                        "WHOLE-WORD WRITE (no feeding load found)"))
            continue
        src = rows[j]["ops"][0]
        # symbolic: reg -> (keep, set) meaning value = (word & keep) | set
        # only for regs derived from the loaded word
        st = {src: (M, 0)}
        notes = []
        for k in range(j + 1, i):
            q = rows[k]
            mn, ops = q["mn"], q["ops"]
            if not ops:
                continue
            t = ops[0]
            try:
                if mn in ("se_bseti",) and t in st:
                    b = 1 << (31 - imm(ops[1]))
                    ke, se = st[t]
                    st[t] = (ke & ~b & M, (se | b) & M)
                    notes.append("%06X bseti -> SET 0x%08X" % (q["a"], b))
                elif mn in ("se_bclri",) and t in st:
                    b = 1 << (31 - imm(ops[1]))
                    ke, se = st[t]
                    st[t] = (ke & ~b & M, se & ~b & M)
                    notes.append("%06X bclri -> CLR 0x%08X" % (q["a"], b))
                elif mn in ("e_or2i", "e_ori") and len(ops) >= 2:
                    s2 = ops[1] if len(ops) == 3 else t
                    v = imm(ops[-1]) & M
                    if s2 in st:
                        ke, se = st[s2]
                        st[t] = (ke & ~v & M, (se | v) & M)
                        notes.append("%06X ori -> SET 0x%08X" % (q["a"], v))
                    else:
                        st.pop(t, None)
                elif mn in ("e_or2is", "e_oris") and len(ops) >= 2:
                    v = (imm(ops[-1]) << 16) & M
                    if t in st:
                        ke, se = st[t]
                        st[t] = (ke & ~v & M, (se | v) & M)
                        notes.append("%06X oris -> SET 0x%08X" % (q["a"], v))
                elif mn in ("e_andi", "e_and2i", "se_andi") and len(ops) >= 2:
                    s2 = ops[1] if len(ops) == 3 else t
                    raw = ops[-1].strip()
                    if raw.startswith("-"):
                        keep = (~(imm(raw[1:] if False else raw) * -1 - 1)) & M
                        keep = (~((-imm(raw)) - 1)) & M
                    else:
                        keep = imm(raw) & M
                    if s2 in st:
                        ke, se = st[s2]
                        st[t] = (ke & keep, se & keep)
                        notes.append("%06X andi -> keep 0x%08X (clears 0x%08X)"
                                     % (q["a"], keep, (~keep) & M))
                    else:
                        st.pop(t, None)
                elif mn in ("e_rlwinm", "rlwinm") and len(ops) == 5:
                    sh, mb, me = imm(ops[2]), imm(ops[3]), imm(ops[4])
                    mk = ppc_mask(mb, me)
                    s2 = ops[1]
                    if s2 in st and sh == 0:
                        ke, se = st[s2]
                        st[t] = (ke & mk, se & mk)
                        notes.append("%06X rlwinm sh=0 -> keep 0x%08X "
                                     "(clears 0x%08X)"
                                     % (q["a"], mk, (~mk) & M))
                    else:
                        if s2 in st:
                            notes.append("%06X rlwinm sh=%d EXTRACT mask "
                                         "0x%08X (derived value leaves word)"
                                         % (q["a"], sh, mk))
                        st.pop(t, None)
                elif mn in ("e_rlwimi", "rlwimi") and len(ops) == 5:
                    sh, mb, me = imm(ops[2]), imm(ops[3]), imm(ops[4])
                    mk = ppc_mask(mb, me)
                    # operand[1] is the SOURCE, operand[0] the DESTINATION
                    if t in st:
                        ke, se = st[t]
                        st[t] = (ke & ~mk & M, se & ~mk & M)
                        notes.append("%06X rlwimi INSERT into 0x%08X "
                                     "(src=%s, value data-dependent)"
                                     % (q["a"], mk, ops[1]))
                    else:
                        notes.append("%06X rlwimi into %s (not the word)"
                                     % (q["a"], t))
                elif mn in ("se_mr",) and len(ops) == 2:
                    if ops[1] in st:
                        st[t] = st[ops[1]]
                    else:
                        st.pop(t, None)
                elif mn in ("se_li", "e_li", "e_lis", "se_lbz", "e_lbz",
                            "se_lwz", "e_lwz", "se_lhz", "e_lhz",
                            "se_extzb", "se_srwi", "se_slwi", "cntlzw",
                            "e_xori", "se_bmaski", "e_add16i", "e_addi"):
                    st.pop(t, None)
                elif mn.startswith("e_st") or mn.startswith("se_st") \
                        or mn.startswith("e_b") or mn.startswith("se_b") \
                        or mn.startswith("e_cmp") or mn.startswith("se_cmp"):
                    pass
                else:
                    st.pop(t, None)
            except Exception as e:
                notes.append("%06X UNPARSED %s %s (%s)"
                             % (q["a"], mn, ops, e))
                st.pop(t, None)
        if dst not in st:
            out.append((r["a"], r["fn"], None, None,
                        "value not traceable from loaded reg; notes: "
                        + "; ".join(notes)))
            continue
        keep, setm = st[dst]
        clr = (~keep) & M & (~setm) & M
        ins = (~keep) & M & (~setm) & M  # cleared-or-inserted
        out.append((r["a"], r["fn"], setm, keep, "; ".join(notes)))

    print("=== per-site effect on +0x94 (value = (word & KEEP) | SET) ===\n")
    for a, fn, setm, keep, notes in out:
        if setm is None:
            print("0x%06X %-16s  %s" % (a, fn, notes))
            continue
        clr = (~keep) & M & ~setm & M
        print("0x%06X %-16s KEEP=0x%08X SET=0x%08X  touches=0x%08X"
              % (a, fn, keep, setm, (~keep) & M))
        if notes:
            print("            %s" % notes)
    print("\n\n=== PER-BIT SUMMARY ===")
    for bit, lab in sorted(BITS.items()):
        print("\n---- %s ----" % lab)
        for a, fn, setm, keep, notes in out:
            if setm is None:
                if "WHOLE-WORD" in notes:
                    print("  0x%06X %-16s  BULK: whole-word write (=0), "
                          "clears every bit" % (a, fn))
                continue
            if not ((~keep) & bit):
                continue
            if setm & bit:
                print("  0x%06X %-16s  SET" % (a, fn))
            else:
                print("  0x%06X %-16s  CLEAR  (touched mask 0x%08X)"
                      % (a, fn, (~keep) & M))


if __name__ == "__main__":
    main()
