"""Exhaustive RM extraction to drive a COMPLETE peripheral sweep.

Pulls, from spc560b64x-refmanual.pdf:
  [1] the full peripheral memory map (every base address + peripheral name)
  [2] the complete SIUL register map (to name EVERY SIUL register, notably the
      PSMI "Pad Selection for Multiplexed Input" block, which is the documented
      way a peripheral input can be sourced from a *different* pad - i.e. the
      "via some mux" route)
  [3] any table row naming pad/PCR 143 or 92

Run with python3.14 (pdfplumber). Read-only.
"""
import json
import re
import pdfplumber

RM = "/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"
OUT = "/home/gl/Projects/ford/BCM/Research/work/rm_periph_map.json"

pdf = pdfplumber.open(RM)
print("pages:", len(pdf.pages))

# ---------- [1] peripheral memory map (p76-77 area) ----------------------
print("\n" + "=" * 78)
print("[1] PERIPHERAL MEMORY MAP")
print("=" * 78)
periphs = []
base_re = re.compile(r"0x([0-9A-Fa-f]{4})_([0-9A-Fa-f]{4})")
for pi in range(70, 84):
    p = pdf.pages[pi]
    for tb in p.extract_tables():
        for r in tb:
            cells = [(c or "").replace("\n", " ").strip() for c in r]
            row = " | ".join(cells)
            m = base_re.findall(row)
            if not m:
                continue
            name = cells[-1] if cells else ""
            if not name or name.startswith("0x"):
                for c in reversed(cells):
                    if c and not c.startswith("0x") and not c.isdigit():
                        name = c
                        break
            start = int(m[0][0] + m[0][1], 16)
            end = int(m[1][0] + m[1][1], 16) if len(m) > 1 else None
            periphs.append({"start": start, "end": end, "name": name})
            print("  0x%08X..%s  %s"
                  % (start, ("0x%08X" % end) if end else "?", name))

json.dump(periphs, open(OUT, "w"), indent=1)
print("\n  -> %d entries written to %s" % (len(periphs), OUT))

# ---------- [2] SIUL register map ---------------------------------------
print("\n" + "=" * 78)
print("[2] SIUL REGISTER MAP (look for PSMI / input multiplexing)")
print("=" * 78)
for pi, p in enumerate(pdf.pages):
    t = p.extract_text() or ""
    if "C3F9_0000" not in t:
        continue
    for tb in p.extract_tables():
        rows = []
        for r in tb:
            row = " | ".join((c or "").replace("\n", " ").strip() for c in r)
            if row.strip(" |"):
                rows.append(row)
        if any("Address offset" in r or "Base address" in r for r in rows):
            print("\n---- RM page idx %d ----" % pi)
            for r in rows:
                print("   " + r[:145])

# ---------- [3] PSMI field description ----------------------------------
print("\n" + "=" * 78)
print("[3] PSMI / multiplexed-input description text")
print("=" * 78)
for pi, p in enumerate(pdf.pages):
    t = p.extract_text() or ""
    if "PSMI" not in t and "Multiplexed Input" not in t:
        continue
    hits = [ln for ln in t.split("\n")
            if "PSMI" in ln or "Multiplexed Input" in ln or "PADSEL" in ln]
    if hits:
        print("\n-- page idx %d --" % pi)
        for ln in hits[:14]:
            print("   " + ln[:140])
