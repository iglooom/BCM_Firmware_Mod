"""Extract authoritative ADC / eDMA / DMAMUX register memory maps from the
SPC560B64 reference manual (pdfplumber; pdftotext mangles these tables).

Run with python3.14 (has pdfplumber), NOT the pyghidra venv.
"""
import pdfplumber

RM = "/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"

WANT = {
    "ADC": ["NCMR", "CDR", "DMAE", "CIMR", "Conversion Data Register"],
    "eDMA": ["TCD", "ERQ", "Transfer Control Descriptor", "EDMA"],
    "DMAMUX": ["DMAMUX", "Channel Configuration"],
}

pdf = pdfplumber.open(RM)
print("pages:", len(pdf.pages))

# 1) score pages for each subsystem's register-map table
for subsys, keys in WANT.items():
    cands = []
    for i, p in enumerate(pdf.pages):
        t = p.extract_text() or ""
        if "Address offset" not in t and "Offset" not in t:
            continue
        s = sum(t.count(k) for k in keys)
        if s > 2:
            cands.append((s, i))
    cands.sort(reverse=True)
    print("\n##### %s candidate register-map pages: %s" % (subsys, cands[:8]))

# 2) dump base-address / memory-map rows mentioning our peripherals
print("\n\n########## peripheral base addresses ##########")
for i, p in enumerate(pdf.pages):
    t = p.extract_text() or ""
    if "Base address" not in t:
        continue
    for tb in p.extract_tables():
        for r in tb:
            row = " | ".join((c or "").replace("\n", " ").strip() for c in r)
            if "Base address" in row and any(k in row for k in ("ADC", "DMA", "eDMA")):
                print("  p%-4d %s" % (i, row))
