"""Dump the reference-manual peripheral memory map rows around 0xFFE6_xxxx, and
the CTU chapter's register map, to confirm what 0xFFE64000 really is.

The ADC init FUN_0003a402 does:
    e_lis  r7,0xffe6 ; e_lwz r7,0x4000(r7)   -> read  0xFFE64000
    se_bseti r7,0x18 ; e_stw r7,0x4000(r30)  -> write 0xFFE64000
    r4 = r31*4 + 0x4030 + (0xFFE6<<16)       -> 0xFFE64030 + r31*4
and special-cases r31 == 0x17 (23) and r31 == 0x37 (55).

0xFFE64030 is CTU_EVTCFGR0 if the CTU base is 0xFFE64000, so this needs
confirming against the RM rather than assumed. Run with python3.14 (pdfplumber).
"""
import pdfplumber

RM = "/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"
pdf = pdfplumber.open(RM)

print("########## peripheral memory-map rows mentioning 0xFFE6 ##########")
for i, p in enumerate(pdf.pages[:120]):
    t = p.extract_text() or ""
    if "0xFFE6" not in t:
        continue
    for tb in p.extract_tables():
        for r in tb:
            row = " | ".join((c or "").replace("\n", " ").strip() for c in r)
            if "0xFFE6" in row:
                print("  p%-5d %s" % (i, row[:140]))

print("\n########## CTU register map / EVTCFGR field description ##########")
for i, p in enumerate(pdf.pages):
    t = p.extract_text() or ""
    if "EVTCFGR" not in t and "Cross Triggering Unit" not in t:
        continue
    if not any(k in t for k in ("Address offset", "Field", "Base address", "CHANNELVALUE")):
        continue
    print("\n---- RM page idx %d ----" % i)
    for tb in p.extract_tables():
        for r in tb:
            row = " | ".join((c or "").replace("\n", " ").strip() for c in r)
            if row.strip(" |"):
                print("   " + row[:150])
    for ln in (t or "").split("\n"):
        if any(k in ln for k in ("CHANNELVALUE", "TM ", "CLR_FLAG", "ADC_SEL",
                                 "Channel value", "trigger")):
            print("   TXT: " + ln[:140])
