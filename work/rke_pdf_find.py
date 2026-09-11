import pdfplumber, re, sys

RM="/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"

# 1) Peripheral memory map: find pages whose text has 0xFFE4 / 0xC3FA / on-platform peripheral names.
# 2) WKPU wakeup source table: pages mentioning "WKPU" + "NMI" + pad names.
targets_mm = ["0xFFE4", "FFE4_", "FFE44", "FFE48", "FFE4C", "FFE50", "LINFlex", "Peripheral memory map", "SIU_"]
targets_wk = ["WKPU", "NSR", "WISR", "Wakeup", "NMI", "WKPU[", "External wakeup"]

def scan(keys, label, maxpages=8):
    hits=[]
    with pdfplumber.open(RM) as pdf:
        for pi,page in enumerate(pdf.pages):
            t=page.extract_text() or ""
            score=sum(t.count(k) for k in keys)
            if score>0: hits.append((score,pi))
    hits.sort(reverse=True)
    print("=== %s: top pages ===" % label)
    for s,pi in hits[:maxpages]:
        print("  page idx %d (score %d)"%(pi,s))
    return [pi for s,pi in hits[:maxpages]]

mm_pages=scan(targets_mm,"MEMORY MAP")
wk_pages=scan(targets_wk,"WKPU")
print("\nMMPAGES=",mm_pages)
print("WKPAGES=",wk_pages)
