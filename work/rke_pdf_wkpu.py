import pdfplumber
RM="/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"

def dump(pi):
    with pdfplumber.open(RM) as pdf:
        page=pdf.pages[pi]
        print("\n########## PAGE idx %d ##########"%pi)
        tbls=page.extract_tables()
        for ti,tb in enumerate(tbls):
            print("  --- table %d (%d rows) ---"%(ti,len(tb)))
            for r in tb[:60]:
                cells=[ (c or "").replace("\n"," ").strip() for c in r]
                j=" | ".join(cells)
                print("   | "+j)

# WKPU pages: block diagram / external source table live around 268-279
for pi in (268,271,272,273,274):
    dump(pi)
