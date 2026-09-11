import pdfplumber
RM="/home/gl/Projects/ford/BCM/Research/spc560b64x-refmanual.pdf"

def dump_tables(pi, kwfilter=None):
    with pdfplumber.open(RM) as pdf:
        page=pdf.pages[pi]
        tbls=page.extract_tables()
        print("\n########## PAGE idx %d : %d tables ##########"%(pi,len(tbls)))
        for ti,tb in enumerate(tbls):
            # filter rows that mention our interests
            rows=[[ (c or "").replace("\n"," ").strip() for c in r] for r in tb]
            keep=[]
            for r in rows:
                joined=" ".join(r)
                if kwfilter is None or any(k in joined for k in kwfilter):
                    keep.append(r)
            if keep:
                print("  --- table %d ---"%ti)
                for r in keep[:40]:
                    print("   | "+" | ".join(r))

# Memory map page 76: look for peripheral bases incl 0xFFE4x / SIUL / WKPU
dump_tables(76, kwfilter=["FFE4","FFF","C3F","C3FA","LINFlex","SIUL","WKPU","0x"])
