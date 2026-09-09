import struct, zlib, sys

def find_header_end(d):
    i = d.find(b'header')
    depth = 0; j = d.find(b'{', i)
    while j < len(d):
        c = d[j:j+1]
        if c == b'{': depth += 1
        elif c == b'}':
            depth -= 1
            if depth == 0: return j+1
        j += 1

for path, exp in [("../JV6T-14C094-AD.VBF",0x01D09FC3),
                  ("../JV6T-14C095-AB.VBF",0x8BA612D2),
                  ("../JV6T-14C403-AB.VBF",0xC3A8264A)]:
    d=open(path,'rb').read()
    hend=find_header_end(d)
    off=hend
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    # crc32 over everything from first block addr to end (all block records incl crc16)
    crc = zlib.crc32(d[off:]) & 0xFFFFFFFF
    print(f"{path.split('/')[-1]:20s} file_crc32 calc=0x{crc:08X} expect=0x{exp:08X} {'OK' if crc==exp else 'MISMATCH'}")
