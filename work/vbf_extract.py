#!/usr/bin/env python3
import sys, struct, os

def find_header_end(d):
    i = d.find(b'header')
    depth = 0
    j = d.find(b'{', i)
    while j < len(d):
        c = d[j:j+1]
        if c == b'{': depth += 1
        elif c == b'}':
            depth -= 1
            if depth == 0:
                return j+1
        j += 1
    raise ValueError("no header end")

def parse_vbf(path, outdir):
    d = open(path, 'rb').read()
    hend = find_header_end(d)
    # skip whitespace/CRLF after header
    off = hend
    while off < len(d) and d[off] in (0x0d, 0x0a, 0x20, 0x09):
        off += 1
    blocks = []
    p = off
    # data section: [start(4 BE)][len(4 BE)][data][crc16(2 BE)] repeated
    while p + 8 <= len(d):
        start, length = struct.unpack('>II', d[p:p+8])
        # sanity: length must fit and not be absurd
        if length == 0 or p + 8 + length + 2 > len(d) + 0:
            # maybe trailing; break
            if p + 8 + length + 2 > len(d):
                break
        data = d[p+8 : p+8+length]
        crc = struct.unpack('>H', d[p+8+length : p+8+length+2])[0]
        blocks.append((start, length, data, crc))
        p = p + 8 + length + 2
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path))[0]
    print(f"=== {base} : {len(blocks)} block(s), data bytes trailing={len(d)-p}")
    for i,(s,l,data,crc) in enumerate(blocks):
        fn = os.path.join(outdir, f"{base}_blk{i}_0x{s:08X}.bin")
        open(fn,'wb').write(data)
        print(f"  block{i}: start=0x{s:08X} len=0x{l:08X} ({l}) crc16=0x{crc:04X} -> {fn}")
    return blocks

if __name__ == '__main__':
    outdir = sys.argv[2] if len(sys.argv)>2 else 'bins'
    parse_vbf(sys.argv[1], outdir)
