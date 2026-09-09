import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

def parse(start, stop):
    rx={}; tx={}
    a=start
    while a < stop:
        w0=u32(a); w1=u32(a+4)
        if (w0 & 0x3FFFF)==0 and 0 < (w0>>18) <= 0x7FF:
            idv=w0>>18; flag=(w1>>24)&0xFF
            if flag==0x04: rx[idv]=a
            elif flag==0x08: tx[idv]=a
            a+=12
        else:
            break
    return rx,tx

hs_rx,hs_tx = parse(0x146530,0x146900)
ms_rx,ms_tx = parse(0x146950,0x146C50)

def fmt(s): return ", ".join(f"0x{x:03X}" for x in sorted(s))

print("HS RX:",len(hs_rx),"| HS TX:",len(hs_tx),"| MS RX:",len(ms_rx),"| MS TX:",len(ms_tx))

# Same-ID gateway forwarding
hs2ms = sorted(set(hs_rx) & set(ms_tx))   # received on HS, transmitted on MS
ms2hs = sorted(set(ms_rx) & set(hs_tx))   # received on MS, transmitted on HS

print("\n=== HS-CAN -> MS-CAN  (RX@HS & TX@MS, same ID) ===")
for i in hs2ms:
    print(f"  0x{i:03X}   HSrx@0x{hs_rx[i]:06X}  ->  MStx@0x{ms_tx[i]:06X}")
print("count:",len(hs2ms))

print("\n=== MS-CAN -> HS-CAN  (RX@MS & TX@HS, same ID) ===")
for i in ms2hs:
    print(f"  0x{i:03X}   MSrx@0x{ms_rx[i]:06X}  ->  HStx@0x{hs_tx[i]:06X}")
print("count:",len(ms2hs))

# IDs received on HS but NOT re-tx same-ID on MS (candidates for ID-translation, e.g. 0x0C0->0x020)
print("\n=== HS RX ids with NO same-id MS TX (possible translated or BCM-internal) ===")
print(fmt(set(hs_rx)-set(ms_tx)))
print("\n=== MS TX ids with NO same-id HS RX (BCM-originated or translated target, incl 0x020?) ===")
print(fmt(set(ms_tx)-set(hs_rx)))
