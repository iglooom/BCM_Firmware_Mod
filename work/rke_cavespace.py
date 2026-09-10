import json
img=open("flash_merged.bin","rb").read()
base=0x40000918
print("0x100 RX image: d1=0x%08X (bit7 key-outside), d7=0x%08X (bit0 LOCK), d6=0x%08X (bit2 UB)"%(base+1,base+7,base+6))
b=json.load(open("acc-fix/patch_blobs.json"))
c1,c2=b["c1"],b["c2"]; cave1,cave2=b["cave1"],b["cave2"]
print("acc-fix cave1 @0x%X len=%d end=0x%X"%(cave1,len(c1),cave1+len(c1)))
print("acc-fix cave2 @0x%X len=%d end=0x%X"%(cave2,len(c2),cave2+len(c2)))
p=cave2+len(c2); run=0
while img[p]==0xFF: p+=1; run+=1
print("free 0xFF after cave2: %d bytes (until 0x%X)"%(run,p))
best=[]; start=None
for a in range(0x110000,0x140000):
    if img[a]==0xFF:
        if start is None: start=a
    else:
        if start is not None and (a-start)>=200: best.append((start,a-start))
        start=None
if start is not None and (0x140000-start)>=200: best.append((start,0x140000-start))
print("big 0xFF runs (>=200B) in 0x110000-0x140000:")
for s,l in best[:20]: print("  0x%06X len %d"%(s,l))
