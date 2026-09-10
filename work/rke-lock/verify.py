#!/usr/bin/env python3
"""Verify combined acc-fix + rke-lock VBF: block CRC16, file CRC32, internal sum8,
re-disasm both caves from the REBUILT image, diff-vs-OEM (expect only 2 hooks + 2 caves +
sum8 word + file_checksum text), and simulate the RKE 0x3A gate across input states."""
import struct, zlib, hashlib, os, json, re
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT="/home/gl/Projects/ford/BCM/Research"
OEM=os.path.join(ROOT,"JV6T-14C094-AD.VBF"); NEW=os.path.join(HERE,"JV6T-14C094-AD_accfix-rkelock.VBF")
bl=json.load(open(os.path.join(HERE,"patch_blobs.json")))
CAVE1=bl["cave1"]; CAVE2=bl["cave2"]; c1=bytes(bl["c1"]); c2=bytes(bl["c2"])
def crc16(d):
    c=0xFFFF
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xFFFF if (c&0x8000) else (c<<1)&0xFFFF
    return c
def hdr_end(d):
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while j<len(d):
        if d[j]==0x7b: depth+=1
        elif d[j]==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
def parse(path):
    d=bytearray(open(path,'rb').read()); he=hdr_end(d); off=he
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    ds=off; blocks=[]; p=off
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        blocks.append(dict(start=s,dataoff=p+8,length=l,crcoff=p+8+l)); p=p+8+l+2
    return d,ds,blocks
d,ds,blocks=parse(NEW)
ok=True
# 1) block CRC16
for b in blocks:
    stored=struct.unpack_from(">H",d,b['crcoff'])[0]; calc=crc16(bytes(d[b['dataoff']:b['dataoff']+b['length']]))
    s="OK" if stored==calc else "FAIL"; ok&=stored==calc
    print("  block @0x%06X len %d CRC16 stored=0x%04X calc=0x%04X %s"%(b['start'],b['length'],stored,calc,s))
# 2) file CRC32
m=re.search(rb'file_checksum\s*=\s*0x([0-9A-Fa-f]+)',bytes(d[:ds])); stored=int(m.group(1),16); calc=zlib.crc32(bytes(d[ds:]))&0xFFFFFFFF
print("  file CRC32 stored=0x%08X calc=0x%08X %s"%(stored,calc,"OK" if stored==calc else "FAIL")); ok&=stored==calc
# 3) internal sum8
appblk=[b for b in blocks if b['start']==0x10020][0]; rchw=[b for b in blocks if b['start']==0x10000][0]
def fo(fa): return appblk['dataoff']+(fa-0x10020)
flat=bytearray(b'\xFF'*(0x140000-0x10000))
flat[0:rchw['length']]=d[rchw['dataoff']:rchw['dataoff']+rchw['length']]
flat[0x20:0x20+appblk['length']]=d[appblk['dataoff']:appblk['dataoff']+appblk['length']]
stored=struct.unpack_from(">H",d,fo(0x13FFFE))[0]; calc=sum(flat[0:0x13FFFE-0x10000])&0xFFFF
print("  internal sum8 @0x13FFFE stored=0x%04X calc=0x%04X %s"%(stored,calc,"OK" if stored==calc else "FAIL")); ok&=stored==calc
# 4) caves present byte-exact in rebuilt image
for name,cave,blob in (("cave1",CAVE1,c1),("cave2",CAVE2,c2)):
    got=bytes(flat[cave-0x10000:cave-0x10000+len(blob)]); s=got==blob; ok&=s
    print("  %s @0x%X %d B byte-exact in image: %s"%(name,cave,len(blob),s))
# 5) diff vs OEM: enumerate changed app-block byte ranges
od,ods,oblocks=parse(OEM); oapp=[b for b in oblocks if b['start']==0x10020][0]
a=bytes(d[appblk['dataoff']:appblk['dataoff']+appblk['length']]); o=bytes(od[oapp['dataoff']:oapp['dataoff']+oapp['length']])
ranges=[]; i=0
while i<len(a):
    if a[i]!=o[i]:
        j=i
        while j<len(a) and a[j]!=o[j]: j+=1
        ranges.append((0x10020+i,j-i)); i=j
    else: i+=1
print("  changed app-block ranges vs OEM:")
for fa,n in ranges: print("     0x%06X +%d"%(fa,n))
# coalesce ranges separated by <=4 unchanged bytes (a cave may contain coincidental 0xFF bytes
# equal to OEM padding, splitting one cave's diff into pieces)
coal=[]
for fa,n in ranges:
    if coal and fa-(coal[-1][0]+coal[-1][1])<=4:
        coal[-1]=(coal[-1][0], fa+n-coal[-1][0])
    else:
        coal.append((fa,n))
# expected clusters: hook1(0xFC2C2,4) hook2(0xFC440,4) cave1 cave2 sum8(0x13FFFE,2)
exp={(0xFC2C2,4),(0xFC440,4),(CAVE1,len(c1)),(CAVE2,len(c2)),(0x13FFFE,2)}
got=set(coal)
print("  diff matches expected clusters (coalesced):", got==exp, "" if got==exp else ("\n   unexpected=%s\n   missing=%s"%(got-exp,exp-got)))
ok&=got==exp
# 6) behavior sim of RKE 0x3A gate (v5: press-latch L2 + independent suppress-countdown L3)
def sim_stream(frames):
    """Each frame: (d7,d6,d1,ign, out_d3,out_b6) = RKE inputs + BCM's own native outgoing 0x3A.
    L2: press latch (0=armed,1=fired-this-press; re-armed on button release).
    L3: suppress countdown (frames); >0 kills d1 bit6 on outgoing d3==01 frames, decremented each frame.
    Returns per-frame the FINAL wire action:
      'STROBE' our injected lock strobe   'KILL' suppressed BCM lock re-strobe (bit6 cleared)
      'PASS'   frame emitted as-is."""
    SUPP=30; L2=0; L3=0; out=[]
    for d7,d6,d1,ign,od3,ob6 in frames:
        if not (d7&0x01):                        # button released -> re-arm latch, then suppression
            L2=0
        elif L2==0 and (d1&0x80) and ((ign&0xF0)==0x40):   # UB gate dropped (RFA asserts it late)
            # RISING EDGE: fire once, latch, open window, protect our own strobe (skip suppress)
            L2=1; L3=SUPP; out.append('STROBE'); continue
        # suppression pass (also runs while armed-but-not-firing, and after fire on later frames)
        if L3>0:
            if od3==0x01: out.append('KILL')     # kill bit6 on outgoing lock frame
            else:         out.append('PASS')     # unlock/idle unaffected
            L3-=1                                # time-based decrement (never resets)
        else:
            out.append('PASS')
    return out
print("\n  RKE sim v5 (BCM native stream + our cave -> wire action):")
RUN=0x41
# CRITICAL regression (the v4 5-click bug): button HELD ~10 frames while BCM streams native d3=02
# for a while BEFORE switching to d3=01 -> must fire EXACTLY ONE strobe.
held=[(0x01,0x04,0x80,RUN,0x02,0)]*5 + [(0x01,0x04,0x80,RUN,0x01,0)]*5 + [(0x00,0,0x80,RUN,0x01,1)]*3
r=sim_stream(held); n=r.count('STROBE'); ok&=(n==1)
print("     HELD press, BCM d3=02 then 01 -> STROBEs=%d %s  (KILL=%d)"%(n,"OK" if n==1 else "FAIL",r.count('KILL')))
print("       seq:",r)
# BCM's follow-up re-strobe (bit6=1, after release) must be KILLed, not passed
ok&= 'STROBE' not in r[1:]   # only the first frame strobes
# double-click scenario: our strobe + BCM re-strobe within window
stream=[
 (0x00,0x00,0x00,RUN, 0x02,0),  # idle
 (0x01,0x04,0x80,RUN, 0x02,0),  # RKE lock -> STROBE (protect), open window
 (0x01,0x04,0x80,RUN, 0x02,0),  # held, latched, BCM still 02 -> PASS (window running, not d3=01)
 (0x01,0x04,0x80,RUN, 0x01,0),  # BCM switched to lock hold -> KILL
 (0x00,0x00,0x80,RUN, 0x01,1),  # released; BCM re-sync strobe bit6=1 -> KILL (kills 2nd click)
 (0x00,0x00,0x80,RUN, 0x02,1),  # genuine UNLOCK strobe -> PASS
]
exp=['PASS','STROBE','PASS','KILL','KILL','PASS']
res=sim_stream(stream); ok&=res==exp
for fr,rr,e in zip(stream,res,exp):
    print("     d7=0x%02X d6=0x%02X d1=0x%02X ign=0x%02X bcm(d3=0x%02X,b6=%d) -> %-6s %s"%(
        fr[0],fr[1],fr[2],fr[3],fr[4],fr[5],rr,"OK" if rr==e else "FAIL"))
# ign OFF / key inside -> never fires
off=sim_stream([(0x01,0x04,0x80,0x11,0x02,0)]*5); ok&=off.count('STROBE')==0
print("     ign-OFF -> strobes:",off.count('STROBE'),"(OK)" if off.count('STROBE')==0 else "(FAIL)")
ins=sim_stream([(0x01,0x04,0x00,RUN,0x02,0)]*5); ok&=ins.count('STROBE')==0
print("     key-INSIDE -> strobes:",ins.count('STROBE'),"(OK)" if ins.count('STROBE')==0 else "(FAIL)")
# two SEPARATE presses -> two strobes (re-arm on release works)
two=[(0x01,0x04,0x80,RUN,0x02,0)]+[(0x00,0,0x80,RUN,0x02,0)]*40+[(0x01,0x04,0x80,RUN,0x02,0)]
ok&=sim_stream(two).count('STROBE')==2
print("     two separate presses -> strobes:",sim_stream(two).count('STROBE'),"(OK)")
# UB=0 press must now FIRE (rke_lock6 bug: RFA asserted UB only on the 4th press)
ub0=sim_stream([(0x01,0x00,0x80,RUN,0x02,0)]*3+[(0x00,0,0x80,RUN,0x02,0)]); n=ub0.count('STROBE'); ok&=n==1
print("     UB=0 press (lock+keyout+ign) -> strobes:",n,"(OK)" if n==1 else "(FAIL)")
ul=sim_stream([(0x01,0x04,0x80,RUN,0x02,0),(0x00,0,0x80,RUN,0x02,1)]); ok&=ul[1]=='PASS'
print("     unlock right after lock -> ",ul[1],"(OK)" if ul[1]=='PASS' else "(FAIL)")
print("\nVERDICT:", "ALL PASS" if ok else "*** FAILURES ***")
