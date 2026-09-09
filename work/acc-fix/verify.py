import os, pyghidra, jpype, struct, zlib, hashlib, re
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
ROOT="/home/gl/Projects/ford/BCM/Research"
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"JV6T-14C094-AD_acc-fix.VBF")
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
d=open(OUT,'rb').read(); he=hdr_end(d); off=he
while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
ds=off;p=off;blocks=[]
while p+8<=len(d):
    s,l=struct.unpack('>II',d[p:p+8])
    if l==0 or p+8+l+2>len(d): break
    blocks.append((s,l,d[p+8:p+8+l],struct.unpack('>H',d[p+8+l:p+8+l+2])[0])); p=p+8+l+2
print("=== integrity ===")
for s,l,data,crc in blocks: print("  blk 0x%06X crc16 %s"%(s,"OK" if crc16(data)==crc else "FAIL"))
fc=int(re.search(rb'file_checksum\s*=\s*0x([0-9A-Fa-f]+)',d[:ds]).group(1),16)
print("  file crc32 %s"%("OK" if fc==(zlib.crc32(d[ds:])&0xFFFFFFFF) else "FAIL"))
appd=[x for s,l,x,c in blocks if s==0x10020][0]; rchw=[x for s,l,x,c in blocks if s==0x10000][0]
flat=bytearray(b'\xFF'*(0x140000-0x10000)); flat[0:len(rchw)]=rchw; flat[0x20:0x20+len(appd)]=appd
st=struct.unpack_from(">H",flat,0x13FFFE-0x10000)[0]
print("  sum8 %s"%("OK" if st==(sum(flat[0:0x13FFFE-0x10000])&0xFFFF) else "FAIL"))

def hook(d1,d5,d6dat,c0,setspd,L):
    # edge-latched model. L: 0=idle,1=Res,2=Plus (persists across frames)
    if d1 & 0x40:
        if L==0:
            L = 1 if ((c0 & 0x48) and setspd!=0) else 2
        d5 |= 0x20 if L==1 else 0x80
        d1 &= ~0x40
    else:
        L = 0
    if d1 & 0x20: d6dat=(d6dat&~0x60)|0x40; d1&=~0x20
    return d1,d5,d6dat,L
print("\n=== single-frame behavior (fresh press, L starts 0) ===")
cases=[("idle",0x00,0x00,0xB3,0x00,0),
       ("RES+ off",0x40,0x00,0xB3,0x00,0),
       ("RES+ CRUISE engaged-not-set",0x40,0x00,0xB3,0x18,0),
       ("RES+ CRUISE active",0x40,0x00,0xB3,0x10,30),
       ("RES+ CRUISE cancel FRESH",0x40,0x00,0xB3,0x40,30),
       ("RES+ CRUISE cancel decayed",0x40,0x00,0xB3,0x18,30),
       ("RES+ LIM engaged-not-set",0x40,0x00,0xB3,0x38,0),
       ("RES+ LIM active",0x40,0x00,0xB3,0x30,30),
       ("RES+ LIM cancel FRESH",0x40,0x00,0xB3,0x48,30),
       ("RES+ LIM cancel decayed",0x40,0x00,0xB3,0x38,30),
       ("LIM press",0x20,0x00,0xB3,0x30,30),
       ("RES+&LIM cruise-cancel",0x60,0x00,0xB3,0x40,30)]
for name,d1,d5,d6,c0,spd in cases:
    a,b,c,_=hook(d1,d5,d6,c0,spd,0)
    print("  %-30s c0=%02X spd=%2d d1=%02X -> d1=%02X d5=%02X d6=%02X | %s"%(
        name,c0,spd,d1,a,b,c,
        ("CC_Res" if b&0x20 else "")+("CC_Set+" if b&0x80 else "")+(" CC_Lim" if (c>>5)&3==2 else "")))

print("\n=== HELD-PRESS regression (the bug): paused-cancel held while PCM resumes mid-press ===")
# Frame stream mimicking candump-2026-09-09_214156: held ResPlus; after ~3 frames PCM 0x38->0x30, spd 0x50->0x55
L=0; out=[]
stream=[(0x40,0x38,0x50),(0x40,0x38,0x50),(0x40,0x38,0x50),  # paused, held
        (0x40,0x30,0x50),(0x40,0x30,0x55),(0x40,0x30,0x55),  # PCM resumed mid-press, still held
        (0x40,0x30,0x55),(0x00,0x30,0x55)]                   # ...released
for i,(d1,c0,spd) in enumerate(stream):
    a,b,c,L=hook(d1,0x00,0xB3,c0,spd,L)
    act="CC_Res" if b&0x20 else ("CC_Set+" if b&0x80 else "-")
    out.append(act)
    print("  frame %d: d1=%02X c0=%02X spd=%2d L=%d -> d5=%02X %s"%(i,d1,c0,spd,L,b,act))
assert all(x in ("CC_Res","-") for x in out), "REGRESSION: emitted Plus during held Resume!"
print("  PASS: held press stayed CC_Res (no Plus bump) despite mid-press 0x38->0x30 decay")

# re-disasm caves from rebuilt image
img=bytearray(b'\xFF'*0x15BF4C); img[0x10000:0x10000+len(rchw)]=rchw; img[0x10020:0x10020+len(appd)]=appd
import pyghidra; pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger
project=GhidraProject.openProject(ROOT+"/ghidra_proj","BCM_C1MCA",False)
program=project.openProgram("/","flash_merged.bin",False)
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
mem=program.getMemory(); listing=program.getListing()
ctxreg=program.getLanguage().getContextBaseRegister(); pc=program.getProgramContext()
JB=jpype.JArray(jpype.JByte)
def jb(bs): return JB([b if b<128 else b-256 for b in bs])
tid=program.startTransaction("v")
try:
    # clear any existing code units in the target ranges FIRST, so setting the VLE
    # context does not conflict with instructions already defined in the saved project
    for lo,hi in ((0x117100,0x117500),(0xFC2C2,0xFC2C6),(0xFC440,0xFC444)):
        listing.clearCodeUnits(A(lo),A(hi-1),False)
    pc.setRegisterValue(A(0x117100),A(0x117500),RegisterValue(ctxreg,BigInteger("20000000",16),BigInteger("FFFFFFFF",16)))
    for lo,hi in ((0x117100,0x117500),(0xFC2C2,0xFC2C6),(0xFC440,0xFC444)):
        mem.setBytes(A(lo),jb(bytes(img[lo:hi])))
    for lo,hi in ((0x117300,0x117420),(0xFC2C2,0xFC2C6),(0xFC440,0xFC444)):
        DisassembleCommand(A(lo),AddressSet(A(lo),A(hi-1)),True).applyTo(program)
    print("\n=== HOOKS ===  %s | %s"%(listing.getInstructionAt(A(0xFC2C2)),listing.getInstructionAt(A(0xFC440))))
    print("=== CAVE2 (walker) full re-disasm from rebuilt image ===")
    for ins in listing.getInstructions(AddressSet(A(0x117300),A(0x11741F)),True):
        print("  %s %s"%(ins.getAddress(),ins))
finally:
    program.endTransaction(tid,False); project.close()

orig=open(ROOT+"/work/backups/JV6T-14C094-AD.VBF.orig_1569cde589ec","rb").read()
ranges=[];i=0
while i<len(orig):
    if orig[i]!=d[i]:
        j=i
        while j<len(orig) and orig[j]!=d[j]: j+=1
        ranges.append((i,j)); i=j
    else: i+=1
merged=[]
for s,e in ranges:
    if merged and s-merged[-1][1]<=8: merged[-1]=(merged[-1][0],e)
    else: merged.append((s,e))
print("\n=== diff vs OEM: %d clusters, %d bytes ==="%(len(merged),sum(e-s for s,e in ranges)))
for s,e in merged: print("  0x%06X..0x%06X (%dB)"%(s,e,e-s))
print("sha256:",hashlib.sha256(d).hexdigest())
