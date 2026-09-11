#!/usr/bin/env python3
"""Assemble a minimal VLE RAM probe at 0x40006000.
It initializes the stock SBL runtime, emits DUMPTEST through its proven PBLD/PBLF
TX primitive, then loops forever. Produces probe_blob.json.
"""
import os, json, pyghidra, jpype
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.app.plugin.assembler import Assemblers
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
project=GhidraProject.openProject(os.path.join(ROOT,"ghidra_proj_sbl"),"SBL",False)
program=project.openProgram("/","sbl_merged.bin",False)
af=program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)
asm=Assemblers.getAssembler(program.getLanguage())
JB=jpype.JArray(jpype.JByte); CTX=AssemblyPatternBlock.fromBytes(0,JB([0x20,0,0,0]))
def asm1(a,line): return bytes(int(x)&0xff for x in asm.assembleLine(A(a),line,CTX))
def jb(bs): return JB([b if b<128 else b-256 for b in bs])

BASE=0x40006000
DATA=0x40006100
P=[
    # Initialize the stock SBL runtime (CAN/PBL callback state, timers, globals).
    "e_bl 0x40004322",
    # Explicitly zero TX primitive state @0x40012AE0.
    "e_lis r31,0x4001", "e_add16i r31,r31,0x2AE0",
    "e_li r0,0", "e_stw r0,0x0(r31)",
    ("LBL","TRY"),
    # Service the same watchdog/timer helpers used by the native readback loop.
    "e_bl 0x40004A24", "e_bl 0x400030DE",
    # tx(state, sequence=0xD001, src=DATA, len=8)
    "se_mr r3,r31",
    "e_li r4,0xD001",
    "e_lis r5,0x4000", "e_or2i r5,0x6100",
    "e_li r6,0x8",
    "e_bl 0x40002F8C",
    "se_cmpi r3,0x0", ("BEQ","TRY"),
    ("LBL","HALT"), "e_b 0x40006032", # replaced after pass with HALT address
]

def ins_size(it,a):
    if isinstance(it,tuple):
        if it[0]=="LBL": return 0
        if it[0]=="BEQ": return len(asm1(a,f"e_beq cr0,0x{a+0x20:X}"))
    return len(asm1(a,it))

# pass 1
addrs=[]; labels={}; a=BASE
for it in P:
    if isinstance(it,tuple) and it[0]=="LBL": labels[it[1]]=a
    addrs.append(a); a+=ins_size(it,a)
end=a
# pass 2
out=bytearray()
for it,a0 in zip(P,addrs):
    if isinstance(it,tuple):
        if it[0]=="LBL": continue
        line=f"e_beq cr0,0x{labels[it[1]]:X}"
    elif it.startswith("e_b 0x40006032"):
        line=f"e_b 0x{labels['HALT']:X}"
    else: line=it
    out+=asm1(a0,line)
# pad to data and append marker
assert BASE+len(out)<=DATA
blob=bytes(out)+bytes(DATA-(BASE+len(out)))+b"DUMPTEST"

# round-trip disassemble code, transaction rolled back
tid=program.startTransaction("probe roundtrip")
try:
    listing=program.getListing(); mem=program.getMemory(); pc=program.getProgramContext()
    code_end=BASE+len(out)-1
    listing.clearCodeUnits(A(BASE),A(code_end),False)
    ctxreg=program.getLanguage().getContextBaseRegister()
    val=RegisterValue(ctxreg,BigInteger("20000000",16),BigInteger("FFFFFFFF",16))
    pc.setRegisterValue(A(BASE),A(code_end),val)
    mem.setBytes(A(BASE),jb(blob))
    DisassembleCommand(A(BASE),AddressSet(A(BASE),A(code_end)),True).applyTo(program)
    got=[]
    print(f"probe code len={len(out)} blob len={len(blob)} end=0x{BASE+len(blob):X}")
    for ins in listing.getInstructions(AddressSet(A(BASE),A(code_end)),True):
        bb=bytes(int(x)&0xff for x in ins.getBytes()); got+=bb
        print(f"  {ins.getAddress()}  {bb.hex().upper():12} {ins}")
    assert bytes(got)==bytes(out), f"roundtrip coverage mismatch {len(got)} != {len(out)}"
finally:
    program.endTransaction(tid,False); project.close()

path=os.path.join(os.path.dirname(__file__),"probe_blob.json")
json.dump({"address":BASE,"code_len":len(out),"data_address":DATA,"blob":list(blob)},open(path,"w"),indent=2)
print("saved",path)
