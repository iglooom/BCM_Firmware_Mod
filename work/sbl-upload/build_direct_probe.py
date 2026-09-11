#!/usr/bin/env python3
"""Assemble direct FlexCAN probe: transmit DUMPTEST as raw CAN ID 0x5A5 from
CAN0 MB0, then halt. Relies only on PBL having left CAN0 initialized at 500 kbps."""
import os,json,pyghidra,jpype
os.environ["GHIDRA_INSTALL_DIR"]="/opt/ghidra"; pyghidra.start()
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
af=program.getAddressFactory().getDefaultAddressSpace(); A=lambda x:af.getAddress(x)
asm=Assemblers.getAssembler(program.getLanguage()); JB=jpype.JArray(jpype.JByte)
CTX=AssemblyPatternBlock.fromBytes(0,JB([0x20,0,0,0]))
def asm1(a,s): return bytes(int(x)&255 for x in asm.assembleLine(A(a),s,CTX))
def jb(b): return JB([x if x<128 else x-256 for x in b])
BASE=0x40006000
P=[
  # Initialize stock SBL timers/SBL2 watchdog callback before a long run.
  "e_bl 0x40004322",
  # r31 = CAN0 MB0 CS @0xFFFC0080
  "e_lis r31,0xFFFC", "e_or2i r31,0x0080",
  # Make MB inactive before touching ID/data.
  "e_lis r0,0x0808", "e_stw r0,0x0(r31)",
  # ID 0x5A5 << 18 = 0x16940000
  "e_lis r0,0x1694", "e_stw r0,0x4(r31)",
  # data = ASCII DUMPTEST
  "e_lis r0,0x4455", "e_or2i r0,0x4D50", "e_stw r0,0x8(r31)",
  "e_lis r0,0x5445", "e_or2i r0,0x5354", "e_stw r0,0xC(r31)",
  # Arm TX: OEM flags 0x08080000 | CODE/SRR 0x04400000 = 0x0C480000.
  "e_lis r0,0x0C48", "e_stw r0,0x0(r31)",
  ("LBL","HALT"), "e_b 0x40006000",
]
# two pass (only halt label)
labels={}; addrs=[]; a=BASE
for it in P:
    if isinstance(it,tuple): labels[it[1]]=a
    addrs.append(a)
    if not isinstance(it,tuple): a+=len(asm1(a,it))
out=bytearray()
for it,a0 in zip(P,addrs):
    if isinstance(it,tuple): continue
    line=f"e_b 0x{labels['HALT']:X}" if it=="e_b 0x40006000" else it
    out+=asm1(a0,line)
# round trip
tid=program.startTransaction("direct probe roundtrip")
try:
    listing=program.getListing(); mem=program.getMemory(); end=BASE+len(out)-1
    listing.clearCodeUnits(A(BASE),A(end),False)
    ctx=program.getLanguage().getContextBaseRegister()
    pc=program.getProgramContext(); pc.setRegisterValue(A(BASE),A(end),RegisterValue(ctx,BigInteger("20000000",16),BigInteger("FFFFFFFF",16)))
    mem.setBytes(A(BASE),jb(out)); DisassembleCommand(A(BASE),AddressSet(A(BASE),A(end)),True).applyTo(program)
    got=b""
    print(f"direct probe len={len(out)}")
    for ins in listing.getInstructions(AddressSet(A(BASE),A(end)),True):
        b=bytes(int(x)&255 for x in ins.getBytes()); got+=b
        print(f"  {ins.getAddress()} {b.hex().upper():12} {ins}")
    assert got==bytes(out)
finally:
    program.endTransaction(tid,False); project.close()
json.dump({"address":BASE,"code_len":len(out),"data_address":0,"blob":list(out)},open(os.path.join(os.path.dirname(__file__),"probe_blob.json"),"w"),indent=2)
print("saved probe_blob.json")
