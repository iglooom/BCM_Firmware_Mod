import itertools
frames = {
 "UNLOCK": ["1FE2","1FF2","3FE2","3FF2"],
 "LOCK":   ["1FE1","1FF1","3FE1","3FF1"],
 "RELEASE":["2000"],
 "IDLE":   ["0000"],
}
def word(h6h7): return int(h6h7,16)   # d6<<8 | d7 already given as 4 hex digits

# collect 16-bit d6:d7 words
sets={k:[word(v) for v in vs] for k,vs in frames.items()}

def andall(vs):
    r=0xFFFF
    for v in vs: r&=v
    return r
def orall(vs):
    r=0
    for v in vs: r|=v
    return r

print("=== d6:d7 as 16-bit word (d6 high, d7 low) ===")
for k,vs in sets.items():
    print(f"{k:8s}: "+", ".join(f"0x{v:04X}={v:016b}" for v in vs))

U=sets["UNLOCK"]; L=sets["LOCK"]
print("\n=== within-button variable bits (counter / _UB candidates) ===")
uvar=orall(U)^andall(U); lvar=orall(L)^andall(L)
print(f"UNLOCK varies in bits: 0x{uvar:04X} = {uvar:016b}")
print(f"LOCK   varies in bits: 0x{lvar:04X} = {lvar:016b}")
allvar=uvar|lvar
print(f"toggling bits (both):  0x{allvar:04X} = {allvar:016b}  (positions {[i for i in range(16) if (allvar>>i)&1]})")

print("\n=== stable per-button bits (mask out toggling) ===")
ust=andall(U)&~allvar; lst=andall(L)&~allvar
print(f"UNLOCK stable: 0x{ust:04X} = {ust:016b}")
print(f"LOCK   stable: 0x{lst:04X} = {lst:016b}")
print(f"differ (button identity): 0x{ust^lst:04X} = {(ust^lst):016b}  positions {[i for i in range(16) if ((ust^lst)>>i)&1]}")

print("\n=== interpret as [_UB:1][button:13] in low 14 bits ===")
for k,vs in sets.items():
    for v in vs:
        code=v & 0x1FFF          # low 13 bits = button code
        ub  =(v>>13)&1           # bit13 = _UB (start of field)
        hi  =(v>>14)&3           # top 2 bits (unused?)
        print(f"{k:8s} 0x{v:04X}: _UB(b13)={ub} code13=0x{code:04X}({code}) top2={hi}")
