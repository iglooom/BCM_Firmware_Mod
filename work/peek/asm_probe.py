#!/usr/bin/env python3
"""Probe which VLE compare mnemonics Ghidra's assembler accepts, and prove the
chosen one against OEM bytes.

Two assembler rejections so far, both from guessing a mnemonic/immediate form:
  e_cmpli cr0,r26,0xDEAD  -> scaled IMM8, 0xDEAD not encodable
  e_cmpl16i r26,0xDEAD    -> syntax error (Ghidra spells it with a dot)

AGENTS.md rule 3: assemble ONLY with Ghidra and round-trip every instruction.
The strongest check available is the OEM's own bytes: 0x0010B7CC disassembles
as an arbitrary 16-bit unsigned compare, so whatever mnemonic reproduces THOSE
bytes is the correct spelling.
"""
import os
import sys
import traceback
import pyghidra
import jpype

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.base.project import GhidraProject                       # noqa: E402
from ghidra.app.plugin.assembler import Assemblers                  # noqa: E402
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
OEM_SITE = 0x0010B7CC          # e_cmpl16i. r26,0xf3ff  per the listing

project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj_fullflash"),
                                    "BCM_OwnerFlash", True)
program = None
try:
    program = project.openProgram("/", "cflash.bin", True)
    af = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    mem = program.getMemory()

    def A(x):
        return af.getAddress(x)

    asm = Assemblers.getAssembler(program.getLanguage())
    JB = jpype.JArray(jpype.JByte)
    CTX = AssemblyPatternBlock.fromBytes(0, JB([0x20, 0, 0, 0]))

    ins = listing.getInstructionAt(A(OEM_SITE))
    oem = bytes(x & 0xFF for x in ins.getBytes())
    print("OEM @0x%X : %-28s bytes=%s" % (OEM_SITE, str(ins), oem.hex().upper()))
    print("  (this is ground truth -- the spelling that reproduces it wins)\n")

    cands = [
        "e_cmpl16i. r26,0xf3ff",
        "e_cmpl16i r26,0xf3ff",
        "e_cmpli16i r26,0xf3ff",
        "e_cmpl16i. r26,0xF3FF",
    ]
    good = None
    for c in cands:
        try:
            b = bytes(int(x) & 0xFF for x in asm.assembleLine(A(OEM_SITE), c, CTX))
            ok = (b == oem)
            print("  %-28s -> %s %s" % (c, b.hex().upper(),
                                        "MATCHES OEM" if ok else "(differs)"))
            if ok and good is None:
                good = c
        except Exception as e:
            print("  %-28s -> REJECTED (%s)" % (c, type(e).__name__))

    if not good:
        print("\n!! no candidate reproduced the OEM bytes -- do not proceed")
        sys.exit(1)

    print("\nchosen spelling: %s" % good)
    # now prove it encodes our MAGIC too, at the real cave address
    tmpl = good.split(",")[0]
    for magic in (0xDEAD, 0xBEEF, 0xCAFE):
        line = "%s,0x%04X" % (tmpl, magic)
        try:
            b = bytes(int(x) & 0xFF for x in
                      asm.assembleLine(A(0x00118000), line, CTX))
            print("  %-28s -> %s  (%d bytes)" % (line, b.hex().upper(), len(b)))
        except Exception as e:
            print("  %-28s -> REJECTED (%s)" % (line, type(e).__name__))

    # also settle the other forms the cave needs
    print("\nother forms the cave uses:")
    for line in ("se_mflr r0", "se_mtlr r0", "e_stwu r1,-0x10(r1)",
                 "e_lwz r0,0xC(r1)", "e_add16i r1,r1,0x10",
                 "se_addi r28,0x4", "cmplw r7,r27", "e_lbz r4,0x0(r9)",
                 "e_stb r3,0x0(r4)", "e_lwz r9,0x0(r4)", "e_li r4,0xEE",
                 "e_addi r7,r28,0x6", "se_extzh r4", "e_or2i r7,0x8000"):
        try:
            b = bytes(int(x) & 0xFF for x in
                      asm.assembleLine(A(0x00118000), line, CTX))
            print("  %-28s -> %s" % (line, b.hex().upper()))
        except Exception as e:
            print("  %-28s -> REJECTED (%s)" % (line, type(e).__name__))
except Exception:
    traceback.print_exc()
finally:
    try:
        if program is not None:
            project.close()
    except Exception:
        pass
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)
