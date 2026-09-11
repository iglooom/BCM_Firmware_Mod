#!/usr/bin/env python3
"""Build a bounded SRAM-only flash backup reader for the bench BCM.

The first-stage payload reads a compile-time region in 4-byte words and emits
self-indexing raw CAN records on CAN0 ID 0x5A5:
    data[0:4] = absolute source address (big-endian)
    data[4:8] = four source bytes
A final FFFFFFFF#DONE record marks completion. No flash-controller register is
written. The default 0x100-byte range is deliberately small for first hardware
validation.
"""
import argparse
import json
import os

import jpype
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.plugin.assembler import Assemblers
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock
from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PROJECT_DIR = os.path.join(ROOT, "ghidra_proj_sbl")
BASE = 0x40006000
DEFAULT_START = 0x0000C000
DEFAULT_LENGTH = 0x100
CAN_ID_REGISTER = 0x5A5 << 18
MB_INACTIVE = 0x08080000
MB_TX_ONCE_8 = 0x0C480000


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=lambda value: int(value, 0), default=DEFAULT_START)
    parser.add_argument("--length", type=lambda value: int(value, 0), default=DEFAULT_LENGTH)
    parser.add_argument(
        "--service-mode",
        choices=("both", "sbl2", "none"),
        default="both",
        help="helpers called while waiting for TX completion",
    )
    parser.add_argument("--output", default=os.path.join(HERE, "backup_reader_blob.json"))
    return parser.parse_args()


def main():
    args = parse_args()
    if args.start < 0 or args.start > 0xFFFFFFFF:
        raise SystemExit("start must fit in 32 bits")
    if args.length <= 0 or args.length & 3:
        raise SystemExit("length must be positive and 4-byte aligned")
    end = args.start + args.length
    if end > 0x100000000:
        raise SystemExit("range wraps the 32-bit address space")

    project = GhidraProject.openProject(PROJECT_DIR, "SBL", False)
    program = project.openProgram("/", "sbl_merged.bin", False)
    af = program.getAddressFactory().getDefaultAddressSpace()
    address = lambda value: af.getAddress(value)
    assembler = Assemblers.getAssembler(program.getLanguage())
    jbytes = jpype.JArray(jpype.JByte)
    context = AssemblyPatternBlock.fromBytes(0, jbytes([0x20, 0, 0, 0]))

    def assemble_one(at, text):
        return bytes(int(value) & 0xFF for value in assembler.assembleLine(address(at), text, context))

    def make_jbytes(data):
        return jbytes([value if value < 128 else value - 256 for value in data])

    def load_const(register, value):
        value &= 0xFFFFFFFF
        return [f"e_lis {register},0x{value >> 16:04X}", f"e_or2i {register},0x{value & 0xFFFF:04X}"]

    service_lines = {
        "both": ["e_bl 0x40004A24", "e_bl 0x400030DE"],
        "sbl2": ["e_bl 0x400030DE"],
        "none": [],
    }[args.service_mode]

    # r28-r31 are nonvolatile EABI registers and must survive stock helper calls.
    # r30 = current source, r29 = exclusive end, r31 = CAN0 MB0 CS.
    program_lines = [
        "e_bl 0x40004322",
    ]
    if args.service_mode != "none":
        # FUN_400030DE only invokes SBL2 after this OEM main-loop timer
        # is started. FUN_40004322 sets the 10 ms period but does not
        # activate the timer at 0x4000FE04.
        program_lines += [
            "e_lis r3,0x4000",
            "e_or2i r3,0xFE04",
            "e_li r4,0xA",
            "e_bl 0x400049F2",
        ]
    program_lines += [
        *load_const("r30", args.start),
        *load_const("r29", end),
        *load_const("r31", 0xFFFC0080),
        *load_const("r0", MB_INACTIVE),
        "e_stw r0,0x0(r31)",
        *load_const("r0", CAN_ID_REGISTER),
        "e_stw r0,0x4(r31)",
        ("LABEL", "RECORD"),
        "e_lwz r28,0x0(r30)",
        ("LABEL", "WAIT_FREE"),
        *service_lines,
        # Compare only CODE. SRR/IDE/DLC bits may remain changed after TX.
        "e_lbz r0,0x0(r31)",
        "e_li r27,0x08",
        "cmplw r0,r27",
        ("BNE", "WAIT_FREE"),
        "e_stw r30,0x8(r31)",
        "e_stw r28,0xC(r31)",
        *load_const("r0", MB_TX_ONCE_8),
        "e_stw r0,0x0(r31)",
        "e_add16i r30,r30,0x4",
        "cmplw r30,r29",
        ("BNE", "RECORD"),
        ("LABEL", "WAIT_DONE_SLOT"),
        *service_lines,
        "e_lbz r0,0x0(r31)",
        "e_li r27,0x08",
        "cmplw r0,r27",
        ("BNE", "WAIT_DONE_SLOT"),
        *load_const("r0", 0xFFFFFFFF),
        "e_stw r0,0x8(r31)",
        *load_const("r0", 0x444F4E45),
        "e_stw r0,0xC(r31)",
        *load_const("r0", MB_TX_ONCE_8),
        "e_stw r0,0x0(r31)",
        ("LABEL", "WAIT_FINAL"),
        *service_lines,
        "e_lbz r0,0x0(r31)",
        "e_li r27,0x08",
        "cmplw r0,r27",
        ("BNE", "WAIT_FINAL"),
        ("LABEL", "HALT"),
        ("B", "HALT"),
    ]

    labels = {}
    locations = []
    cursor = BASE
    for item in program_lines:
        locations.append(cursor)
        if isinstance(item, tuple):
            if item[0] == "LABEL":
                labels[item[1]] = cursor
            else:
                probe = "e_bne cr0,0x40006000" if item[0] == "BNE" else "e_b 0x40006000"
                cursor += len(assemble_one(cursor, probe))
        else:
            cursor += len(assemble_one(cursor, item))

    blob = bytearray()
    source_listing = []
    for item, at in zip(program_lines, locations):
        if isinstance(item, tuple):
            kind, target = item
            if kind == "LABEL":
                continue
            text = f"e_bne cr0,0x{labels[target]:08X}" if kind == "BNE" else f"e_b 0x{labels[target]:08X}"
        else:
            text = item
        encoded = assemble_one(at, text)
        blob += encoded
        source_listing.append({"address": at, "bytes": encoded.hex().upper(), "instruction": text})

    transaction = program.startTransaction("backup reader roundtrip")
    try:
        listing = program.getListing()
        memory = program.getMemory()
        last = BASE + len(blob) - 1
        listing.clearCodeUnits(address(BASE), address(last), False)
        base_context = program.getLanguage().getContextBaseRegister()
        program.getProgramContext().setRegisterValue(
            address(BASE),
            address(last),
            RegisterValue(base_context, BigInteger("20000000", 16), BigInteger("FFFFFFFF", 16)),
        )
        memory.setBytes(address(BASE), make_jbytes(blob))
        DisassembleCommand(address(BASE), AddressSet(address(BASE), address(last)), True).applyTo(program)
        roundtrip = bytearray()
        print(f"backup reader start=0x{args.start:08X} length=0x{args.length:X} code_len=0x{len(blob):X}")
        for instruction in listing.getInstructions(AddressSet(address(BASE), address(last)), True):
            encoded = bytes(int(value) & 0xFF for value in instruction.getBytes())
            roundtrip += encoded
            print(f"  {instruction.getAddress()} {encoded.hex().upper():12} {instruction}")
        assert bytes(roundtrip) == bytes(blob), "round-trip disassembly did not cover the exact blob"
    finally:
        program.endTransaction(transaction, False)
        project.close()

    result = {
        "address": BASE,
        "code_len": len(blob),
        "source_start": args.start,
        "source_length": args.length,
        "source_end_exclusive": end,
        "service_mode": args.service_mode,
        "can_id": 0x5A5,
        "completion_address": 0xFFFFFFFF,
        "completion_data": "DONE",
        "blob": list(blob),
        "listing": source_listing,
    }
    with open(args.output, "w") as handle:
        json.dump(result, handle, indent=2)
    print("saved", args.output)


if __name__ == "__main__":
    main()
