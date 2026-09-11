"""Trace whether PI15 can be consumed through ADC0_S[23].

Read-only Ghidra analysis. PI15 has ADC0_S[23], absolute ADC channel 55,
as its only plausible non-GPIO input alternate function.
"""
import os
import struct
from collections import defaultdict

import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
IMAGE = ROOT + "/work/flash_merged.bin"
ADC0 = 0xFFE00000
ADC1 = 0xFFE04000
ADC_SIZE = 0x4000
ADC0_NCMR0 = ADC0 + 0xA4
PI15_ABS_CHANNEL = 32 + 23
ADC0_CDR55 = ADC0 + 0x180 + 4 * (PI15_ABS_CHANNEL - 32)
DEFAULT_CONFIG = 0x16B28

raw = open(IMAGE, "rb").read()
print("image bytes:", len(raw))
print("PI15 alternate analog input: ADC0_S[23] = absolute channel 55")
for name, value in (
    ("ADC0 base", ADC0),
    ("ADC0 NCMR0", ADC0_NCMR0),
    ("ADC0 CDR0", ADC0 + 0x100),
    ("ADC0 CDR55", ADC0_CDR55),
):
    pattern = struct.pack(">I", value)
    offsets = []
    start = 0
    while True:
        offset = raw.find(pattern, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    print("%-12s 0x%08X: %s" % (name, value, [hex(x) for x in offsets]))

# FUN_00039374 installs this default ADC configuration when passed NULL.
# Its compact header contains three flash pointers followed by counts.  The
# channel configuration array has six-byte records: channel, ADC instance,
# and four bytes of per-channel settings consumed by FUN_00039d72.
unit_configs, group_configs, channel_configs = struct.unpack_from(
    ">III", raw, DEFAULT_CONFIG
)
group_count, channel_count, unit_count = struct.unpack_from(
    ">BBB", raw, DEFAULT_CONFIG + 0xC
)
print("\n=== default ADC configuration @0x%X ===" % DEFAULT_CONFIG)
print(
    "unit_cfg=0x%X group_cfg=0x%X channel_cfg=0x%X "
    "groups=%d channels=%d units=%d"
    % (
        unit_configs,
        group_configs,
        channel_configs,
        group_count,
        channel_count,
        unit_count,
    )
)
configured_channels = defaultdict(list)
for index in range(channel_count):
    offset = channel_configs + index * 6
    channel, unit = struct.unpack_from(">BB", raw, offset)
    settings = raw[offset + 2 : offset + 6]
    configured_channels[unit].append(channel)
    print(
        "  rec[%02d] @0x%X: ADC%d channel %d (0x%02X), settings=%s"
        % (index, offset, unit, channel, channel, settings.hex())
    )
print(
    "configured ADC0 channels:",
    configured_channels[0],
    "-- channel 55 / PI15 present:",
    PI15_ABS_CHANNEL in configured_channels[0],
)

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", True)
try:
    listing = program.getListing()
    functions = program.getFunctionManager()
    memory = program.getMemory()
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    def address(value):
        return address_space.getAddress(value)

    def read_u32(value):
        try:
            buf = bytearray(4)
            memory.getBytes(address(value), buf)
            return int.from_bytes(bytes(buf), "big")
        except Exception:
            return None

    def registers(insn):
        return [
            insn.getRegister(index)
            for index in range(insn.getNumOperands())
            if insn.getRegister(index)
        ]

    def scalar(insn):
        result = None
        for index in range(insn.getNumOperands()):
            if insn.getScalar(index) is not None:
                result = insn.getScalar(index)
        return result

    loads = {"e_lbz", "e_lhz", "e_lwz", "lbz", "lhz", "lwz", "se_lwz", "se_lbz", "se_lhz"}
    stores = {"e_stb", "e_sth", "e_stw", "stb", "sth", "stw", "se_stw", "se_stb", "se_sth"}
    indexed = {
        "e_lbzx", "lbzx", "e_lhzx", "lhzx", "e_lwzx", "lwzx",
        "e_stbx", "stbx", "e_sthx", "sthx", "e_stwx", "stwx",
    }
    accesses = defaultdict(list)
    indexed_bases = []

    for function in functions.getFunctions(True):
        values = {}
        for insn in listing.getInstructions(function.getBody(), True):
            mnemonic = insn.getMnemonicString()
            try:
                if mnemonic in ("e_lis", "lis"):
                    dest = insn.getRegister(0)
                    immediate = insn.getScalar(1)
                    if dest and immediate is not None:
                        values[dest.getName()] = (immediate.getUnsignedValue() & 0xFFFF) << 16
                elif mnemonic in ("e_li", "li", "se_li"):
                    dest = insn.getRegister(0)
                    immediate = insn.getScalar(1)
                    if dest and immediate is not None:
                        values[dest.getName()] = immediate.getSignedValue() & 0xFFFFFFFF
                elif mnemonic in ("e_add16i", "e_addi", "addi", "se_addi"):
                    regs = registers(insn)
                    immediate = scalar(insn)
                    if regs and immediate is not None:
                        dest = regs[0].getName()
                        source = regs[1].getName() if len(regs) > 1 else dest
                        if source in values:
                            values[dest] = (values[source] + immediate.getSignedValue()) & 0xFFFFFFFF
                        else:
                            values.pop(dest, None)
                elif mnemonic in ("e_or2i", "oris", "ori"):
                    dest = insn.getRegister(0)
                    immediate = scalar(insn)
                    if dest and immediate is not None and dest.getName() in values:
                        values[dest.getName()] |= immediate.getUnsignedValue()
                elif mnemonic in indexed:
                    regs = registers(insn)
                    known = [(reg.getName(), values.get(reg.getName())) for reg in regs]
                    for register, value in known:
                        if value is not None and ADC0 <= value < ADC1 + ADC_SIZE:
                            indexed_bases.append(
                                (str(insn.getAddress()), function.getName(), mnemonic, register, value)
                            )
                elif mnemonic in loads | stores:
                    base = None
                    displacement = 0
                    for operand in range(insn.getNumOperands()):
                        objects = list(insn.getOpObjects(operand))
                        regs = [obj for obj in objects if obj.__class__.__name__.endswith(".Register")]
                        scalars = [obj for obj in objects if obj.__class__.__name__.endswith(".Scalar")]
                        if regs and scalars:
                            base = regs[0].getName()
                            displacement = scalars[0].getSignedValue()
                        elif regs and operand > 0 and base is None:
                            base = regs[0].getName()
                    if base in values:
                        effective = (values[base] + displacement) & 0xFFFFFFFF
                        if ADC0 <= effective < ADC1 + ADC_SIZE:
                            accesses[function.getEntryPoint().getOffset()].append(
                                (str(insn.getAddress()), mnemonic, effective)
                            )
                        if mnemonic in loads:
                            dest = insn.getRegister(0)
                            word = read_u32(effective)
                            if dest is not None:
                                if word is not None and (word >> 24) in (0xC3, 0xFF):
                                    values[dest.getName()] = word
                                else:
                                    values.pop(dest.getName(), None)
            except Exception:
                pass

    print("\n=== statically resolved ADC accesses ===")
    for entry, items in sorted(accesses.items()):
        print("FUN_%08X" % entry)
        for site, mnemonic, effective in items:
            print("  @%s %-8s 0x%08X (+0x%03X)" % (site, mnemonic, effective, effective & 0x3FFF))
    if not accesses:
        print("  (none)")

    print("\n=== indexed ADC accesses with a statically known ADC base ===")
    for site, function, mnemonic, register, value in indexed_bases:
        print("  @%s [%s] %s base %s=0x%08X" % (site, function, mnemonic, register, value))
    if not indexed_bases:
        print("  (none)")
finally:
    project.close()
