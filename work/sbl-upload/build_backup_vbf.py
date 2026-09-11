#!/usr/bin/env python3
"""Append the bounded backup-reader blob to the OEM SBL VBF.

All OEM blocks are preserved byte-for-byte. Only the header call address/block
metadata, appended SRAM block, per-block CRC-16, and file CRC-32 differ.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_SOURCE = os.path.join(ROOT, "DV6T-14C097-AB.vbf")
DEFAULT_BLOB = os.path.join(HERE, "backup_reader_blob.json")
DEFAULT_OUTPUT = os.path.join(HERE, "DV6T-14C097-AB_backup-reader.VBF")


def crc16(data):
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    return value


def find_header_end(data):
    cursor = data.find(b"{", data.find(b"header"))
    depth = 0
    while cursor < len(data):
        if data[cursor] == 0x7B:
            depth += 1
        elif data[cursor] == 0x7D:
            depth -= 1
            if depth == 0:
                return cursor + 1
        cursor += 1
    raise ValueError("unterminated VBF header")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--blob", default=DEFAULT_BLOB)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main():
    args = parse_args()
    descriptor = json.load(open(args.blob))
    new_address = int(descriptor["address"])
    new_data = bytes(descriptor["blob"])

    original = open(args.source, "rb").read()
    header_end = find_header_end(original)
    header = original[:header_end].decode("latin1")
    first_block = header_end
    while original[first_block] in (9, 10, 13, 32):
        first_block += 1

    blocks = []
    cursor = first_block
    while cursor + 8 <= len(original):
        address, length = struct.unpack(">II", original[cursor:cursor + 8])
        if length == 0 or cursor + 10 + length > len(original):
            break
        data = original[cursor + 8:cursor + 8 + length]
        stored_crc = struct.unpack(">H", original[cursor + 8 + length:cursor + 10 + length])[0]
        if crc16(data) != stored_crc:
            raise ValueError(f"source block at 0x{address:08X} has invalid CRC-16")
        blocks.append((address, data))
        cursor += 10 + length
    if cursor != len(original):
        raise ValueError("unparsed bytes after final source block")

    for address, data in blocks:
        if not (new_address + len(new_data) <= address or new_address >= address + len(data)):
            raise ValueError(f"custom block overlaps OEM block at 0x{address:08X}")
    blocks.append((new_address, new_data))

    header = re.sub(r"call\s*=\s*0x[0-9A-Fa-f]+;", f"call = 0x{new_address:08X};", header)
    header = re.sub(r"// Blocks:\s*\d+", f"// Blocks:   {len(blocks)}", header)
    header = re.sub(r"// Bytes:\s*\d+", f"// Bytes:    {sum(len(data) for _, data in blocks)}", header)
    header = re.sub(r"file_checksum\s*=\s*0x[0-9A-Fa-f]+;", "file_checksum = 0x00000000;", header)

    separator = original[header_end:first_block]
    body = bytearray()
    for address, data in blocks:
        body += struct.pack(">II", address, len(data))
        body += data
        body += struct.pack(">H", crc16(data))

    header_bytes = header.encode("latin1")
    output = header_bytes + separator + body
    data_start = len(header_bytes) + len(separator)
    file_crc = zlib.crc32(output[data_start:]) & 0xFFFFFFFF
    output = re.sub(
        rb"file_checksum\s*=\s*0x00000000;",
        f"file_checksum = 0x{file_crc:08X};".encode(),
        output,
        count=1,
    )
    with open(args.output, "wb") as handle:
        handle.write(output)

    print("wrote", args.output)
    print("size", len(output), "sha256", hashlib.sha256(output).hexdigest())
    print("blocks", len(blocks), "file_crc32", f"0x{file_crc:08X}")
    print(
        f"reader source=0x{descriptor['source_start']:08X}.."
        f"0x{descriptor['source_end_exclusive'] - 1:08X} code_len=0x{len(new_data):X}"
    )
    for index, (address, data) in enumerate(blocks):
        print(f"  {index}: 0x{address:08X} len0x{len(data):X} crc16=0x{crc16(data):04X}")


if __name__ == "__main__":
    main()
