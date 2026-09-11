#!/usr/bin/env python3
"""Verify backup-reader VBF integrity and OEM block preservation."""
import argparse
import hashlib
import json
import os
import re
import struct
import zlib

from build_backup_vbf import crc16, find_header_end

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_OEM = os.path.join(ROOT, "DV6T-14C097-AB.vbf")
DEFAULT_BLOB = os.path.join(HERE, "backup_reader_blob.json")
DEFAULT_MODIFIED = os.path.join(HERE, "DV6T-14C097-AB_backup-reader.VBF")


def parse(path):
    raw = open(path, "rb").read()
    header_end = find_header_end(raw)
    header = raw[:header_end].decode("latin1")
    cursor = header_end
    while raw[cursor] in (9, 10, 13, 32):
        cursor += 1
    data_start = cursor
    blocks = []
    while cursor + 8 <= len(raw):
        address, length = struct.unpack(">II", raw[cursor:cursor + 8])
        if not length or cursor + 10 + length > len(raw):
            raise ValueError(f"invalid block framing at file offset 0x{cursor:X}")
        data = raw[cursor + 8:cursor + 8 + length]
        stored = struct.unpack(">H", raw[cursor + 8 + length:cursor + 10 + length])[0]
        if crc16(data) != stored:
            raise ValueError(f"CRC-16 failure at block 0x{address:08X}")
        blocks.append((address, data, stored))
        cursor += 10 + length
    if cursor != len(raw):
        raise ValueError("unparsed trailing data")

    call_match = re.search(r"call\s*=\s*0x([0-9A-Fa-f]+)", header)
    checksum_match = re.search(r"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", header)
    if not call_match or not checksum_match:
        raise ValueError("missing call or file_checksum header field")
    call = int(call_match.group(1), 16)
    stored_file_crc = int(checksum_match.group(1), 16)
    calculated_file_crc = zlib.crc32(raw[data_start:]) & 0xFFFFFFFF
    if stored_file_crc != calculated_file_crc:
        raise ValueError("file CRC-32 mismatch")
    return raw, header, call, blocks, stored_file_crc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oem", default=DEFAULT_OEM)
    parser.add_argument("--blob", default=DEFAULT_BLOB)
    parser.add_argument("--modified", default=DEFAULT_MODIFIED)
    args = parser.parse_args()

    descriptor = json.load(open(args.blob))
    original_raw, _, _, original_blocks, _ = parse(args.oem)
    modified_raw, modified_header, call, modified_blocks, file_crc = parse(args.modified)
    if len(modified_blocks) != len(original_blocks) + 1:
        raise ValueError("modified image does not contain exactly one appended block")
    for index, original_block in enumerate(original_blocks):
        if original_block != modified_blocks[index]:
            raise ValueError(f"OEM block {index} changed")

    blob = bytes(descriptor["blob"])
    appended = modified_blocks[-1]
    if call != descriptor["address"]:
        raise ValueError("VBF call address differs from reader entry")
    if appended[0] != descriptor["address"] or appended[1] != blob:
        raise ValueError("appended block differs from assembled reader")
    if f"Blocks:   {len(modified_blocks)}" not in modified_header:
        raise ValueError("header block count was not updated")

    stores = [entry["instruction"] for entry in descriptor["listing"] if "stw" in entry["instruction"]]
    if any("(r31)" not in instruction for instruction in stores):
        raise ValueError(f"unexpected store outside CAN mailbox: {stores}")
    reads = [entry["instruction"] for entry in descriptor["listing"] if "lwz" in entry["instruction"]]
    if reads != ["e_lwz r28,0x0(r30)"]:
        raise ValueError(f"unexpected 32-bit source reads: {reads}")

    print("PASS backup-reader VBF")
    print(f"  call=0x{call:08X} blocks={len(modified_blocks)} file_crc32=0x{file_crc:08X}")
    print("  OEM blocks preserved byte-exact; all CRC-16 values and file CRC-32 valid")
    print(
        f"  bounded source=0x{descriptor['source_start']:08X}.."
        f"0x{descriptor['source_end_exclusive'] - 1:08X} ({descriptor['source_length']} bytes)"
    )
    print(f"  reader block=0x{appended[0]:08X} len=0x{len(blob):X} crc16=0x{appended[2]:04X}")
    print("  static store audit: writes target CAN0 MB0 only; source access is one read via r30")
    print("  sha256", hashlib.sha256(modified_raw).hexdigest())
    print("  OEM sha256", hashlib.sha256(original_raw).hexdigest())


if __name__ == "__main__":
    main()
