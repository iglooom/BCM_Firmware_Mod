#!/usr/bin/env python3
"""Load the bounded SRAM backup reader and reconstruct its raw CAN records."""
import argparse
import datetime
import hashlib
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_VBF = os.path.join(HERE, "DV6T-14C097-AB_backup-reader.VBF")
DEFAULT_DESCRIPTOR = os.path.join(HERE, "backup_reader_blob.json")
CAN_RAW = 1


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="can0")
    parser.add_argument("--vbf", default=DEFAULT_VBF)
    parser.add_argument("--descriptor", default=DEFAULT_DESCRIPTOR)
    parser.add_argument("--output", help="output binary; default is timestamped and never overwritten")
    parser.add_argument("--reference", help="optional exact reference binary for comparison")
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


def analyze_records(frames, can_id, start, end, completion_address, completion_data):
    cells = {}
    conflicts = []
    rejected = []
    completion_seen = False
    relevant_frames = 0
    for timestamp, frame_id, data in frames:
        if frame_id != can_id or len(data) != 8:
            continue
        address = struct.unpack(">I", data[:4])[0]
        payload = data[4:]
        if address == completion_address and payload == completion_data:
            completion_seen = True
            relevant_frames += 1
            continue
        if address < start or address >= end or address & 3:
            rejected.append((timestamp, address, payload))
            continue
        relevant_frames += 1
        prior = cells.get(address)
        if prior is not None and prior != payload:
            conflicts.append((address, prior, payload))
        else:
            cells[address] = payload
    return cells, conflicts, rejected, completion_seen, relevant_frames


def main():
    args = parse_args()
    descriptor = json.load(open(args.descriptor))
    start = int(descriptor["source_start"])
    length = int(descriptor["source_length"])
    end = int(descriptor["source_end_exclusive"])
    can_id = int(descriptor["can_id"])
    completion_address = int(descriptor["completion_address"])
    completion_data = descriptor["completion_data"].encode("ascii")
    if end - start != length or length <= 0 or length & 3:
        raise SystemExit("invalid range in reader descriptor")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = args.output or os.path.join(HERE, f"backup_{start:08X}_{length:08X}_{stamp}.bin")
    log_path = output_path + ".can.log"
    metadata_path = output_path + ".json"
    for path in (output_path, log_path, metadata_path):
        if os.path.exists(path):
            raise SystemExit(f"refusing to overwrite existing artifact: {path}")

    raw_socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, CAN_RAW)
    raw_socket.bind((args.interface,))
    raw_socket.setblocking(False)

    command = [sys.executable, os.path.join(HERE, "load_sbl.py"), args.vbf]
    print("starting:", " ".join(command))
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    started = time.monotonic()
    frames = []
    process_done = None
    completion_observed = None
    last_reader_frame = None
    stopped_reason = None
    while True:
        now = time.monotonic()
        if process.poll() is not None and process_done is None:
            process_done = now
        if completion_observed is not None and now - completion_observed > 1.0:
            stopped_reason = "completion"
            break
        if process_done is not None and process.returncode and now - process_done > 1.0:
            stopped_reason = f"loader exited {process.returncode}"
            break
        if last_reader_frame is not None and completion_observed is None and now - last_reader_frame > 3.0:
            stopped_reason = "reader stream stalled before completion"
            break
        if now - started > args.timeout:
            stopped_reason = "capture timeout"
            if process.poll() is None:
                process.kill()
            break
        readable, _, _ = select.select([raw_socket], [], [], 0.02)
        if readable:
            frame = raw_socket.recv(16)
            frame_id, dlc, data = struct.unpack("=IB3x8s", frame)
            frame_id &= 0x1FFFFFFF
            data = data[:dlc]
            frames.append((now - started, frame_id, data))
            if frame_id == can_id and len(data) == 8:
                last_reader_frame = now
                if data == struct.pack(">I", completion_address) + completion_data:
                    completion_observed = now
    raw_socket.close()
    loader_output = process.stdout.read() if process.stdout else ""
    print(loader_output)
    print("capture stop:", stopped_reason)

    with open(log_path, "w") as handle:
        for timestamp, frame_id, data in frames:
            handle.write(f"({timestamp:.6f}) {args.interface} {frame_id:03X}#{data.hex().upper()}\n")
    print(f"captured {len(frames)} frames -> {log_path}")

    cells, conflicts, rejected, completion_seen, relevant_frames = analyze_records(
        frames, can_id, start, end, completion_address, completion_data
    )

    expected_addresses = list(range(start, end, 4))
    missing = [address for address in expected_addresses if address not in cells]
    print(
        f"reader records={relevant_frames} unique_cells={len(cells)}/{len(expected_addresses)} "
        f"completion={completion_seen} rejected={len(rejected)} conflicts={len(conflicts)}"
    )
    if rejected:
        for timestamp, address, payload in rejected[:10]:
            print(f"  rejected t={timestamp:.6f} addr=0x{address:08X} data={payload.hex().upper()}")
    if conflicts:
        for address, first, second in conflicts[:10]:
            print(f"  CONFLICT 0x{address:08X}: {first.hex().upper()} != {second.hex().upper()}")
    if missing:
        print("  missing:", ", ".join(f"0x{address:08X}" for address in missing[:20]))

    success = completion_seen and not missing and not conflicts
    if not success:
        print("RESULT: FAIL incomplete or inconsistent capture; no binary written")
        raise SystemExit(2)

    reconstructed = b"".join(cells[address] for address in expected_addresses)
    if len(reconstructed) != length:
        raise AssertionError("reconstructed length mismatch")
    digest = hashlib.sha256(reconstructed).hexdigest()
    with open(output_path, "xb") as handle:
        handle.write(reconstructed)

    reference_result = None
    if args.reference:
        reference = open(args.reference, "rb").read()
        reference_result = reference == reconstructed
        if not reference_result:
            differences = [index for index, (left, right) in enumerate(zip(reconstructed, reference)) if left != right]
            if len(reference) != len(reconstructed):
                differences.append(min(len(reference), len(reconstructed)))
            print(
                f"REFERENCE MISMATCH reference_len={len(reference)} captured_len={len(reconstructed)} "
                f"first_offset={differences[0] if differences else 'unknown'}"
            )
        else:
            print("reference comparison: byte-exact PASS")

    metadata = {
        "interface": args.interface,
        "vbf": os.path.abspath(args.vbf),
        "source_start": start,
        "source_end_exclusive": end,
        "length": length,
        "can_id": can_id,
        "completion_seen": completion_seen,
        "captured_frames": len(frames),
        "reader_records": relevant_frames,
        "unique_cells": len(cells),
        "rejected_records": len(rejected),
        "conflicts": len(conflicts),
        "missing_cells": len(missing),
        "sha256": digest,
        "reference": os.path.abspath(args.reference) if args.reference else None,
        "reference_match": reference_result,
    }
    with open(metadata_path, "x") as handle:
        json.dump(metadata, handle, indent=2)
    print(f"RESULT: PASS {length} bytes -> {output_path}")
    print("sha256", digest)
    print("metadata", metadata_path)
    if args.reference and not reference_result:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
