#!/usr/bin/env python3
"""Capture a large readable region as restartable sub-timeout chunks."""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def integer(value):
    return int(value, 0)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=integer, required=True)
    parser.add_argument("--length", type=integer, required=True)
    parser.add_argument("--chunk-size", type=integer, default=0x18000)
    parser.add_argument("--service-mode", choices=("both", "sbl2", "none"), default="both")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output-dir")
    parser.add_argument("--reference-dir", help="matching prior chunk set for byte-exact comparison")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.start < 0 or args.length <= 0 or args.chunk_size <= 0:
        raise SystemExit("start, length, and chunk-size must describe a positive range")
    if args.start & 3 or args.length & 3 or args.chunk_size & 3:
        raise SystemExit("start, length, and chunk-size must be 4-byte aligned")
    end = args.start + args.length
    if end > 0x100000000:
        raise SystemExit("range wraps the 32-bit address space")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or os.path.join(
        HERE, f"backup_set_{args.start:08X}_{args.length:08X}_{stamp}"
    )
    os.makedirs(output_dir, exist_ok=False)

    chunks = []
    address = args.start
    while address < end:
        length = min(args.chunk_size, end - address)
        name = f"chunk_{address:08X}_{length:08X}.bin"
        output = os.path.join(output_dir, name)
        run(
            [
                sys.executable,
                os.path.join(HERE, "build_backup_reader.py"),
                "--start",
                hex(address),
                "--length",
                hex(length),
                "--service-mode",
                args.service_mode,
            ]
        )
        run([sys.executable, os.path.join(HERE, "build_backup_vbf.py")])
        run([sys.executable, os.path.join(HERE, "verify_backup_vbf.py")])
        command = [
            sys.executable,
            os.path.join(HERE, "run_backup_reader.py"),
            "--timeout",
            str(args.timeout),
            "--output",
            output,
        ]
        reference = None
        if args.reference_dir:
            reference = os.path.join(args.reference_dir, name)
            if not os.path.isfile(reference):
                raise SystemExit(f"missing reference chunk: {reference}")
            command += ["--reference", reference]
        run(command)
        chunks.append(
            {
                "start": address,
                "length": length,
                "file": name,
                "sha256": sha256(output),
                "reference": os.path.abspath(reference) if reference else None,
            }
        )
        address += length

    combined_name = f"backup_{args.start:08X}_{args.length:08X}.bin"
    combined_path = os.path.join(output_dir, combined_name)
    with open(combined_path, "xb") as destination:
        for chunk in chunks:
            with open(os.path.join(output_dir, chunk["file"]), "rb") as source:
                destination.write(source.read())
    if os.path.getsize(combined_path) != args.length:
        raise AssertionError("combined backup length mismatch")

    combined_hash = sha256(combined_path)
    reference_combined_match = None
    if args.reference_dir:
        reference_combined = os.path.join(args.reference_dir, combined_name)
        if os.path.isfile(reference_combined):
            reference_combined_match = sha256(reference_combined) == combined_hash
            if not reference_combined_match:
                raise SystemExit("combined backup differs from reference set")

    manifest = {
        "start": args.start,
        "end_exclusive": end,
        "length": args.length,
        "chunk_size": args.chunk_size,
        "service_mode": args.service_mode,
        "combined_file": combined_name,
        "combined_sha256": combined_hash,
        "reference_dir": os.path.abspath(args.reference_dir) if args.reference_dir else None,
        "reference_combined_match": reference_combined_match,
        "chunks": chunks,
    }
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "x") as handle:
        json.dump(manifest, handle, indent=2)
    print(f"PASS chunked backup: 0x{args.start:08X}..0x{end - 1:08X}")
    print("combined", combined_path)
    print("sha256", combined_hash)
    print("manifest", manifest_path)


if __name__ == "__main__":
    main()
