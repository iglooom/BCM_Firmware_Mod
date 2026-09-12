#!/usr/bin/env python3
"""Consolidate the bench #2 region captures into one verified backup set.

Mirrors the layout of backups/owner-backup-20260911T090300Z/ (bench #1) so the
two are directly comparable, and records the DEVICE IDENTITY in the manifest -
AGENTS rule 32: two modules of the same model are not the same device, and a
backup without its serial number is a trap for whoever reads it next.

Verification performed here (not merely asserted):
  * app blocks from the flashed VBF must match the capture BYTE-EXACT
    (independent ground truth - proves we read real flash, not a buffer)
  * every region's sha256 is recomputed from the combined file on disk
"""
import hashlib, json, os, shutil, struct, sys, time

R = "/home/gl/Projects/ford/BCM/Research/"
OUT = R + "backups/bench2-backup-%s/" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

REGIONS = [
    ("cflash.bin", "code flash (PBL, calibration, application, remaining physical CFlash)",
     0x00000000, 0x180000, "work/backups/bench2-cflash/backup_00000000_00180000.bin"),
    ("shadow.bin", "flash shadow array (censorship / NV config)",
     0x00200000, 0x004000, "work/backups/bench2-shadow/backup_00200000_00004000.bin"),
    ("dflash.bin", "data flash (EEPROM emulation)",
     0x00800000, 0x010000, "work/backups/bench2-dflash/backup_00800000_00010000.bin"),
]

IDENTITY = {
    "F188_application_sw_part": "JV6T-14C094-AD",
    "F124_calibration_part":    "GV6T-14C095-AK",
    "F111_ecu_hardware":        "GV6T-14F119-EB",
    "F113_ecu_core_assembly":   "GV6T-14A073-EF",
    "F180_bootloader":          "FORD-PBL-V014",
    "F18C_serial_number":       "007670223726",
    "note": ("HYBRID UNIT: JV6T application flashed onto GV6T hardware with the "
             "GV6T calibration left in place. Code addresses match the Ghidra DB; "
             "BEHAVIOUR is not comparable to bench #1. "
             "PHYSICAL: partially disassembled, NO RELAYS FITTED - absent "
             "actuation on this unit is not evidence of anything."),
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def vbf_blocks(path):
    v = bytearray(open(path, "rb").read())
    i = v.find(b"header")
    if i < 0:
        raise ValueError("%s: no 'header' keyword" % path)
    depth, j, end = 0, v.find(b"{", i), None
    while j < len(v):
        if v[j] == 0x7B:
            depth += 1
        elif v[j] == 0x7D:
            depth -= 1
            if depth == 0:
                end = j + 1
                break
        j += 1
    if end is None:
        raise ValueError("%s: unbalanced header braces" % path)
    while v[end] in (0x0D, 0x0A, 0x20, 0x09):
        end += 1
    p, out = end, []
    while p + 8 <= len(v):
        s, l = struct.unpack(">II", v[p:p + 8])
        if l == 0 or p + 8 + l + 2 > len(v):
            break
        out.append((s, l, bytes(v[p + 8:p + 8 + l])))
        p = p + 8 + l + 2
    return out


def main():
    for _, _, _, _, src in REGIONS:
        if not os.path.exists(R + src):
            print("MISSING: %s" % src)
            return 1
    os.makedirs(OUT, exist_ok=True)

    manifest = {
        "format": "SPC560B64L7 owner backup",
        "module": "Ford BCM (bench #2 - JTAG unit)",
        "mcu": "SPC560B64L7 / MPC5607B, PowerPC e200z0h, big-endian VLE",
        "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "identity": IDENTITY,
        "method": {
            "loader": "OEM SBL DV6T-14C097-AB with an appended seventh SRAM block at 0x40006000",
            "reader": "work/sbl-upload/build_backup_reader.py (bounded, SRAM-resident, no flash-controller writes)",
            "transport": "raw CAN0 id 0x5A5, records of [address:u32-be][data:u32], completion marker FFFFFFFF#444F4E45",
            "host": "work/sbl-upload/run_chunked_backup.py",
        },
        "regions": [],
    }

    for name, desc, start, length, src in REGIONS:
        dst = OUT + name
        shutil.copy2(R + src, dst)
        got = os.path.getsize(dst)
        if got != length:
            print("SIZE MISMATCH %s: got %d want %d" % (name, got, length))
            return 1
        manifest["regions"].append({
            "file": name, "description": desc,
            "start": "0x%08X" % start,
            "end_exclusive": "0x%08X" % (start + length),
            "length_bytes": length,
            "sha256": sha256(dst),
        })
        print("  %-12s 0x%08X..0x%08X  %7d bytes  %s"
              % (name, start, start + length, length, sha256(dst)[:16]))

    # --- verification against independent ground truth ---------------------
    cf = open(OUT + "cflash.bin", "rb").read()
    checks = []
    for s, l, data in vbf_blocks(R + "JV6T-14C094-AD.VBF"):
        match = cf[s:s + l] == data
        checks.append(match)
        print("  VERIFY app block @0x%06X len 0x%06X : %s"
              % (s, l, "MATCH" if match else "*** DIFFER ***"))
    manifest["verification"] = {
        "app_blocks_vs_flashed_vbf": "JV6T-14C094-AD.VBF",
        "blocks_checked": len(checks),
        "blocks_matching": sum(checks),
        "byte_exact": all(checks),
    }

    # censorship, read from THIS device
    sh = open(OUT + "shadow.bin", "rb").read()
    cw = struct.unpack(">I", sh[0x3DE0:0x3DE4])[0]
    manifest["censorship"] = {
        "NVSCC0_0x203DE0": "0x%08X" % cw,
        "NVSCC1_0x203DE4": "0x%08X" % struct.unpack(">I", sh[0x3DE4:0x3DE8])[0],
        "censored": (cw >> 16) != 0x55AA,
        "interpretation": ("0x55AA55AA = factory uncensored: internal flash enabled, "
                           "Nexus/JTAG debug enabled, no password required (AN3787)"),
    }

    with open(OUT + "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    with open(OUT + "SHA256SUMS", "w") as f:
        for r in manifest["regions"]:
            f.write("%s  %s\n" % (r["sha256"], r["file"]))

    print("\nbackup set: %s" % OUT)
    print("app blocks byte-exact vs flashed VBF: %s" % all(checks))
    print("censored: %s" % manifest["censorship"]["censored"])
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
