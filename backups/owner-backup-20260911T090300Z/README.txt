Ford BCM (C1MCA) owner firmware backup — 2026-09-11T09:03:00Z
=============================================================

Right-to-repair preservation copy of the nonvolatile memory of an owner-operated
BCM from a 12-year-old vehicle for which the manufacturer no longer supplies
firmware. Read non-destructively: a temporary SRAM-resident routine, loaded
through the module's normal wired programming path, read mapped flash and
transmitted it as addressed CAN records. No flash-controller erase/program bits
were ever set, and a power cycle restores the stock execution path.

Files
-----
  cflash.bin   0x00000000..0x0017FFFF   1572864 bytes   code flash
  shadow.bin   0x00200000..0x00203FFF     16384 bytes   flash shadow array
  dflash.bin   0x00800000..0x0080FFFF     65536 bytes   data flash / EEPROM emu

Each file is a flat image: file offset 0 is the region's start address.

Integrity
---------
Every region was captured twice in independent runs and compared byte-for-byte;
both captures matched exactly. Each capture required complete address coverage,
an explicit completion marker, zero rejected records and zero conflicting
duplicates before it was accepted.

  cd <this directory> && sha256sum -c SHA256SUMS

manifest.json records the address map, sizes, hashes and the capture method.

Independent verification
------------------------
The capture was cross-checked against the OEM VBFs in this repository, so its
correctness does not rest on repeatability alone:

  * the calibration block at 0x00C000 (0x4000 bytes) is byte-identical to
    JV6T-14C095-AB;
  * the application matches JV6T-14C094-AD except for four configuration bytes
    (0x017CAD, 0x017CAE, 0x017CAF, 0x017CBB) and the internal checksum byte;
  * the firmware's own integrity word at 0x13FFFE is 0x75A5 and equals the sum
    of bytes 0x10000..0x13FFFE recomputed from the capture;
  * those four configuration bytes sum to +51 relative to OEM -AD, and the
    stored checksum is likewise +51 (0x75A5 vs 0x7572) — an internally
    consistent image, not a transfer artifact.

Reproducing
-----------
See docs/sbl-upload-patch.md and docs/sbl-DV6T-14C097-AB.md in this repository.
Tooling lives in work/sbl-upload/ (build_backup_reader.py, build_backup_vbf.py,
verify_backup_vbf.py, run_backup_reader.py, run_chunked_backup.py).
