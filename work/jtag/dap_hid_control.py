#!/usr/bin/env python3
"""Is the raw HID DAP transport actually working?

dap_reset_hid.py reported DAP_Info as '' (empty) and every pin as 0, including
TCK/TMS/TDO which we know toggle.  Per AGENTS rule 27, an empty instrument
reading is INCONCLUSIVE, not a negative result about the subject - so before
concluding anything about nRESET wiring, prove the transport itself.

Positive control: DAP_Info(0xF0) returns DAP capabilities, and DAP_Info(0x01)
returns the vendor string.  If those come back sane, the transport works and
the pin readings can be believed.  If they are empty/garbage, the pin test told
us nothing.
"""
import glob, sys


def find_nodes():
    out = []
    for node in sorted(glob.glob("/dev/hidraw*")):
        name = node.split("/")[-1]
        try:
            with open("/sys/class/hidraw/%s/device/uevent" % name) as f:
                u = f.read().upper()
        except OSError:
            continue
        if "2E8A" in u and "000C" in u:
            out.append(node)
    return out


def xfer(f, payload, pad_to=65):
    pkt = bytes([0x00]) + bytes(payload)
    pkt += b"\x00" * (pad_to - len(pkt))
    f.write(pkt)
    return f.read(64)


def main():
    nodes = find_nodes()
    print("nodes: %s" % nodes)
    if not nodes:
        return 1

    for node in nodes:
        print("\n=== %s ===" % node)
        try:
            f = open(node, "rb+", buffering=0)
        except OSError as e:
            print("  open failed: %s" % e)
            continue

        for label, cmd in [("DAP_Info(0x01) vendor", [0x00, 0x01]),
                           ("DAP_Info(0x02) product", [0x00, 0x02]),
                           ("DAP_Info(0xF0) caps", [0x00, 0xF0]),
                           ("DAP_Connect(JTAG)", [0x02, 0x02]),
                           ("DAP_SWJ_Pins read", [0x10, 0x00, 0x00, 0, 0, 0, 0])]:
            try:
                r = xfer(f, cmd)
            except OSError as e:
                print("  %-22s -> IO ERROR %s" % (label, e))
                continue
            print("  %-22s -> %s" % (label, r[:12].hex(" ")))
        f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
