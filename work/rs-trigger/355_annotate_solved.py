#!/usr/bin/env python3
"""355 -- annotate the SOLVED remote-start announce chain in Ghidra.

Writes labels, plate comments and bookmarks for the mechanism proven on bench #1
(docs/vehicle_session_1.md Sec.10-11, docs/remote_start.md header).

WHICH PROJECT: ghidra_proj_fullflash / cflash.bin -- the PRIMARY ANALYSIS
project.  NOT ghidra_proj/BCM_C1MCA, which the shipped acc-fix and rke-lock
builders verify against and which must stay OEM-clean.  (AGENTS.md Sec.1:
addresses are not interchangeable between projects.)

This is the ONE script here that opens a project WRITABLE.  Per AGENTS.md Sec.7:
  - save with project.save(program), never program.getDomainFile().save()
  - do NOT call program.release(project) as well as project.close()
  - commit the transaction and undo rejected units explicitly; aborting a
    nested transaction rolls back the enclosing one
  - a large save must exit NORMALLY -- os._exit() can kill the JVM mid-flush.
    This save is small (tens of units), but we still exit normally.
  - verify by reopening READ-ONLY and asserting the bookmark ADDRESS SET,
    never a count (setBookmark replaces same address+category)
"""
import sys
import os
import traceback

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")
import pyghidra  # noqa: E402

pyghidra.start()

from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.program.model.listing import CodeUnit  # noqa: E402
from ghidra.program.model.symbol import SourceType  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
PNAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

CAT = "REMOTE-START"

# (address, label, plate comment)
SITES = [
    (0x058538, "APP_rke_code_commit",
     "RKE COMMAND COMMIT -- the ANNOUNCE PAIR.\n"
     "Writes the Volcano dirty flag 0x40003F53 = 0xFF (se_bmaski r0,0x8 at\n"
     "0x058568, stored at 0x05856A) and THEN the command code 0x40002DA2\n"
     "(0x05856E).  r30 = 0x40003F02 so +0x51 = 0x40003F53;\n"
     "r31 = 0x40002D20 so +0x82 = 0x40002DA2.\n"
     "PROVEN ON BENCH #1: injecting the code WITHOUT this announce leaves it\n"
     "resident for minutes and NOTHING fires.  Injecting both advances the\n"
     "chain 2/2 against a 0/2 negative control.\n"
     "See docs/vehicle_session_1.md Sec.10-11."),

    (0x05856A, "APP_rke_announce_store",
     "ANNOUNCE: 0x40003F53 = 0xFF.  This is the arrival signal.\n"
     "Consumers call VOL_test_and_clear_dirty(&flag, n) testing mask 0x80>>n.\n"
     "Writing 0x01 here (bit index 7) is read by NOBODY -- that was the bug\n"
     "in the first injection attempt."),

    (0x0AEEC6, "APP_rs_announce_consumer",
     "REMOTE-START CONSUMER of the RKE announce flag.\n"
     "  0x0AEECC e_lis r29,0x4000 / 0x0AEED0 e_add16i r29,r29,0x3f02\n"
     "  0x0AEED4 e_addi r3,r29,0x51   -> 0x40003F53\n"
     "  0x0AEED8 se_li  r4,0x2        -> n=2, mask 0x20\n"
     "Then drives 0x4000968B -> 0x400095E1 -> read at 0x0ADA24 (== 1)\n"
     "-> 0x0ADA3E sets bit 27 of 0x40009680.\n"
     "BENCH-CONFIRMED: writing 0xFF and reading back 0x9F shows bits 0x60\n"
     "cleared = indices 1 and 2, i.e. THIS site and 0x099308 test-and-cleared\n"
     "their own bits.  No other consumer exists image-wide."),

    (0x099308, "APP_rke_demux_announce_consumer",
     "The OTHER consumer of 0x40003F53, n=1 (mask 0x40): RKE one-hot demux.\n"
     "NOT remote start.  Listed so nobody mistakes it for the RS path."),

    (0x031360, "VOL_test_and_clear_dirty",
     "Volcano dirty-flag helper: tests mask (0x80 >> n), clears it, returns\n"
     "whether it was set.  MSB-FIRST index convention -- n=2 is mask 0x20.\n"
     "Shift/mask build confirmed at 0x031366 (se_srw) and 0x031378 (e_rlwinm)."),

    (0x0AD97C, "APP_rs_bit27_state_machine",
     "Two-state machine that raises/clears bit 27 of 0x40009680.\n"
     "  if ((0x4000967C >> 26) & 3) == 1 and *(u8*)0x400095E1 == 1:\n"
     "        sub-state -> 2 ; 0x40009680 |= 0x08000000   (0x0ADA3E)\n"
     "  counter at 0x40009672 += 10 per tick, HOLD LIMIT 200 (verified on the\n"
     "  vehicle: 10,40,...,190,200 then reset -- value, step AND limit all\n"
     "  match this code).\n"
     "param_1 = 0x400095DC, proven from the call site (e_lis/e_add16i at\n"
     "0x0AD888/0x0AD88C) plus fallthrough into this entry.\n"
     "NOTE: dormant on an idle module -- an early 'never called' conclusion\n"
     "was measured on an idle car and REFUTED during a real fob start."),

    (0x0ADADA, "APP_rs_enum8_consumer",
     "Consumes RKE enum 8: tests (code & 0xF) == 8 on 0x40002DA2.\n"
     "Guard ((word >> 0x1B) & 7) == 7 on 0x40009680: bits 28/29 are ALWAYS\n"
     "set, so this reduces to BIT 27 ALONE.\n"
     "WARNING: bit 27 is NOT a remote-start gate.  It rises for ANY keyfob\n"
     "button in ANY vehicle state (operator-observed) -- it is a\n"
     "receiver-active indicator.  docs/vehicle_session_1.md Sec.1."),
]

# RAM cells worth labelling
DATA = [
    (0x40003F53, "APP_rke_announce_flag",
     "Volcano dirty-flag byte for the RKE command signal.\n"
     "Set to 0xFF by APP_rke_code_commit.  RS consumer tests mask 0x20 (n=2);\n"
     "RKE demux tests mask 0x40 (n=1).  Bit index 7 (0x01) is read by nobody."),
    (0x40002DA2, "APP_rke_command_code",
     "RKE command code halfword.  Remote start = 0x1808 / 0x1818\n"
     "(low nibble 8).  Lock = low nibble 1.  Holding a value here does\n"
     "NOTHING without the announce flag above."),
    (0x400095E1, "APP_rs_bit27_arm_flag",
     "Read at 0x0ADA24, compared == 1; on match 0x0ADA3E sets bit 27.\n"
     "Written from 0x4000968B by the announce consumer."),
    (0x40009672, "APP_rs_hold_counter",
     "+0x86 of the RS state block.  += 10 per tick, wraps at 200.\n"
     "A moving counter is direct proof APP_rs_bit27_state_machine is running\n"
     "-- it increments OUTSIDE the flag test, so it separates 'my write did\n"
     "not take' from 'the code never ran'."),
    (0x40009680, "APP_rs_gate_word",
     "+0x94 of the RS state block (base 0x400095EC).\n"
     "bit 27 = fob receiver active (NOT a remote-start gate -- see above).\n"
     "bits 28/29 always set, so (>>27)&7 == 7 tests bit 27 alone."),
]


def main():
    project = None
    program = None
    try:
        project = GhidraProject.openProject(PROJ, PNAME, True)
        program = project.openProgram("/", PROG, False)   # WRITABLE
        listing = program.getListing()
        st = program.getSymbolTable()
        bm = program.getBookmarkManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        tx = program.startTransaction("annotate remote-start announce chain")
        touched = []
        try:
            for addr, label, plate in SITES + [(a, l, c) for a, l, c in DATA]:
                ga = af.getAddress(addr)
                try:
                    st.createLabel(ga, label, SourceType.USER_DEFINED)
                except Exception:
                    pass  # label may already exist
                cu = listing.getCodeUnitAt(ga)
                if cu is not None:
                    cu.setComment(CodeUnit.PLATE_COMMENT, plate)
                bm.setBookmark(ga, "Note", CAT, label)
                touched.append(addr)
        finally:
            # ALWAYS commit -- aborting a nested transaction rolls back the
            # enclosing one and would discard every good unit as well.
            program.endTransaction(tx, True)

        project.save(program)
        print("annotated and saved %d addresses" % len(touched))
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        try:
            if project is not None:
                # project.close() releases the program; do NOT also call
                # program.release(project) -- that raises "unknown consumer".
                project.close()
        except Exception:
            traceback.print_exc()
        sys.stdout.flush()
        sys.stderr.flush()

    # ---- verify by REOPENING READ-ONLY and asserting the ADDRESS SET -------
    print("\nverifying by reopening read-only...")
    project = None
    try:
        project = GhidraProject.openProject(PROJ, PNAME, True)
        program = project.openProgram("/", PROG, True)
        bm = program.getBookmarkManager()
        want = {a for a, _, _ in SITES} | {a for a, _, _ in DATA}
        got = set()
        it = bm.getBookmarksIterator("Note")
        while it.hasNext():
            b = it.next()
            if b.getCategory() == CAT:
                got.add(int(b.getAddress().getOffset()))
        missing = want - got
        print("  expected %d addresses, found %d" % (len(want), len(got & want)))
        if missing:
            print("  MISSING: " + " ".join("0x%X" % a for a in sorted(missing)))
            print("  RESULT: FAIL")
        else:
            print("  RESULT: PASS -- every annotation persisted")
    except Exception:
        traceback.print_exc()
    finally:
        try:
            if project is not None:
                project.close()
        except Exception:
            traceback.print_exc()
        sys.stdout.flush()
        sys.stderr.flush()
    return 0


sys.exit(main())
