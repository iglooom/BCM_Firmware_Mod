#!/usr/bin/env python3
"""Decompile SBL functions containing the requested addresses."""
import os
import sys

import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor

PROJECT = "/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl"


def main():
    if len(sys.argv) < 2:
        raise SystemExit(f"usage: {sys.argv[0]} ADDRESS [ADDRESS ...]")
    project = GhidraProject.openProject(PROJECT, "SBL", False)
    program = project.openProgram("/", "sbl_merged.bin", False)
    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    try:
        space = program.getAddressFactory().getDefaultAddressSpace()
        manager = program.getFunctionManager()
        for text in sys.argv[1:]:
            requested = int(text, 0)
            function = manager.getFunctionContaining(space.getAddress(requested))
            if function is None:
                print(f"0x{requested:08X}: no containing function")
                continue
            result = decompiler.decompileFunction(function, 60, monitor)
            print(f"\n===== {function.getName()} @ {function.getEntryPoint()} =====")
            if not result.decompileCompleted():
                print("decompile failed:", result.getErrorMessage())
            else:
                print(result.getDecompiledFunction().getC())
    finally:
        decompiler.dispose()
        project.close()


if __name__ == "__main__":
    main()
