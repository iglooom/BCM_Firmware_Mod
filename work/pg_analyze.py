import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScriptUtil
from ghidra.program.util import GhidraProgramUtilities
from ghidra.app.plugin.core.analysis import AutoAnalysisManager

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
monitor = ConsoleTaskMonitor()
try:
    tx = program.startTransaction("auto-analyze")
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)
    program.endTransaction(tx, True)
    print("instr:", program.getListing().getNumInstructions())
    print("funcs:", program.getFunctionManager().getFunctionCount())
    project.save(program)
    print("saved")
finally:
    project.close()
