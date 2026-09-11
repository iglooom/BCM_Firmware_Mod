import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScriptUtil
monitor=ConsoleTaskMonitor()
gp=GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj_sbl","SBL",False)
prog=gp.openProgram("/","sbl_merged.bin",False)
try:
    tx=prog.startTransaction("analyze")
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    mgr=AutoAnalysisManager.getAnalysisManager(prog)
    mgr.initializeOptions(); mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)
    prog.endTransaction(tx,True)
    fm=prog.getFunctionManager()
    print("functions:", fm.getFunctionCount())
    gp.save(prog)
finally:
    gp.close()
print("ANALYZED")
