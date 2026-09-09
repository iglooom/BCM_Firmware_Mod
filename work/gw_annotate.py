"""Annotate the BCM_C1MCA Ghidra project with all discovered labels/functions/comments.
Opens the project WRITABLE (single-writer!), applies, saves. Idempotent.
"""
import os, struct
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor

PROJ="/home/gl/Projects/ford/BCM/Research/ghidra_proj"
project = GhidraProject.openProject(PROJ, "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)   # writable
monitor = ConsoleTaskMonitor()
st = program.getSymbolTable()
fm = program.getFunctionManager()
listing = program.getListing()
space = program.getAddressFactory().getDefaultAddressSpace()
def A(x): return space.getAddress(x)

img = open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I", img, a)[0]

tx = program.startTransaction("annotate")
made_labels=0; made_funcs=0; made_cmts=0

def label(addr, name, comment=None):
    global made_labels, made_cmts
    a=A(addr)
    # remove pre-existing user label of same addr with different name? just add a primary label
    try:
        s=st.createLabel(a, name, SourceType.USER_DEFINED)
        s.setPrimary()
        made_labels+=1
    except Exception as e:
        pass
    if comment:
        listing.setComment(a, 0, comment)  # 0 = EOL_COMMENT
        made_cmts+=1

def plate(addr, text):
    global made_cmts
    listing.setComment(A(addr), 3, text)   # 3 = PLATE_COMMENT
    made_cmts+=1

def func(addr, name, comment=None):
    global made_funcs
    a=A(addr)
    f=fm.getFunctionAt(a)
    if f is None:
        f=fm.getFunctionContaining(a)
    if f is None:
        from ghidra.app.cmd.function import CreateFunctionCmd
        CreateFunctionCmd(a).applyTo(program, monitor)
        f=fm.getFunctionAt(a)
    if f is not None:
        try: f.setName(name, SourceType.USER_DEFINED)
        except Exception: pass
        if comment: f.setComment(comment)
        made_funcs+=1
    else:
        # fall back to a label
        label(addr, name, comment)

# ---- FUNCTIONS ----
func(0x0010F4A0, "reset_entry",           "Reset vector target (from RCHW 005A005A @0x10000)")
func(0x0004471A, "volcano_net_walker",    "Walks master net table @0x178B0; calls volcano_net_bringup")
func(0x000FBC48, "volcano_net_bringup",   "Network bring-up/reset; zeroes frame images, copies defaults")
func(0x000FC63E, "flexcan_rx_copier",     "RX: FlexCAN MB -> frame image. Walks 28B reception descriptors @ctrlDesc+0x44")
func(0x000FC218, "flexcan_tx_packer",     "TX: frame image -> FlexCAN MB (sets CODE 0xC40, applies byte masks)")
func(0x000FC2F6, "flexcan_tx_packer2",    "TX: frame image -> FlexCAN MB (variant)")

# ---- TOP-LEVEL DATA STRUCTURES ----
label(0x00010000, "RCHW_boot_header",     "Reset Config Half Word 005A005A; +4 = entry 0x0010F4A0")
label(0x000178B0, "volcano_master_net_table", "Master network table: 0x5C-byte records, +0x04 -> controller descriptor")
label(0x00140000, "volcano_routing_records", "Signal-routing record array (20B: [sigA][sigB][frameObj][spec1][spec2]) 0x140000..~0x15BF00")
label(0x00018000, "flexcan_hs_rx_desc_table", "HS-CAN reception descriptors (32B: ..[handler->routing @+0x0C]..[frame-image RAM @+0x18])")
label(0x0015A920, "volcano_signal_desc_table", "24B signal descriptors: [mask][sigRAM][frameObj][handler][0][(byteIdx<<8)|bitmask]")
label(0x0000C000, "cal_data_F124",        "Calibration DATA block F124 (JV6T-14C095) - signal defaults/local config")
label(0x00140000, "cal_config_F10A",      None)  # same addr; routing label already primary

# ---- CONTROLLER DESCRIPTORS ----
for nm,base,role in [("HS",0x1464E0,"HS-CAN 500k CAN_0 @0xFFFC0000"),
                     ("MS",0x146900,"MS-CAN 125k CAN_1 @0xFFFC4000"),
                     ("MSX",0x146C50,"MSX-CAN 125k CAN_2 @0xFFFC8000 (L/R obstacle modules)")]:
    label(base, "ctrlDesc_%s"%nm, "Volcano controller descriptor: %s"%role)
    plate(base, "Volcano controller descriptor (%s)\n  +0x10 FlexCAN base 0x%08X\n  +0x30 CTRL/baud 0x%08X\n  +0x44 RX-desc ptr 0x%08X"%(
        role, u32(base+0x10), u32(base+0x30), u32(base+0x44)))

# ---- MB ACCEPTANCE / ID FILTER LISTS: label every entry with id+dir ----
def annotate_mb(name, start, stop):
    a=start; n=0
    label(start, "mbfilter_%s"%name, "FlexCAN MB acceptance/ID filter list (%s): 12B [id<<18][dir][mask]"%name)
    while a < stop:
        w0=u32(a); w1=u32(a+4); w2=u32(a+8)
        if (w0 & 0x3FFFF)==0 and 0 < (w0>>18) <= 0x7FF:
            idv=w0>>18; flag=(w1>>24)&0xFF
            d = "RX" if flag==0x04 else ("TX" if flag==0x08 else "d%02X"%flag)
            label(a, "%s_%s_%03X"%(name, d, idv),
                  "%s %s CAN 0x%03X (id<<18=0x%08X mask=0x%08X)"%(name, d, idv, w0, w2))
            a+=12; n+=1
        else:
            break
    return n
nh=annotate_mb("HSCAN", 0x146530, 0x146900)
nm=annotate_mb("MSCAN", 0x146950, 0x146C50)
nx=annotate_mb("MSXCAN",0x146CA0, 0x146FA0)
print("MB entries labeled: HS=%d MS=%d MSX=%d"%(nh,nm,nx))

# ---- Signal-RAM cells of the proven gateway link ----
for c in (0x40000751,0x40000774,0x4000077B,0x4000078A,0x4000078D,0x4000079F,0x400007A1):
    label(c, "sig_gw_0C0_to_020_%08X"%c, "Shared signal-RAM: HS 0x0C0 -> MS 0x020 gateway link")
label(0x40000614, "sig_NULL_placeholder", "Volcano null/unused-signal sink; appears in >100 records - IGNORE")

program.endTransaction(tx, True)
project.save(program)
print("labels=%d funcs=%d comments=%d"%(made_labels, made_funcs, made_cmts))
print("SAVED.")
project.close()
