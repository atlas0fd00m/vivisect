# vivisect/envi/archs/esp32/regs.py
"""
ESP32 (Xtensa LX6) register definitions for ENVI/Vivisect.

Pattern matches other architectures:
  - define registers as (name, bitsize)
  - addLocalEnums(locals(), REGDEF) to create REG_* indices
  - define meta-registers (aliases/bitfields) as tuples
  - define status bitfields for PS (processor status)
  - load into RegisterContext with loadRegDef()/loadRegMetas()
  - setRegisterIndexes(PC, SP, PS)
"""

import envi
from envi import registers as e_regs

# ---------------------------------------------------------------------------
# 1) Base registers: (name, bitsize)
# Xtensa LX6/ESP32 general registers are a0..a15 (32-bit).
# We also model commonly-used special regs as 32-bit scalars for analysis.
# ---------------------------------------------------------------------------
REGDEF = (
    # General-purpose address regs
    ('a0',  32), ('a1',  32), ('a2',  32), ('a3',  32),
    ('a4',  32), ('a5',  32), ('a6',  32), ('a7',  32),
    ('a8',  32), ('a9',  32), ('a10', 32), ('a11', 32),
    ('a12', 32), ('a13', 32), ('a14', 32), ('a15', 32),

    # Pseudo/special registers
    ('pc',  32),   # program counter
    ('ps',  32),   # processor status
    ('sar', 32),   # shift amount register
    ('lbeg', 32),  # loop begin
    ('lend', 32),  # loop end
    ('lcount', 32),# loop count
    ('scompare1', 32),
    ('br', 32),    # window/base (present on some configs; kept for analysis)
    ('litbase', 32),
)

# Create REG_* enum indices in this module's locals (REG_A0, REG_PC, REG_PS, etc.)
e_regs.addLocalEnums(locals(), REGDEF)

# ---------------------------------------------------------------------------
# 2) Meta-registers (aliases / bit ranges):
# Each tuple: (meta_name, REG_*, start_bit, bit_size)
# ---------------------------------------------------------------------------
METADEF = [
    # Friendly aliases
    ('sp', REG_A1, 0, 32),   # stack pointer
    ('ra', REG_A0, 0, 32),   # return address (conventionally a0)
]

# Make META_* names (and meta-index constants if your Vivisect build supports it)
e_regs.addLocalMetas(locals(), METADEF)

# ---------------------------------------------------------------------------
# 3) Status meta-registers (bitfields) for PS (Processor Status):
# Tuples: (flag_name, REG_*, start_bit, bit_size, long_name)
#
# NOTE: Xtensa PS varies by config. These fields reflect common ESP32/LX6 usage.
# If you need exactness for every bit, adjust to match your TRM build.
# ---------------------------------------------------------------------------
STATUSDEF = [
    ('INTLEVEL', REG_PS, 0,  4, 'Interrupt Level'),
    ('EXCM',     REG_PS, 4,  1, 'Exception Mode'),
    ('UM',       REG_PS, 5,  1, 'User Mode'),
    ('RING',     REG_PS, 6,  2, 'Privilege Ring'),      # present on some configs
    ('WOE',      REG_PS, 18, 1, 'Window Overflow Enable'),
    ('CALLINC',  REG_PS, 16, 2, 'Call Increment'),
]

# Create STATUS_* meta constants for easy reference
####e_regs.addLocalStatusMetas(locals(), STATUSDEF)
####e_regs.addLocalStatusMetas(locals(), STATUSDEF, REG_PS, 'ps')
e_regs.addLocalStatusMetas(locals(), METADEF, STATUSDEF, 'ps')


# ---------------------------------------------------------------------------
# 4) RegisterContext implementation
#   - loadRegDef with the base list
#   - loadRegMetas with meta + status lists
#   - setRegisterIndexes(pc_idx, sp_idx, ps_idx)
# ---------------------------------------------------------------------------
###class ESP32RegisterContext(envi.RegisterContext):
class ESP32RegisterContext(e_regs.RegisterContext):
    def __init__(self):
        super().__init__()
        # Load base regs and metas
        self.loadRegDef(REGDEF)
        self.loadRegMetas(METADEF, STATUSDEF)

        # Tell ENVI which indices map to PC, SP, and PS
        self.setRegisterIndexes(REG_PC, REG_A1, REG_PS)

    # Optional: If you want custom pretty names, you can override getRegisterName.
    # The default from RegisterContext will use the names from REGDEF.
    # def getRegisterName(self, rid):
    #     return super().getRegisterName(rid)


