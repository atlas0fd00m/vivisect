


MODE_ARM        = 0
MODE_THUMB      = 1
MODE_JAZELLE    = 2
MODE_THUMBEE    = 3


#Support for different ARM Instruction set versions

# name          bitmask                    decimal         hex
REV_ARMv4   =   0b0000000000000000000001 #        1        0x1
REV_ARMv4T  =   0b0000000000000000000010 #        2        0x2
REV_ARMv5   =   0b0000000000000000000100 #        4        0x4
REV_ARMv5T  =   0b0000000000000000001000 #        8        0x8
REV_ARMv5E  =   0b0000000000000000010000 #       16        0x10
REV_ARMv5J  =   0b0000000000000000100000 #       32        0x20
REV_ARMv5TE =   0b0000000000000001000000 #       64        0x40
REV_ARMv6   =   0b0000000000000010000000 #      128        0x80
REV_ARMv6M  =   0b0000000000000100000000 #      256        0x100
REV_ARMv6T2 =   0b0000000000001000000000 #      512        0x200
REV_ARMv7A  =   0b0000000000010000000000 #     1024        0x400
REV_ARMv7R  =   0b0000000000100000000000 #     2048        0x800
REV_ARMv7M  =   0b0000000001000000000000 #     4096        0x1000
REV_ARMv7EM =   0b0000000010000000000000 #     8192        0x2000
REV_ARMv8A  =   0b0000000100000000000000 #    16384        0x4000
REV_ARMv8R  =   0b0000001000000000000000 #    32768        0x8000
REV_ARMv8M  =   0b0000010000000000000000 #    65536        0x10000

REV_ALL_ARMv4  = (REV_ARMv4 | REV_ARMv4T)
REV_ALL_ARMv5  = (REV_ARMv5 | REV_ARMv5T | REV_ARMv5E | REV_ARMv5J | REV_ARMv5TE)
REV_ALL_ARMv6  = (REV_ARMv6 | REV_ARMv6T2 | REV_ARMv6M)
REV_ALL_ARMv7  = (REV_ARMv7A | REV_ARMv7R | REV_ARMv7M | REV_ARMv7EM) 
REV_ALL_ARMv8  = (REV_ARMv8A | REV_ARMv8R | REV_ARMv8M)

#Todo - For easy instruction filtering add more like:
REV_ALL_TO_ARMv6 = REV_ALL_ARMv4 | REV_ALL_ARMv5 | REV_ALL_ARMv6
REV_ALL_FROM_ARMv6 = REV_ALL_ARMv6 | REV_ALL_ARMv7 | REV_ALL_ARMv8
#Note: since arm must be backwards compatible any depreciated commands
#Would be noted but not removed with the REV_ALL_TO_* if this is even used.
#These are put here for suggestion and comment for now

REV_ALL_ARM = (REV_ALL_ARMv4 | REV_ALL_ARMv5 | REV_ALL_ARMv6 | REV_ALL_ARMv7 | REV_ALL_ARMv8)

#Will be set below, THUMB16 up through v6 except v6T2, THUMB2 from v6T2 up, THUMBEE from v7 up.
REV_THUMB16 = REV_THUMB2  = REV_THUMBEE = 0   

ARCH_REVS = {}
#Iterate through all REV_ARM values and setup related combo values 
for name, val in list(globals().items()):
    if (not name.startswith('REV_ARM')):
        continue
    shortName = name[4:]
    #add to lookup dictionary
    ARCH_REVS[shortName] = val
    #setup thumb versions to Architecture versions
    if (int(shortName[4]) > 6 or shortName == 'ARMv6T2'):
        REV_THUMB2 = REV_THUMB2 | val
        if int(shortName[4])!= 6:
            REV_THUMBEE = REV_THUMBEE | val
    else:
        REV_THUMB16 = REV_THUMB16 | val
#Added thumbs to dictionary
ARCH_REVS['thumb16'] = REV_THUMB16
ARCH_REVS['thumb'] = REV_THUMB2
ARCH_REVS['thumbee'] = REV_THUMBEE
ARCH_REVSLEN = len(ARCH_REVS)

# The supported types of operand shifts (by the 2 bit field)
S_LSL = 0
S_LSR = 1
S_ASR = 2
S_ROR = 3
S_RRX = 4 # FIXME HACK XXX add this

ENDIAN_LSB = 0
ENDIAN_MSB = 1

iencs = (\
    'IENC_DATA_SIMD',
    'IENC_LS_EXCL',
    'IENC_LS_NAPAIR_OFFSET',
    'IENC_LS_REGPAIR_POSTI',
    'IENC_LS_REGPAIR_OFFSET',
    'IENC_LS_REGPAIR_PREI',
    'IENC_LOG_SHFT_REG',
    'IENC_ADDSUB_SHFT_REG',
    'IENC_ADDSUB_EXT_REG',
    'IENC_SIMD_LS_MULTISTRUCT',
    'IENC_SIMD_LS_MULTISTRUCT_POSTI',
    'IENC_SIMD_LS_ONESTRUCT',
    'IENC_SIMD_LS_ONESTRUCT_POSTI',
    'IENC_PC_ADDR',
    'IENC_ADDSUB_IMM',
    'IENC_LOG_IMM',
    'IENC_MOV_WIDE_IMM',
    'IENC_BITFIELD',
    'IENC_EXTRACT',
    'IENC_CMP_BRANCH_IMM',
    'IENC_BRANCH_UNCOND_IMM',
    'IENC_BRANCH_COND_IMM',
    'IENC_EXCP_GEN',
    'IENC_SYS',
    'IENC_TEST_BRANCH_IMM',
    'IENC_BRANCH_UNCOND_REG',
    'IENC_LOAD_REG_LIT',
    'IENC_LS_REG_US_IMM',
    'IENC_LS_REG_UNSC_IMM',
    'IENC_LS_REG_IMM_POSTI',
    'IENC_LS_REG_UNPRIV',
    'IENC_LS_REG_IMM_PREI',
    'IENC_LS_REG_OFFSET',
    'IENC_ADDSUB_CARRY',
    'IENC_COND_CMP_REG',
    'IENC_COND_CMP_IMM',
    'IENC_COND_SEL',
    'IENC_DATA_PROC_3',
    'IENC_DATA_PROC_2',
    'IENC_DATA_PROC_1',
    'IENC_FP_FP_CONV',
    'IENC_FP_COND_COMPARE',
    'IENC_FP_DP2',
    'IENC_FP_COND_SELECT',
    'IENC_FP_IMMEDIATE',
    'IENC_FP_COMPARE',
    'IENC_FP_DP1',
    'IENC_FP_INT_CONV',
    'IENC_FP_DP3',
    'IENC_SIMD_THREE_SAME',
    'IENC_SIMD_THREE_DIFF',
    'IENC_SIMD_TWOREG_MISC',
    'IENC_SIMD_ACROSS_LANES',
    'IENC_SIMD_COPY',
    'IENC_SIMD_VECTOR_IE',
    'IENC_SIMD_MOD_SHIFT_IMM',
    'IENC_SIMD_TBL_TBX',
    'IENC_SIMD_ZIP_UZP_TRN',
    'IENC_SIMD_EXT',
    'IENC_SIMD_SCALAR_THREE_SAME',
    'IENC_SIMD_SCALAR_THREE_DIFF',
    'IENC_SIMD_SCALAR_TWOREG_MISC',
    'IENC_SIMD_SCALAR_PAIRWISE',
    'IENC_SIMD_SCALAR_COPY',
    'IENC_SIMD_SCALAR_IE',
    'IENC_SIMD_SCALAR_SHIFT_IMM',
    'IENC_CRPYTO_AES',
    'IENC_CRYPTO_THREE_SHA',
    'IENC_CRYPTO_TWO_SHA',
    'IENC_RESERVED',
    'IENC_UNDEF',
)

IENC_MAX = len(iencs)

for ieidx in range(IENC_MAX):
    globals()[iencs[ieidx]] = ieidx

instrnames = [
    'ADR',
    'ADRP',
    'ADD',
    'ADDS',
    'SUB',
    'SUBS',
    'AND',
    'ORR',
    'EOR',
    'ANDS',
    'MOV',
    'BFM',
    'EXTR',
    'B',
    'BL',
    'ST',
    'LD',
    'SVC',
    'HVC',
    'SMC',
    'BRK',
    'HLT',
    'DCPS1',
    'DCPS2',
    'DCPS3',
    'MSR',
    'HINT',
    'CLREX',
    'DSB',
    'DMB',
    'ISB',
    'SYS',
    'MRS',
    'BR',
    'BLR',
    'RET',
    'ERET',
    'DRPS',
    'STXRB',
    'STLXRB',
    'LDXRB',
    'LDAXRB',
    'STLRB',
    'LDARB',
    'STXRH',
    'STLXRH',
    'LDXRH',
    'LDAXRH',
    'STLRH',
    'LDARH',
    'STXR',
    'STLXR',
    'STXP',
    'STLXP',
    'LDXR',
    'LDAXR',
    'LDXP',
    'LDAXP',
    'STLR',
    'LDAR',
    'LDR',
    'LDRSW',
    'PRFM',
    'STNP',
    'LDNP',
    'STP',
    'LDP',
    'LDPSW',
    'LDUR',
    'STUR',
    'PRFUM',
    'STTR',
    'LDTR',
    'STR',
    'LDR',
    'ST4',
    'ST1',
    'LD4',
    'LD1',
    'ST3',
    'LD3',
    'ST2',
    'LD2',
    'BIC',
    'EO',
    'OR',
    'ADC',
    'SBC',
    'CCM',
    'CS',
    'MADD',
    'MSUB',
    'SMADDL',
    'SMSUBL',
    'UMADDL',
    'UMSUBL',
    'SMULH',
    'UMULH',
    'UDIV',
    'SDIV',
    'LSLV',
    'LSRV',
    'ASRV',
    'RORV',
    'CRC32',
    'RBIT',
    'REV',
    'CL',
    'SCVTF',
    'UCVTF',
    'FCVTZS',
    'FCVTZU',
    'FCCMP',
    'FMUL',
    'FDIV',
    'FADD',
    'FSUB',
    'FMAX',
    'FMIN',
    'FMAXNM',
    'FMINNM',
    'FNMUL',
    'FCSEL',
    'FMADD',
    'FMSUB',
    'FNMADD',
    'FNMSUB',
    'FCMP',
    'FMOV',
    'FABS',
    'FNEG',
    'FSQRT',
    'FCVT',
    'FRINT',

    'CM',
    'SHL',
    'MUL',
    'AC',
    'ABD',
    'RECP',
    'SQRT',
    'ML',
    'ABS',
    'NEG',
    'XT',
    'CVT',
    'MAX',
    'MIN',
    'DUP',
    'MLA',
    'MLS',
    'SHR',
    'SRA',
    'SLI',
    'SHA1C',
    'SHA1P',
    'SHA1M',
    'SHA1SU0',
    'SHA256H',
    'SHA256H2',
    'SHA256SU1',
    'SHA1H',
    'SHA1SU1',
    'SHA256SU0',
    'AESE',
    'AESD',
    'AESMC',
    'AESIMC',
    'ADDHN',
    'SUBHN',
    'MUL',
    'ABA',
    'ABD',
    'UZP1',
    'TRN1',
    'ZIP1',
    'UZP2',
    'TRN2',
    'ZIP2',
    'CBZ',
    'CBNZ',
    'TBZ',
    'TBNZ',
    'AT',
    'DC',
    'IC',
    'TBLI',
    'BCC',
    'UDF',
]

ins_index = 85
for instr in instrnames:
    globals()['INS_' + instr] = ins_index
    ins_index += 1

#IFLAGS
IF_LE = 1 << 37
IF_HS = 1 << 36
IF_GE = 1 << 35
IF_HI = 1 << 34
IF_EQ = 1 << 33
IF_LT = 1 << 32
IF_GT = 1 << 31
IF_2 = 1 << 25
IF_NEG = 1 << 24
IF_INV = 1 << 23
IF_INC = 1 << 22
IF_EL = 1 << 21
IF_32 = 1 << 20
IF_16 = 1 << 19
IF_P = 1 << 18
IF_PSR_S = 1 << 17
IF_N = 1 << 16
IF_Z = 1 << 15
IF_K = 1 << 14
IF_L = 1 << 13
IF_A = 1 << 12
IF_X = 1 << 11
IF_R = 1 << 10
IF_P = 1 << 9
IF_B = 1 << 8
IF_H = 1 << 7
IF_SW = 1 << 6
IF_S = 1 << 5
IF_W = 1 << 4
IF_E = 1 << 3
IF_M = 1 << 2
IF_I = 1 << 1
IF_U = 1 << 0

IFP_U = 1 << 26
IFP_S = 1 << 27
IFP_P = 1 << 28
IFP_QD = 1 << 29
IFP_R = 1 << 30

IFS = (
    None,
    '.8b',
    '.16b',
    '.4h',
    '.8h',
    '.2s',
    '.4s',
    '.1d',
    '.2d',
)

for ifx in range(1, len(IFS)):
    ifs = IFS[ifx]
    gblname = "IFS" + ifs.upper().replace('.', '_')
    globals()[gblname] = ifx

PM_usr = 0b10000
PM_fiq = 0b10001
PM_irq = 0b10010
PM_svc = 0b10011
PM_mon = 0b10110
PM_abt = 0b10111
PM_hyp = 0b11010
PM_und = 0b11011
PM_sys = 0b11111

# reg stuff stolen from regs.py to support proc_modes
# these are in context of reg_table, not reg_data.  
#  ie. these are indexes into the lookup table.
REG_OFFSET_USR = 17 * (PM_usr&0xf)
REG_OFFSET_FIQ = 17 * (PM_fiq&0xf)
REG_OFFSET_IRQ = 17 * (PM_irq&0xf)
REG_OFFSET_SVC = 17 * (PM_svc&0xf)
REG_OFFSET_MON = 17 * (PM_mon&0xf)
REG_OFFSET_ABT = 17 * (PM_abt&0xf)
REG_OFFSET_HYP = 17 * (PM_hyp&0xf)
REG_OFFSET_UND = 17 * (PM_und&0xf)
REG_OFFSET_SYS = 17 * (PM_sys&0xf)
#REG_OFFSET_CPSR = 17 * 16
REG_OFFSET_CPSR = 16                    # CPSR is available in every mode, and PM_usr and PM_sys don't have an SPSR.

REG_SPSR_usr = REG_OFFSET_USR + 17
REG_SPSR_fiq = REG_OFFSET_FIQ + 17
REG_SPSR_irq = REG_OFFSET_IRQ + 17
REG_SPSR_svc = REG_OFFSET_SVC + 17
REG_SPSR_mon = REG_OFFSET_MON + 17
REG_SPSR_abt = REG_OFFSET_ABT + 17
REG_SPSR_hyp = REG_OFFSET_HYP + 17
REG_SPSR_und = REG_OFFSET_UND + 17
REG_SPSR_sys = REG_OFFSET_SYS + 17

REG_PC = 0xf
REG_SP = 0xd
REG_BP = None
REG_CPSR = REG_OFFSET_CPSR
REG_FLAGS = REG_OFFSET_CPSR    #same location, backward-compat name

proc_modes = { # mode_name, short_name, description, offset, mode_reg_count, PSR_offset, privilege_level
    PM_usr: ("User Processor Mode", "usr", "Normal program execution mode", REG_OFFSET_USR, 15, REG_SPSR_usr, 0),
    PM_fiq: ("FIQ Processor Mode", "fiq", "Supports a high-speed data transfer or channel process", REG_OFFSET_FIQ, 8, REG_SPSR_fiq, 1),
    PM_irq: ("IRQ Processor Mode", "irq", "Used for general-purpose interrupt handling", REG_OFFSET_IRQ, 13, REG_SPSR_irq, 1),
    PM_svc: ("Supervisor Processor Mode", "svc", "A protected mode for the operating system", REG_OFFSET_SVC, 13, REG_SPSR_svc, 1),
    PM_mon: ("Monitor Processor Mode", "mon", "Secure Monitor Call exception", REG_OFFSET_MON, 13, REG_SPSR_mon, 1),
    PM_abt: ("Abort Processor Mode", "abt", "Implements virtual memory and/or memory protection", REG_OFFSET_ABT, 13, REG_SPSR_abt, 1),
    PM_hyp: ("Hyp Processor Mode", "hyp", "Hypervisor Mode", REG_OFFSET_HYP, 13, REG_SPSR_hyp, 2),
    PM_und: ("Undefined Processor Mode", "und", "Supports software emulation of hardware coprocessor", REG_OFFSET_UND, 13, REG_SPSR_und, 1),
    PM_sys: ("System Processor Mode", "sys", "Runs privileged operating system tasks (ARMv4 and above)", REG_OFFSET_SYS, 15, REG_SPSR_sys, 1),
}

VFP_QWORD_REG_COUNT = 32    # ARMv8-A docs

'''
from envi.archs.aarch64.disasm import A64PreFetchOper
#Supported PRFOP options
prfop = (
    A64PreFetchOper(PLD, L1, KEEP),
    A64PreFetchOper(PLD, L1, STRM),
    A64PreFetchOper(PLD, L2, KEEP),
    A64PreFetchOper(PLD, L2, STRM),
    A64PreFetchOper(PLD, L3, KEEP),
    A64PreFetchOper(PLD, L3, STRM),
    '#uimm5',
    '#uimm5',
    A64PreFetchOper(PLI, L1, KEEP),
    A64PreFetchOper(PLI, L1, STRM),
    A64PreFetchOper(PLI, L2, KEEP),
    A64PreFetchOper(PLI, L2, STRM),
    A64PreFetchOper(PLI, L3, KEEP),
    A64PreFetchOper(PLI, L3, STRM),
    '#uimm5',
    '#uimm5',
    A64PreFetchOper(PST, L1, KEEP),
    A64PreFetchOper(PST, L1, STRM),
    A64PreFetchOper(PST, L2, KEEP),
    A64PreFetchOper(PST, L2, STRM),
    A64PreFetchOper(PST, L3, KEEP),
    A64PreFetchOper(PST, L3, STRM),
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
    '#uimm5',
)
'''

sys_op_table = (
    (0b00001111000000, 'at', INS_AT),
    (0b10001111000000, 'at', INS_AT),
    (0b11001111000000, 'at', INS_AT),
    (0b00001111000001, 'at', INS_AT),
    (0b10001111000001, 'at', INS_AT),
    (0b11001111000001, 'at', INS_AT),
    (0b00001111000010, 'at', INS_AT),
    (0b00001111000011, 'at', INS_AT),
    (0b10001111000100, 'at', INS_AT),
    (0b10001111000101, 'at', INS_AT),
    (0b10001111000110, 'at', INS_AT),
    (0b10001111000111, 'at', INS_AT),
    (0b01101110100001, 'dc', INS_DC),
    (0b00001110110001, 'dc', INS_DC),
    (0b00001110110010, 'dc', INS_DC),
    (0b01101111010001, 'dc', INS_DC),
    (0b00001111010010, 'dc', INS_DC),
    (0b01101111011001, 'dc', INS_DC),
    (0b01101111110001, 'dc', INS_DC),
    (0b00001111110010, 'dc', INS_DC),
    (0b00001110001000, 'ic', INS_IC),
    (0b00001110101000, 'ic', INS_IC),
    (0b01101110101001, 'ic', INS_IC),
    (0b10010000000001, 'tlbi', INS_TBLI),
    (0b10010000000101, 'tlbi', INS_TBLI),
    (0b00010000011000, 'tlbi', INS_TBLI),
    (0b10010000011000, 'tlbi', INS_TBLI),
    (0b11010000011000, 'tlbi', INS_TBLI),
    (0b00010000011001, 'tlbi', INS_TBLI),
    (0b10010000011001, 'tlbi', INS_TBLI),
    (0b11010000011001, 'tlbi', INS_TBLI),
    (0b00010000011010, 'tlbi', INS_TBLI),
    (0b00010000011011, 'tlbi', INS_TBLI),
    (0b10010000011100, 'tlbi', INS_TBLI),
    (0b00010000011101, 'tlbi', INS_TBLI),
    (0b10010000011101, 'tlbi', INS_TBLI),
    (0b11010000011101, 'tlbi', INS_TBLI),
    (0b10010000011110, 'tlbi', INS_TBLI),
    (0b00010000011111, 'tlbi', INS_TBLI),
    (0b10010000100001, 'tlbi', INS_TBLI),
    (0b10010000100101, 'tlbi', INS_TBLI),
    (0b00010000111000, 'tlbi', INS_TBLI),
    (0b10010000111000, 'tlbi', INS_TBLI),
    (0b11010000111000, 'tlbi', INS_TBLI),
    (0b00010000111001, 'tlbi', INS_TBLI),
    (0b10010000111001, 'tlbi', INS_TBLI),
    (0b11010000111001, 'tlbi', INS_TBLI),
    (0b00010000111010, 'tlbi', INS_TBLI),
    (0b00010000111011, 'tlbi', INS_TBLI),
    (0b10010000111100, 'tlbi', INS_TBLI),
    (0b00010000111101, 'tlbi', INS_TBLI),
    (0b10010000111101, 'tlbi', INS_TBLI),
    (0b11010000111101, 'tlbi', INS_TBLI),
    (0b10010000111110, 'tlbi', INS_TBLI),
    (0b00010000111111, 'tlbi', INS_TBLI),
)

barrier_option_table = (
    0,
    'OSHLD',
    'OSHST',
    'OSH',
    4,
    'NSHLD',
    'NSHST',
    'NSH',
    8,
    'ISHLD',
    'ISHST',
    'ISH',
    12,
    'LD',
    'ST',
    'SY',
)

cond_table = (
    'EQ',
    'NE',
    'CS',
    'CC',
    'MI',
    'PL',
    'VS',
    'VC',
    'HI',
    'LS',
    'GE',
    'LT',
    'GT',
    'LE',
    'AL',
    'NV^b', #FIXME
)
