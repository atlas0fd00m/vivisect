# vivisect/envi/archs/esp32/const.py
"""
ESP32 (Xtensa LX6) architecture constants for ENVI/Vivisect.

The encoding follows the public Xtensa nibble-based opcode tree:
  op0  = bits[3:0]   (low nibble of byte 0)
  t    = bits[7:4]   (high nibble of byte 0)
  s    = bits[11:8]  (low nibble  of byte 1)
  r    = bits[15:12] (high nibble of byte 1)
  op1  = bits[19:16] (low nibble  of byte 2)
  op2  = bits[23:20] (high nibble of byte 2)

Most instructions are 24-bit; several common forms have 16-bit “.N” encodings.
"""

# ----------------------------
# General-purpose registers
# ----------------------------
# Xtensa uses "address" registers a0..a15 (aka AR0..AR15).
REG_A0  = 0
REG_A1  = 1  # stack pointer (sp)
REG_A2  = 2
REG_A3  = 3
REG_A4  = 4
REG_A5  = 5
REG_A6  = 6
REG_A7  = 7
REG_A8  = 8
REG_A9  = 9
REG_A10 = 10
REG_A11 = 11
REG_A12 = 12
REG_A13 = 13
REG_A14 = 14
REG_A15 = 15

# Pseudo / special
REG_PC   = 32
REG_PS   = 33
REG_SAR  = 34
REG_LBEG = 35
REG_LEND = 36
REG_LCOUNT = 37
REG_SCOMPARE1 = 38
REG_BR    = 39  # BR / window-base (if present on some configs)
REG_LITBASE = 40

# Sizes (bytes)
REG_SIZE_32 = 4

# ----------------------------
# Disasm flags / features
# ----------------------------
IF_B       = 0x00000001  # branch
IF_CALL    = 0x00000002
IF_RET     = 0x00000004
IF_COND    = 0x00000008
IF_LOAD    = 0x00000010
IF_STORE   = 0x00000020


# Instruction IDs (stable integers for fast compares)
INS_INVALID = 0

INS_ADD     = 1
INS_ADDI    = 2
INS_ADDX2   = 3
INS_ADDX4   = 4
INS_ADDX8   = 5
INS_SUB     = 6
INS_SUBX2   = 7
INS_SUBX4   = 8
INS_SUBX8   = 9
INS_AND     = 10
INS_OR      = 11
INS_XOR     = 12
INS_EXTUI   = 13
INS_SLLI    = 14
INS_SRLI    = 15
INS_SRAI    = 16
INS_SLL     = 17
INS_SRL     = 18
INS_SRA     = 19
INS_NEG     = 20
INS_ABS     = 21
INS_NSAU    = 22
INS_MOV     = 23
INS_MOVI    = 24
INS_L32R    = 25
INS_L8UI    = 26
INS_L16UI   = 27
INS_L16SI   = 28
INS_L32I    = 29
INS_S8I     = 30
INS_S16I    = 31
INS_S32I    = 32
INS_J       = 33
INS_JX      = 34
INS_BEQZ    = 35
INS_BNEZ    = 36
INS_BLTZ    = 37
INS_BGEZ    = 38
INS_BEQI    = 39
INS_BNEI    = 40
INS_BLTI    = 41
INS_BGEI    = 42
INS_BLTUI   = 43
INS_BGEUI   = 44
INS_CALL0   = 45
INS_CALL4   = 46
INS_CALL8   = 47
INS_CALL12  = 48
INS_CALLX0  = 49
INS_CALLX4  = 50
INS_CALLX8  = 51
INS_CALLX12 = 52
INS_RET     = 53
INS_RETW    = 54
INS_ENTRY   = 55
INS_MEMW    = 56
INS_RSR     = 57
INS_WSR     = 58
INS_XSR     = 59
INS_SYSCALL = 60
INS_BREAK   = 61
INS_WAITI   = 62
INS_NOP     = 63

# Narrow (.N) forms — use _N suffix (no dots in identifiers)
INS_MOV_N   = 80
INS_ADDI_N  = 81
INS_L32I_N  = 82
INS_S32I_N  = 83
INS_ADD_N   = 84
INS_MOVI_N  = 85

# Mnemonic ⇄ ID maps
INS_TO_MNEM = {
    INS_ADD:"add", INS_ADDI:"addi", INS_ADDX2:"addx2", INS_ADDX4:"addx4", INS_ADDX8:"addx8",
    INS_SUB:"sub", INS_SUBX2:"subx2", INS_SUBX4:"subx4", INS_SUBX8:"subx8",
    INS_AND:"and", INS_OR:"or", INS_XOR:"xor", INS_EXTUI:"extui",
    INS_SLLI:"slli", INS_SRLI:"srli", INS_SRAI:"srai", INS_SLL:"sll", INS_SRL:"srl", INS_SRA:"sra",
    INS_NEG:"neg", INS_ABS:"abs", INS_NSAU:"nsau",
    INS_MOV:"mov", INS_MOVI:"movi",
    INS_L32R:"l32r", INS_L8UI:"l8ui", INS_L16UI:"l16ui", INS_L16SI:"l16si", INS_L32I:"l32i",
    INS_S8I:"s8i", INS_S16I:"s16i", INS_S32I:"s32i",
    INS_J:"j", INS_JX:"jx",
    INS_BEQZ:"beqz", INS_BNEZ:"bnez", INS_BLTZ:"bltz", INS_BGEZ:"bgez",
    INS_BEQI:"beqi", INS_BNEI:"bnei", INS_BLTI:"blti", INS_BGEI:"bgei",
    INS_BLTUI:"bltui", INS_BGEUI:"bgeui",
    INS_CALL0:"call0", INS_CALL4:"call4", INS_CALL8:"call8", INS_CALL12:"call12",
    INS_CALLX0:"callx0", INS_CALLX4:"callx4", INS_CALLX8:"callx8", INS_CALLX12:"callx12",
    INS_RET:"ret", INS_RETW:"retw", INS_ENTRY:"entry", INS_MEMW:"memw",
    INS_RSR:"rsr", INS_WSR:"wsr", INS_XSR:"xsr",
    INS_SYSCALL:"syscall", INS_BREAK:"break", INS_WAITI:"waiti", INS_NOP:"nop",
    INS_MOV_N:"mov.n", INS_ADDI_N:"addi.n", INS_L32I_N:"l32i.n", INS_S32I_N:"s32i.n",
    INS_ADD_N:"add.n", INS_MOVI_N:"movi.n",
}

MNEM_TO_INS = {m: i for (i, m) in INS_TO_MNEM.items()}

