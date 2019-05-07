#!/usr/bin/env python

import re
import sys
import collections

# VLE instructions are all prefixed with se_ or e_, but the VLE cores do
# support a small subset of EREF defined instructions (defined in section
# 3.1 of the VLEPEM).
#
# The format of all lines in the IDA produced listing is:
# address |    data   | 16 spaces | disassembly
# XXXXXXXX XX XX ?? ??     ...      e_lis ...
#
# Lines with no data are ignored, any non-code information in the listing can
# be ignored by ensuring that the data is either 2 or 4 bytes - if it is
# 2 bytes then 6 placeholder spaces will be present - 16 spaces, and then an
# instruction that does not start with a ".".  All data defined in IDA starts 
# with ".":
#   .byte
#   .word
#   .dword
#   .qword
#
# This regex first finds all instructions that need to have non-register
# operands adjusted before they can be useful for using in ppc unit tests.
# After all instructions that require modification are found, there are 3
# placeholder patterns at the end to catch SE, E and PPC instructions that need
# no adjustments.
#
# All trailing whitespace and comments is dropped.

class lst_parser(object):
    Token = collections.namedtuple('Token', ['type', 'match', 'value', 'column'])

    def __init__(self):
        token_spec = [
            ('SECTION64',    r'^[0-9A-Za-z_.]+:[0-9A-Fa-f]{16}'),
            ('SECTION32',    r'^[0-9A-Za-z_.]+:[0-9A-Fa-f]{8}'),
            ('ADDR64',       r'^[0-9A-Fa-f]{16}'),
            ('ADDR32',       r'^[0-9A-Fa-f]{8}'),
            ('BYTES',        r' [0-9A-Fa-f]{2} [0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2} [0-9A-Fa-f]{2}| {6})?'),
            ('DATA',         r'\.(?:byte|short|dword|qword)'),
            ('STRUCTDATA',   r' {17}[a-zA-Z][0-9A-Za-z_.]+ +<[x0-9A-Fa-f, ]+>'),
            ('REG',          r'\b(?:cr|r|v|fpr|f)[0-9]{1,2}\b'),
            ('ASM',          r' {17}(?:e_|se_)?[a-z][a-z0-9]*\b\.?(?: |$)'),
            ('CONDITION',    r'(?:4 ?\* ?cr[0-7] ?\+ ?)?(?:lt|gt|eq|so|un)\b'),
            ('COMMENT',      r'#.*'),
            ('STRING',       r'".*"'),
            ('INDIRECT_REF', r'\(r[0-9]{1,2}\)'),
            ('LABEL_MATH',   r'\(?[^-(), ]+ ?[-+] ?[^-+(), ]+\)?(?:@[a-z]+)?'),
            ('LABEL',        r'[^-+(), 0-9][^-+(), ]*'),
            ('DEC_CONST',    r'(?:-)?\b[0-9]+\b'),
            ('HEX_CONST',    r'(?:-)?\b0x[0-9A-Fa-f]+\b'),
        ]
        self.token_regex = re.compile('|'.join('(?P<%s>%s)' % pair for pair in token_spec))

    def tokenize(self, line):
        for obj in self.token_regex.finditer(line):
            kind = obj.lastgroup
            match = obj.group().strip()

            if kind in ['SECTION32', 'SECTION64']:
                value = int(match.split(':')[1], 16)
            elif kind in ['ADDR32', 'ADDR64', 'HEX_CONST']:
                value = int(match, 16)
            elif kind == 'DEC_CONST':
                value = int(match)
            elif kind == 'BYTES':
                match = match.replace(' ', '')
                value = int(match, 16)
            else:
                value = match

            yield lst_parser.Token(kind, match, value, obj.start())

class ppc_instr(object):
    Instructions = {
        # Unconditional Branches
        'se_b':         'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_bl':        'signed_bd8',              # BD8:  signed 8 bit value << 1
        'e_b':          'signed_bd24',             # BD24: signed 24 bit value << 1
        'e_bl':         'signed_bd24',             # BD24: signed 24 bit value << 1
        'b':            'signed_i',                # I:    signed 24 bit value << 2
        'bl':           'signed_i',                # I:    signed 24 bit value << 2

        # Conditional Branches
        'se_bge':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_bgt':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_ble':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_blt':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_bne':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'se_beq':       'signed_bd8',              # BD8:  signed 8 bit value << 1
        'e_bge':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_bgt':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_ble':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_blt':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_bne':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_beq':        'signed_bd15',             # BD15: signed 15 bit value << 1
        'e_bdnz':       'signed_bd15',             # BD15: signed 15 bit value << 1
        'bge':          'signed_b',                # I:    signed 14 bit value << 2
        'bgt':          'signed_b',                # I:    signed 14 bit value << 2
        'ble':          'signed_b',                # I:    signed 14 bit value << 2
        'blt':          'signed_b',                # I:    signed 14 bit value << 2
        'bne':          'signed_b',                # I:    signed 14 bit value << 2
        'beq':          'signed_b',                # I:    signed 14 bit value << 2
        'bdnz':         'signed_b',                # I:    signed 14 bit value << 2
        'bdnzf':        'signed_b',                # I:    signed 14 bit value << 2
        'bdnzt':        'signed_b',                # I:    signed 14 bit value << 2
        'bns':          'signed_b',                # I:    signed 14 bit value << 2
        'bdz':          'signed_b',                # I:    signed 14 bit value << 2
        'bcl':          'signed_b',                # I:    signed 14 bit value << 2
        
        # Integer Select
        'iseleq':       'special_r0_handling',     # A:    special handling of param rA r0 case
        'isellt':       'special_r0_handling',     # A:    special handling of param rA r0 case
        'iselgt':       'special_r0_handling',     # A:    special handling of param rA r0 case

        # Store Doubleword
        'std':          'signed_ds',               # DS:   unsigned 14 bit value << 2
        'stdu':         'signed_ds',               # DS:   unsigned 14 bit value << 2

        # Store Float Double
        'stfd':         'signed_d',                # D:    unsigned 16 bit value
        
        # Load Doubleword
        'ld':           'signed_ds',               # DS:   unsigned 14 bit value << 2
        'ldu':          'signed_ds',               # DS:   unsigned 14 bit value << 2

        # Store Word
        'se_stw':       'unsigned_sd4_word_addr',  # SD4:  unsigned 4 bit value << 2
        'e_stw':        'signed_d',                # D:    signed 16 bit value
        'e_stwu':       'signed_d8',               # D8:   signed 8 bit value
        'e_stmw':       'signed_d8',               # D8:   signed 8 bit value
        'e_stmvgprw':   'signed_d8',               # D8:   signed 8 bit value
        'e_stmvsprw':   'signed_d8',               # D8:   signed 8 bit value
        'e_stmvsrrw':   'signed_d8',               # D8:   signed 8 bit value
        'e_stmvcrrw':   'signed_d8',               # D8:   signed 8 bit value
        'e_stmvdrrw':   'signed_d8',               # D8:   signed 8 bit value
        'stw':          'signed_d',                # D:    unsigned 16 bit value
        'stwu':         'signed_d',                # D:    unsigned 16 bit value
        
        # Store Half Wor'd
        'se_sth':       'unsigned_sd4_half_addr',  # SD4:  unsigned 4 bit value << 1
        'e_sth':        'signed_d',                # D:    signed 16 bit value
        'e_sthu':       'signed_d8',               # D8:   signed 8 bit value
        'sth':          'signed_d',                # D:    unsigned 16 bit value
        'sthu':         'signed_d',                # D:    unsigned 16 bit value
        
        # Store Byte
        'se_stb':       'unsigned_sd4_byte_addr',  # SD4:  unsigned 4 bit value
        'e_stb':        'signed_d',                # D:    signed 16 bit value
        'e_stbu':       'signed_d8',               # D8:   signed 8 bit value
        'stb':          'signed_d',                # D:    unsigned 16 bit value
        'stbu':         'signed_d',                # D:    unsigned 16 bit value
        
        # Load Word
        'se_lwz':       'unsigned_sd4_word_addr',  # SD4:  unsigned 4 bit value << 2
        'e_lwz':        'signed_d',                # D:    signed 16 bit value
        'e_lwz':        'signed_d',                # D:    signed 16 bit value
        'e_lmw':        'signed_d8',               # D8:   signed 8 bit value
        'e_lwzu':       'signed_d8',               # D8:   signed 8 bit value
        'e_ldmvgprw':   'signed_d8',               # D8:   signed 8 bit value
        'e_ldmvsprw':   'signed_d8',               # D8:   signed 8 bit value
        'e_ldmvsrrw':   'signed_d8',               # D8:   signed 8 bit value
        'e_ldmvcrrw':   'signed_d8',               # D8:   signed 8 bit value
        'e_ldmvdrrw':   'signed_d8',               # D8:   signed 8 bit value
        'lwz':          'signed_d',                # D:    signed 16 bit value
        'lwa':          'signed_d',                # D:    signed 16 bit value
        'lwzu':         'signed_d',                # D:    signed 16 bit value
        'lwzx':         'special_r0_handling',     # X:    special handling of param rA r0 case

        # Load Float Double
        'lfd':          'signed_d',                # D:    unsigned 16 bit value

        # Load Float Single
        'lfs':          'signed_d',                # D:    unsigned 16 bit value

        # Load Half
        'se_lhz':       'unsigned_sd4_half_addr',  # SD4:  unsigned 4 bit value << 1
        'e_lhz':        'signed_d',                # D:    signed 16 bit value
        'e_lhzu':       'signed_d8',               # D8:   signed 8 bit value
        'e_lha':        'signed_d',                # D:    signed 16 bit value
        'e_lhau':       'signed_d8',               # D8:   signed 8 bit value
        'lhz':          'signed_d',                # D:    signed 16 bit value
        'lha':          'signed_d',                # D:    signed 16 bit value
        'lhzu':         'signed_d',                # D:    signed 16 bit value
        'lhax':         'special_r0_handling',     # X:    special handling of param rA r0 case
        
        # Load Byte
        'se_lbz':       'unsigned_sd4_byte_addr',  # SD4:  unsigned 4 bit value
        'e_lbz':        'signed_d',                # D:    signed 16 bit value
        'e_lbzu':       'signed_d8',               # D8:   signed 8 bit value
        'lbz':          'signed_d',                # D:    signed 16 bit value
        'lba':          'signed_d',                # D:    signed 16 bit value
        'lbzu':         'signed_d',                # D:    signed 16 bit value
        
        # Load Immediate'
        'se_li':        'unsigned_im7',            # IM7:  unsigned 7 bit value
        'e_li':         'signed_li20',             # LI20: signed 20 bit value
        'e_lis':        'unsigned_i16l',           # I16L: unsigned 16 bit value
        'li':           'signed_d',                # D:    signed 16 bit value
        
        # OR Immediate
        'e_or2i':       'unsigned_i16l',           # I16L: unsigned 16 bit value
        'e_or2is':      'unsigned_i16l',           # I16L: unsigned 16 bit value
        'e_ori':        'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_ori.':       'unsigned_sci8',           # SCI8: "unsigned" 32 bit value

        # XOR Immediate
        'e_xori':       'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_xori.':      'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        
        # AND Immediate
        'se_andi':      'unsigned_im5',            # IM5:  unsigned 5 bit value
        'e_and2i.':     'unsigned_i16l',           # I16L: unsigned 16 bit value
        'e_and2is.':    'unsigned_i16l',           # I16L: unsigned 16 bit value
        'e_andi':       'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_andi.':      'unsigned_sci8',           # SCI8: "unsigned" 32 bit value

        # Shift Immediate
        'se_srwi':      'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_srawi':     'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_slwi':      'unsigned_im5',            # IM5:  unsigned 5 bit value
        'e_srwi':       'unsigned_x',              # X:    unsigned 5 bit value
        'e_srwi.':      'unsigned_x',              # X:    unsigned 5 bit value
        'e_slwi':       'unsigned_x',              # X:    unsigned 5 bit value
        'e_rlwi':       'unsigned_x',              # X:    unsigned 5 bit value
        'e_rlwimi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_rlwinm':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_extrwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_extlwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_clrlslwi':   'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_clrlwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_insrwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_clrrwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_rotrwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'e_rotlwi':     'unsigned_m',              # M:    3 unsigned 5 bit values
        'srawi':        'unsigned_x',              # X:    unsigned 5 bit value

        # Bit Manipulate Immediate
        'se_bmaski':    'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_bclri':     'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_bseti':     'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_btsti':     'unsigned_im5',            # IM5:  unsigned 5 bit value
        'se_bgeni':     'unsigned_im5',            # IM5:  unsigned 5 bit value

        # Compare Immediate
        'se_cmpli':     'unsigned_oim5',           # OIM5: unsigned 5 bit value
        'se_cmpi':      'unsigned_im5',            # IM5:  unsigned 5 bit value
        'e_cmpli':      'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_cmpi':       'signed_sci8',             # SCI8: "signed" 32 bit value
        'e_cmpl16i':    'unsigned_i16a',           # IA16 (same as I16A?): unsigned 16 bit value
        'e_cmp16i':     'signed_i16a',             # IA16 (same as I16A?): signed 16 bit value
        
        # Add Immediate
        'se_addi':      'unsigned_oim5',           # OIM5: unsigned 5 bit value
        'e_add16i':     'signed_d',                # D:    signed 16 bit value
        'e_add2i.':     'signed_i16a',             # I16A: signed 16 bit value
        'e_add2is':     'unsigned_i16a',           # I16A: unsigned 16 bit value
        'e_addi':       'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_addi.':      'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'addi':         'signed_d',                # D:    signed 16 bit value
        'addis':        'signed_d',                # D:    signed 16 bit value
        'addic':        'signed_d',                # D:    signed 16 bit value
        'addic.':       'signed_d',                # D:    signed 16 bit value

        # Multiply Immediate
        'e_mulli':      'signed_sci8',             # SCI8: "signed" 32 bit value
        'e_mull2i':     'signed_i16a',             # I16A: signed 16 bit value

        # Subtract Immediate
        'se_subi':      'unsigned_oim5',           # OIM5: unsigned 5 bit value
        'se_subi.':     'unsigned_oim5',           # OIM5: unsigned 5 bit value
        'e_subfic':     'unsigned_sci8',           # SCI8: "unsigned" 32 bit value
        'e_subfic.':    'unsigned_sci8',           # SCI8: "unsigned" 32 bit value

        # Move To/From SPR
        'mtspr':        'xfx_spr',                 # XFX: Special Purpose Register
        'mfspr':        'xfx_spr',                 # XFX: Special Purpose Register

        # Other
        'mbar':         'xfx',                     # XFX: special MO flag
        'wrteei':       'wrteei',                  # X:   special E flag
    }

    def __init__(self, tokens, line_nr):
        self._line_nr = line_nr
        self._tokens = tokens
        self.data = None
        self.op = None
        self.args = []

        for tok in tokens:
            if tok.type == 'BYTES':
                self.data = tok
            elif tok.type == 'ASM':
                self.op = tok
            elif tok.type in ['REG', 'INDIRECT_REF', 'DEC_CONST', 'HEX_CONST', 'CONDITION']:
                self.args.append(tok)
            elif tok.type in ['LABEL', 'LABEL_MATH']:
                self.args.append(lst_parser.Token('TBD', tok, 'TBD', tok.column))

        # Ensure that there is at most 1 TBD arg
        tbd_args = [a for a in self.args if a.type in ['TBD', 'DEC_CONST', 'HEX_CONST']]
        # Special case, force all mtspr/mfspr instructions to get the immediate
        # values recalculated
        #if len(tbd_args) == 1 or self.op.value in ['mtspr', 'mfspr']:
        if len(tbd_args) >= 1:
            self.fix()

    def fix(self):
        # IDA listings use some incorrect mnemononics
        rename_mapping = {
                'eieio':       'mbar',
                'e_lmvgprw':   'e_ldmvgprw',
                'e_lmvsprw':   'e_ldmvsprw',
                'e_lmvsrrw':   'e_ldmvsrrw',
                'e_lmvcsrrw':  'e_ldmvcsrrw',
                'e_lmvdsrrw':  'e_ldmvdsrrw',
        }

        if self.op.value in rename_mapping:
            # 'eieio' was the old PPC instruction, it should now be called 'mbar'
            new_op = lst_parser.Token('ASM', self.op.match, rename_mapping[self.op.value], self.op.column)
            self.op = new_op

        fixed_args = []
        for arg in self.args:
            if arg.type in ['TBD', 'DEC_CONST', 'HEX_CONST']:
                if self.op.value in ppc_instr.Instructions:
                    new_arg = getattr(self, ppc_instr.Instructions[self.op.value])(self.data.value)
                    if isinstance(new_arg, list):
                        fixed_args.extend(new_arg)
                    else:
                        fixed_args.append(new_arg)
                else:
                    err = '{} (@ {}) needs fixing ({})'.format(self.op.value, self._line_nr, self._tokens)
                    raise NotImplementedError(err)
            else:
                fixed_args.append(arg)
        self.args = fixed_args

    def __repr__(self):
        arg_list = ''
        if self.args:
            if self.args[-1].type == 'INDIRECT_REF':
                arg_list = ' ' + ppc_instr._str_arg_list(self.args[:-1]) + self.args[-1].value
            else:
                arg_list = ' ' + ppc_instr._str_arg_list(self.args)

        return str((self.data.match, self.op.value + arg_list))

    def __str__(self):
        arg_list = ''
        if self.args:
            if self.args[-1].type == 'INDIRECT_REF':
                arg_list = ' ' + ppc_instr._str_arg_list(self.args[:-1]) + self.args[-1].value
            else:
                arg_list = ' ' + ppc_instr._str_arg_list(self.args)

        if self.op.value in ['tdi', 'vaddubm']:
            fmt = '#{0.data.match: <8} {0.op.value}{1}'
        else:
            fmt = '{0.data.match: <8} {0.op.value}{1}'
        return fmt.format(self, arg_list)

    @classmethod
    def _str_arg(cls, arg):
        if isinstance(arg.value, str):
            return arg.value
        else:
            return hex(arg.value)

    @classmethod
    def _str_arg_list(cls, arg_list):
        return ','.join([cls._str_arg(a) for a in arg_list])

    @classmethod
    def _dec_token(cls, val):
        return lst_parser.Token('DEC_CONST', str(val), val, None)

    @classmethod
    def _hex_token(cls, val):
        return lst_parser.Token('HEX_CONST', hex(val), val, None)

    @classmethod
    def signed_bd8(cls, data):
        sign = 0x0080
        mask = 0x007F
        val = ((data & mask) - (data & sign)) * 2
        return cls._dec_token(val)
        
    @classmethod
    def signed_bd15(cls, data):
        sign = 0x00004000
        mask = 0x00003FFF
        shifted = data >> 1
        val = ((shifted & mask) - (shifted & sign)) * 2
        return cls._dec_token(val)
        
    @classmethod
    def signed_bd24(cls, data):
        sign = 0x00800000
        mask = 0x007FFFFF
        shifted = data >> 1
        val = ((shifted & mask) - (shifted & sign)) * 2
        return cls._dec_token(val)

    @classmethod
    def signed_i(cls, data):
        sign = 0x00800000
        mask = 0x007FFFFF
        shifted = data >> 2
        val = ((shifted & mask) - (shifted & sign)) * 4
        return cls._dec_token(val)

    @classmethod
    def signed_b(cls, data):
        sign = 0x00008000
        mask = 0x00007FFF
        shifted = data >> 2
        val = ((shifted & mask) - (shifted & sign)) * 4
        return cls._dec_token(val)

    @classmethod
    def unsigned_sd4_word_addr(cls, data):
        mask = 0x0F00
        val = (data & mask) >> 6 # val >> 8 then << 2
        return cls._dec_token(val)

    @classmethod
    def unsigned_sd4_half_addr(cls, data):
        mask = 0x0F00
        val = (data & mask) >> 7 # val >> 8 then << 1
        return cls._dec_token(val)

    @classmethod
    def unsigned_sd4_byte_addr(cls, data):
        mask = 0x0F00
        val = (data & mask) >> 8
        return cls._dec_token(val)

    @classmethod
    def signed_d8(cls, data):
        sign = 0x00000080
        mask = 0x0000007F
        val = (data & mask) - (data & sign)
        return cls._dec_token(val)

    @classmethod
    def signed_ds(cls, data):
        sign = 0x00008000
        mask = 0x00007FFC # This format takes bits 16-29 then left shifts by 2
                          # bits, which is the same as just masking off the
                          # lower 2 bits
        val = (data & mask) - (data & sign)
        return cls._dec_token(val)

    @classmethod
    def signed_d(cls, data):
        sign = 0x00008000
        mask = 0x00007FFF
        val = (data & mask) - (data & sign)
        return cls._dec_token(val)

    @classmethod
    def unsigned_im7(cls, data):
        mask = 0x07F0
        val = (data & mask) >> 4

        # Since this is a simple unsigned value it is most commonly used with
        # hex values
        return cls._hex_token(val)

    @classmethod
    def signed_li20(cls, data):
        mask_1 = 0x00007800
        mask_2 = 0x001F0000
        mask_3 = 0x000007FF
        up_val = (data & mask_1) << 5  # upper >> 11 then << 16
        mid_val = (data & mask_2) >> 5 # mid >> 16 then << 11
        low_val = (data & mask_3)      # no shift

        unsigned_val = up_val | mid_val | low_val

        sign = 0x00080000
        mask = 0x0007FFFF
        signed_val = (unsigned_val & mask) - (unsigned_val & sign)
        return cls._dec_token(signed_val)

    @classmethod
    def _get_i16l_imm(cls, data):
        mask_1 = 0x001F0000
        mask_2 = 0x000007FF
        up_val = (data & mask_1) >> 5  # upper >> 16 then << 11
        low_val = (data & mask_2)      # no shift
        unsigned_val = up_val | low_val
        return unsigned_val 

    @classmethod
    def unsigned_i16l(cls, data):
        val = cls._get_i16l_imm(data)

        # This unsigned immediate form is most often used in logical (AND/OR)
        # operations, make the token in hex format.
        return cls._hex_token(val)

    @classmethod
    def _get_im5_imm(cls, data):
        mask = 0x01F0
        val = (data & mask) >> 4
        return val 

    @classmethod
    def unsigned_im5(cls, data):
        val = cls._get_im5_imm(data)

        # Make hex tokens for logical operation operands
        return cls._hex_token(val)

    @classmethod
    def unsigned_oim5(cls, data):
        val = cls._get_im5_imm(data) + 1

        # Make since this is used in "se_addi", make this a decimal operand
        return cls._dec_token(val)

    @classmethod
    def unsigned_x(cls, data):
        mask = 0x0000F100
        val = (data & mask) >> 11

        # Make hex tokens for logical operation operands
        return cls._hex_token(val)

    @classmethod
    def unsigned_m(cls, data):
        mask_1 = 0x0000F100
        mask_2 = 0x000007C0
        mask_3 = 0x0000003E
        shift = (data & mask_1) >> 11
        mask_begin = (data & mask_2) >> 6
        mask_end = (data & mask_3) >> 1

        # Make hex tokens for logical operation operands
        return [cls._hex_token(shift), cls._hex_token(mask_begin), cls._hex_token(mask_end)]

    @classmethod
    def special_r0_handling(cls, data):
        mask = 0x001F0000
        val = (data & mask) >> 16

        if val == 0:
            return cls._dec_token(val)
        else:
            reg_str ='r{}'.format(val)
            return lst_parser.Token('REG', reg_str, reg_str, None)

    @classmethod
    def _get_sci8_imm(cls, data):
        f_mask = 0x00000400
        scl_mask = 0x00000300
        data_mask = 0x000000FF

        f = (data & f_mask) >> 10
        scl = (data & scl_mask) >> 8
        ui8 = (data & data_mask)

        fill = 0x00
        if f == 1:
            fill = 0xFF

        if scl == 0:
            val = fill << 24 | fill << 16 | fill << 8 | ui8
        elif scl == 1:
            val = fill << 24 | fill << 16 | ui8 << 8 | fill
        elif scl == 2:
            val = fill << 24 | ui8 << 16 | fill << 8 | fill
        else: # scl == 3
            val = ui8 << 24 | fill << 16 | fill << 8 | fill

        return val

    @classmethod
    def unsigned_sci8(cls, data):
        val = cls._get_sci8_imm(data)

        # The SCI8 form is used most often in mask generating instructions,
        # make this operand hex
        return cls._hex_token(val)

    @classmethod
    def signed_sci8(cls, data):
        unsigned_val = cls._get_sci8_imm(data)

        sign = 0x80000000
        mask = 0x7FFFFFFF
        signed_val = (unsigned_val & mask) - (unsigned_val & sign)

        # The "signed" SCI8 values are used in add operations, make this
        # operand decimal.
        return cls._dec_token(signed_val)

    @classmethod
    def _get_i16a_imm(cls, data):
        mask_1 = 0x03E00000
        mask_2 = 0x000007FF
        up_val = (data & mask_1) >> 10  # upper >> 21 then << 11
        low_val = (data & mask_2)       # no shift
        unsigned_val = up_val | low_val
        return unsigned_val 

    @classmethod
    def signed_i16a(cls, data):
        unsigned_val = cls._get_i16a_imm(data)

        sign = 0x00100000
        mask = 0x000FFFFF
        signed_val = (unsigned_val & mask) - (unsigned_val & sign)

        # For signed values return a decimal operand
        return cls._dec_token(signed_val)

    @classmethod
    def unsigned_i16a(cls, data):
        val = cls._get_i16a_imm(data)

        # For unsigned values return a hex operand
        return cls._hex_token(val)

    @classmethod
    def xfx_spr(cls, data):
        mask_1 = 0x0000F800
        mask_2 = 0x001F0000
        up_val = (data & mask_1) >> 6  # upper >> 11 then << 5
        low_val = (data & mask_2) >> 16 # lower >> 16
        unsigned_val = up_val | low_val

        # For unsigned values return a hex operand
        return cls._hex_token(unsigned_val)

    @classmethod
    def xfx(cls, data):
        mask = 0x003E0000
        val = (data & mask) >> 22

        # For unsigned values return a hex operand
        return cls._hex_token(val)

    @classmethod
    def wrteei(cls, data):
        mask = 0x00008000
        val = (data & mask) >> 15

        # For unsigned values return a hex operand
        return cls._dec_token(val)


def parse(lst_lines):
    parser = lst_parser()
    instructions = []

    for line_nr, line in enumerate(lst_lines, 1):
        tokenized = list(parser.tokenize(line.strip()))
        if [tok for tok in tokenized if tok.type == 'ASM']:
            instr = ppc_instr(tokenized, line_nr)
            instructions.append(instr)
    return instructions


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: {} <input 1> [<input 2> ... <input n>] <output file>'.format(sys.argv[0]))
        sys.exit(-1)

    input_lines = []
    for file_in in sys.argv[1:-1]:
        with open(file_in, 'r') as f:
            input_lines.extend(f.readlines())

    # turn the lines into a set to get unique instructions for testing
    unique_instructions = sorted(list(set([repr(l) for l in parse(input_lines)])))

    if sys.argv[-1] == '-':
        for line in unique_instructions:
            print(line)
    else:
        with open(sys.argv[-1], 'w') as f:
            f.write('instructions = [\n')
            for line in unique_instructions:
                f.write('\t' + line + ',\n')
            f.write(']\n')
