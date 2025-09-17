# vivisect/envi/archs/esp32/disasm.py
"""
ESP32 (Xtensa LX6) disassembler.

Coverage:
- 24-bit base Xtensa encodings (RRR / RRI8 / RRI4 / RI6/RI7 / CALL / CALLX / BRI8 / RSR/WSR/...)
- Common 16-bit "narrow" (.N) forms seen in ESP32 code (MOV.N, MOVI.N, L32I.N, S32I.N, ADD.N, ADDI.N)
- Branches, calls, returns, jump, entry, special-reg moves, loads/stores, shifts, logic, arithmetic.

Encoding references:
  * Opcode tree and nibble fields (public summaries). See sources cited in the Chat answer.

Notes:
- Xtensa instructions are encoded little-endian by *byte*, but fields are best extracted by 4-bit nibbles:
    op0 = b0 & 0xF
    t   = (b0 >> 4) & 0xF
    s   = (b1 >> 0) & 0xF
    r   = (b1 >> 4) & 0xF
    op1 = (b2 >> 0) & 0xF
    op2 = (b2 >> 4) & 0xF
- For immediates spanning bytes, we assemble from the 24-bit word then slice.

This module focuses on producing valid envi.Opcode objects with correct size, mnemonic, and operands.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

import envi
from envi.archs.esp32 import const as C


# ---- MemoryCanvas helpers ----------------------------------------------------

def _mc_add_text(mcanv, text: str):
    # Always available
    mcanv.addText(text)

def _mc_add_name(mcanv, text: str, ntype: str = "name"):
    """
    Prefer addNameText when available (newer Vivisect). Fall back to addText.
    ntype examples used by other arch modules: 'mnemonic', 'register', 'symbol'
    """
    addname = getattr(mcanv, "addNameText", None)
    if callable(addname):
        addname(text, ntype)
    else:
        mcanv.addText(text)

def _mc_render_addr_with_hint(mcanv, va: int, symname: str | None, symoff: int, ntype: str = "symbol"):
    """
    Render an address using symbol info (supplied by caller from getSymHint).
    Always drops a VA hotspot first.
    """
    addva = getattr(mcanv, "addVa", None)
    if callable(addva):
        addva(va & 0xFFFFFFFF)

    if symname:
        _mc_add_name(mcanv, symname, ntype)
        if symoff:
            _mc_add_text(mcanv, f"+0x{symoff:X}")
    else:
        _mc_add_text(mcanv, f"0x{va & 0xFFFFFFFF:X}")




# ----------------------------
# ENVI operand wrappers
# ----------------------------
class EspRegOper(envi.RegisterOper):
    def __init__(self, rid, ctx=None):
        super().__init__(rid, ctx=ctx)

    # ---- required interface ----
    def getOperValue(self, op, emu=None):
        """
        Return the *value* of this operand (register contents).
        If no emulator is supplied, return None (unknown at disasm time).
        """
        if emu is None:
            return None
        return emu.getRegister(self.reg)

    def getOperAddr(self, op, emu=None):
        """
        For registers, there is no dereference address; return None.
        """
        return None

    def setOperValue(self, op, emu, val):
        """
        Write value into the register (requires emulator).
        """
        if emu is None:
            return
        emu.setRegister(self.reg, val & 0xFFFFFFFF)

    # New: opidx-aware render
    def render_with_idx(self, mcanv, op, opidx: int | None):
        """
        Render the register name (e.g., a1).
        """
        rctx = getattr(op, "_regctx", None)
        name = rctx.getRegisterName(self.reg) if rctx is not None else f"a{self.reg}"
        # For registers, syms hint usually isn’t used; still use addNameText for colorizing
        _mc_add_name(mcanv, name, "register")

    # Back-compat
    def render(self, mcanv, op):
        self.render_with_idx(mcanv, op, None)

    def repr(self, op):
        rctx = getattr(op, "_regctx", None)
        return rctx.getRegisterName(self.reg) if rctx is not None else f"a{self.reg}"

        rctx = getattr(op, "_regctx", None)
        name = rctx.getRegisterName(self.reg) if rctx is not None else f"a{self.reg}"
        _mc_add_name(mcanv, name, "register")

    def repr(self, op):
        return self.render(None, op)

class EspImmOper(envi.ImmedOper):
    # ---- required interface ----
    def getOperValue(self, op, emu=None):
        return self.imm

    def getOperAddr(self, op, emu=None):
        # Immediates don't have an address.
        return None

    def setOperValue(self, op, emu, val):
        # Immediates are not lvalues; ignore.
        return

    def render(self, mcanv, op):
        v = self.imm
        # Prefer hex for clarity
        if v < 0:
            return f"-0x{(-v) & 0xFFFFFFFF:X}"
        return f"0x{v:X}"

    def repr(self, op):
        return self.render(None, op)

class EspMemOper(envi.DerefOper):
    """
    Memory operand of the form [a<reg> + imm], sized by tsize.
    self.reg  -> base register id
    self.disp -> immediate displacement (unsigned in enc; we keep as int)
    """
    def __init__(self, imm, reg, disp=0, tsize=4):
        # base=reg, offset=imm ; scale is unused
        super().__init__(tsize, reg, imm, 0)

    # ---- helpers ----
    def _eff_addr(self, op, emu=None):
        basev = None
        if emu is not None:
            basev = emu.getRegister(self.reg)
        # If we don't have emu, best effort: treat base as 0
        if basev is None:
            basev = 0
        return (basev + self.disp) & 0xFFFFFFFF

    # ---- required interface ----
    def getOperAddr(self, op, emu=None):
        return self._eff_addr(op, emu)

    def getOperValue(self, op, emu=None):
        """
        Load memory at effective address with the specified tsize.
        If emulator is not provided, return None.
        """
        if emu is None:
            return None
        ea = self._eff_addr(op, emu)
        try:
            if self.tsize == 1:
                return emu.readMemoryUnsigned(ea, 1)
            elif self.tsize == 2:
                return emu.readMemoryUnsigned(ea, 2)
            elif self.tsize == 4:
                return emu.readMemoryUnsigned(ea, 4)
            else:
                # Fallback: read tsize bytes, return int
                b = emu.readMemory(ea, self.tsize)
                val = 0
                for i, by in enumerate(b):
                    val |= (by << (8 * i))  # little-endian
                return val
        except Exception:
            return None

    def setOperValue(self, op, emu, val):
        """
        Store 'val' to memory at effective address with tsize.
        """
        if emu is None:
            return
        ea = self._eff_addr(op, emu)
        val = val & ((1 << (8 * self.tsize)) - 1)
        if self.tsize == 1:
            emu.writeMemory(ea, bytes([val & 0xFF]))
        elif self.tsize == 2:
            emu.writeMemory(ea, bytes([(val & 0xFF), ((val >> 8) & 0xFF)]))
        elif self.tsize == 4:
            emu.writeMemory(ea, bytes([
                (val >> 0) & 0xFF, (val >> 8) & 0xFF,
                (val >> 16) & 0xFF, (val >> 24) & 0xFF
            ]))
        else:
            out = bytearray()
            for i in range(self.tsize):
                out.append((val >> (8 * i)) & 0xFF)
            emu.writeMemory(ea, bytes(out))

    def render(self, mcanv, op):
        rname = op._regctx.getRegisterName(self.reg) if getattr(op, "_regctx", None) else f"a{self.reg}"
        if self.disp:
            return f"[{rname}+0x{self.disp:X}]"
        return f"[{rname}]"

    def repr(self, op):
        return self.render(None, op)

class ESP32Opcode(envi.Opcode):
    """
    - self.bytes : the raw instruction bytes
    - self.iflags: bit flags for quick tests (branch/call/load/store/cond/ret)
    - self._regctx: optional register context (for pretty printing registers)
    """
    def __init__(self, va, bts, mnem, opers=None, iflags=0):
        super().__init__(va, mnem, opers or [], iflags)
        self.bytes = bytes(bts)
        self.size = len(self.bytes)
        self._regctx = None  # set by disassembler if available

    # ---- required interface ----
    def getOperValue(self, idx, emu=None):
        """
        Delegate to operand getOperValue().
        """
        if idx < 0 or idx >= len(self.opers):
            return None
        return self.opers[idx].getOperValue(self, emu)

    def getOperAddr(self, idx, emu=None):
        """
        Delegate to operand getOperAddr().
        """
        if idx < 0 or idx >= len(self.opers):
            return None
        return self.opers[idx].getOperAddr(self, emu)

    def setOperValue(self, idx, emu, val):
        """
        Delegate to operand setOperValue().
        """
        if idx < 0 or idx >= len(self.opers):
            return
        return self.opers[idx].setOperValue(self, emu, val)

    def getBranches(self):
        """
        Return a list of (target_va, branch_flags) describing outgoing edges.
        We use envi.BR_* flags:
           BR_FALL: fall-through
           BR_DST:  branch/jump destination
           BR_CALL: call destination
           BR_COND: conditional edge
           BR_RET:  return (no target)
        """
        out = []
        va = self.va
        nextva = (va + self.size) & 0xFFFFFFFF

        # helpers
        def add_fall():
            out.append((nextva, envi.BR_FALL))

        m = self.mnem.lower()

        # returns
        if m in ("ret", "retw"):
            out.append((None, envi.BR_RET))
            return out

        # calls
        if "call" in m:
            # direct CALL has target as operand 0; indirect CALLX has reg op0
            tgt = None
            if self.opers and isinstance(self.opers[0], EspImmOper):
                tgt = self.opers[0].imm & 0xFFFFFFFF
            elif self.opers and isinstance(self.opers[0], EspRegOper):
                # indirect target unknown statically
                tgt = None
            out.append((tgt, envi.BR_CALL | envi.BR_DST))
            add_fall()
            return out

        # unconditional jump
        if m in ("j", "jx"):
            tgt = None
            if self.opers and isinstance(self.opers[0], EspImmOper):
                tgt = self.opers[0].imm & 0xFFFFFFFF
            # For JX reg, unknown
            out.append((tgt, envi.BR_DST))
            return out  # no fallthrough for unconditional jump

        # conditional branches
        if m.startswith("b"):  # beqz/bnez/bgez/bltz/.../beqi/etc.
            # last operand is the target in our decoder
            tgt = None
            if self.opers:
                last = self.opers[-1]
                if isinstance(last, EspImmOper):
                    tgt = last.imm & 0xFFFFFFFF
            out.append((tgt, envi.BR_COND | envi.BR_DST))
            add_fall()
            return out

        # default: not control flow => just fallthrough
        add_fall()
        return out

    # Replace getBranches() body with ID-based checks
    def getBranches(self):
        """
        Return a list of (target_va, branch_flags) describing outgoing edges.
        We use envi.BR_* flags:
           BR_FALL: fall-through
           BR_DST:  branch/jump destination
           BR_CALL: call destination
           BR_COND: conditional edge
           BR_RET:  return (no target)
        """
        out = []
        va = self.va
        nextva = (va + self.size) & 0xFFFFFFFF

        def add_fall():
            out.append((nextva, envi.BR_FALL))

        ins = self.insn

        # returns
        if ins in (C.INS_RET, C.INS_RETW):
            out.append((None, envi.BR_RET))
            return out

        # calls (direct + indirect)
        if ins in (C.INS_CALL0, C.INS_CALL4, C.INS_CALL8, C.INS_CALL12,
                   C.INS_CALLX0, C.INS_CALLX4, C.INS_CALLX8, C.INS_CALLX12):
            tgt = None
            if self.opers and isinstance(self.opers[0], EspImmOper):
                tgt = self.opers[0].imm & 0xFFFFFFFF
            out.append((tgt, envi.BR_CALL | envi.BR_DST))
            add_fall()
            return out

        # unconditional jumps
        if ins in (C.INS_J, C.INS_JX):
            tgt = None
            if self.opers and isinstance(self.opers[0], EspImmOper):
                tgt = self.opers[0].imm & 0xFFFFFFFF
            out.append((tgt, envi.BR_DST))
            return out

        # conditional branches: all B* ids
        if ins in (C.INS_BEQZ, C.INS_BNEZ, C.INS_BLTZ, C.INS_BGEZ,
                   C.INS_BEQI, C.INS_BNEI, C.INS_BLTI, C.INS_BGEI,
                   C.INS_BLTUI, C.INS_BGEUI):
            tgt = None
            if self.opers and isinstance(self.opers[-1], EspImmOper):
                tgt = self.opers[-1].imm & 0xFFFFFFFF
            out.append((tgt, envi.BR_COND | envi.BR_DST))
            add_fall()
            return out

        add_fall()
        return out


    def render(self, mcanv):
        """
        Human-readable assembly: "mnem op1, op2, ...".
        """
        if not self.opers:
            return self.mnem
        parts = []
        for op in self.opers:
            # allow opers to access regctx via 'op'
            setattr(self, "_regctx", getattr(self, "_regctx", None))
            parts.append(op.render(mcanv, self))
        return f"{self.mnem} " + ", ".join(parts)

    def repr(self):
        """
        Debug-ish printable form with bytes.
        """
        bhex = " ".join(f"{b:02x}" for b in self.bytes)
        return f"{self.va:08x}: {self.mnem}  {self.render(None).replace(self.mnem+' ', '')}    ; {bhex}"

    def render_new(self, mcanv):
        addname = getattr(mcanv, "addNameText", None)
        (addname(self.mnem, "mnemonic") if callable(addname) else mcanv.addText(self.mnem))
        if not self.opers:
            return
        mcanv.addText(" ")

        ins = self.insn
        is_call = ins in (C.INS_CALL0, C.INS_CALL4, C.INS_CALL8, C.INS_CALL12,
                          C.INS_CALLX0, C.INS_CALLX4, C.INS_CALLX8, C.INS_CALLX12)
        is_jmp  = ins in (C.INS_J, C.INS_JX)
        is_branch = ins in (C.INS_BEQZ, C.INS_BNEZ, C.INS_BLTZ, C.INS_BGEZ,
                            C.INS_BEQI, C.INS_BNEI, C.INS_BLTI, C.INS_BGEI,
                            C.INS_BLTUI, C.INS_BGEUI)

        for i, oper in enumerate(self.opers):
            hint_name = None
            hint_off  = 0
            syms = getattr(mcanv, "syms", None)
            gethint = getattr(syms, "getSymHint", None) if syms is not None else None
            if callable(gethint):
                try:
                    hint = gethint(self.va, i)
                    if isinstance(hint, tuple) and len(hint) >= 2:
                        hint_name, hint_off = hint[0], hint[1]
                    elif isinstance(hint, str):
                        hint_name = hint
                except Exception:
                    pass

            # code target if: direct call/j, or last operand of a conditional branch
            is_target = (is_call or is_jmp or (is_branch and i == len(self.opers)-1))
            if is_target and isinstance(oper, EspImmOper) and oper.imm is not None:
                addr = oper.imm & 0xFFFFFFFF
                addva = getattr(mcanv, "addVa", None)
                if callable(addva):
                    addva(addr)
                if hint_name:
                    if callable(addname):
                        addname(hint_name, "function" if (is_call or ins == C.INS_J) else "symbol")
                    else:
                        mcanv.addText(hint_name)
                    if hint_off:
                        mcanv.addText(f"+0x{hint_off:X}")
                else:
                    mcanv.addText(f"0x{addr:X}")
            elif isinstance(oper, EspImmOper) and hint_name:
                # non-control immediate with name hint
                if callable(addname):
                    addname(hint_name, "symbol")
                else:
                    mcanv.addText(hint_name)
                if hint_off:
                    mcanv.addText(f"+0x{hint_off:X}")
            else:
                oper.render(mcanv, self)

            if i != len(self.opers) - 1:
                mcanv.addText(", ")


# ----------------------------
# Utilities
# ----------------------------
def _u16(b):
    return b[0] | (b[1] << 8)

def _sign_ext(val, bits):
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)

def _get_nibbles24(b):
    """
    Return (op0,t,s,r,op1,op2) from 3-byte sequence.
    """
    b0, b1, b2 = b[0], b[1], b[2]
    op0 = b0 & 0xF
    t   = (b0 >> 4) & 0xF
    s   = (b1 >> 0) & 0xF
    r   = (b1 >> 4) & 0xF
    op1 = (b2 >> 0) & 0xF
    op2 = (b2 >> 4) & 0xF
    return op0, t, s, r, op1, op2

def _areg(n):
    return EspRegOper(n)

def _sr_name_by_num(num):
    # A pragmatic subset; extend as needed.
    m = {
        0x00: "lbeg", 0x01: "lend", 0x02: "lcount",
        0x03: "sar",  0x04: "br",   0x05: "scompare1",
        0x10: "ps",   0x18: "litbase",
    }
    return m.get(num, f"sr{num:x}")

def _branch_target_imm8(pc, imm8):
    # BRI8 form: PC-relative. Offset is sign-extended imm8 << 1 (word aligned); Xtensa branches step PC+4 baseline.
    off = _sign_ext(imm8, 8) << 1
    return (pc + 4 + off) & 0xFFFFFFFF

def _j_off18(b):
    # J: signed 18-bit offset in {op1:op2:t:s:r? depending on layout}, but public tables state: 18-bit PC-rel shifted by 2.
    # We reconstruct from 24-bit word and take bits[21:4] as offset (18 bits). Simpler: assemble 24b and extract mid 18.
    w = b[0] | (b[1]<<8) | (b[2]<<16)
    # Layout: [23:20]=op2 [19:16]=op1 [15:0]=payload. For J, payload carries 18-bit s-offset at [21:4] (per summaries).
    # Extract bits 21..4:
    off = (w >> 4) & ((1<<18)-1)
    return _sign_ext(off, 18) << 2

def _call_off18(b):
    # CALL has 18-bit signed target<<2 as well, different low bits usage. Same extraction strategy as J.
    return _j_off18(b)


# ----------------------------
# Disassembler
# ----------------------------
class ESP32Disasm:
    def __init__(self, regctx=None):
        self.archname = "esp32"
        self.endian = envi.ENDIAN_LSB
        self.ptrsize = 4
        self._regctx = regctx  # Optional: to resolve register names in operands

    # -------- 16-bit narrow helpers (subset) --------
    def _dis_narrow(self, va, b):
        """
        Handle a practical subset of 16-bit ".N" encodings common on ESP32:
          - ADD.N     (a{r} = a{s} + a{t})  with small register sets
          - ADDI.N    (a{t} += imm4)
          - MOV.N     (register move)
          - MOVI.N    (small imm to small reg)
          - L32I.N / S32I.N (word load/store [a{s} + imm] to small reg)
        The exact layouts differ; we implement the usual forms as seen in gcc/xtensa output.
        """
        hw = _u16(b)
        lo = hw & 0xF
        hi = (hw >> 12) & 0xF

        # Very pragmatic decoding based on common opcodes:
        # MOV.N  (pattern often hi=0x2, lo selects)
        # ADDI.N (small imm)
        # L32I.N / S32I.N
        # If unknown, fall back to ILL and let 24-bit path try if bytes exist.

        # Try MOV.N: many encodings look like: 0x2r s t ?  ; we detect simple reg->reg copies
        # Heuristic: top nibble 0x2 and bits forming r/s in middle nibbles.
        if hi in (0x2, 0x3):
            r = (hw >> 8) & 0xF
            s = (hw >> 4) & 0xF
            if (r | s) <= 0xF:
                # Treat as MOV.N ar, as
                return ESP32Opcode(va, b, "mov.n", [_areg(r), _areg(s)], 0, C.INS_MOV_N)

        # ADDI.N style: detect small imm add to low regs
        if hi == 0xB:
            r = (hw >> 8) & 0x7  # often limited to a2..a7
            imm4 = (hw >> 4) & 0xF
            areg = 2 + r
            return ESP32Opcode(va, b, "addi.n", [_areg(areg), EspImmOper(imm4)], 0, C.INS_ADDI_N)

        # L32I.N / S32I.N (very common)
        if hi == 0x8:  # L32I.N (heuristic)
            r = 2 + ((hw >> 8) & 0x7)
            s = 2 + ((hw >> 4) & 0x7)
            off = ((hw >> 1) & 0x7) << 2
            return ESP32Opcode(va, b, "l32i.n", [_areg(r), EspMemOper(off, s, tsize=4)], C.IF_LOAD, C.INS_L32I_N)
        if hi == 0x9:  # S32I.N
            r = 2 + ((hw >> 8) & 0x7)
            s = 2 + ((hw >> 4) & 0x7)
            off = ((hw >> 1) & 0x7) << 2
            return ESP32Opcode(va, b, "s32i.n", [EspMemOper(off, s, tsize=4), _areg(r)], C.IF_STORE, C.INS_S32I_N)

        # ADD.N (register add)
        if hi == 0xA:
            r = (hw >> 8) & 0xF
            s = (hw >> 4) & 0xF
            t = (hw >> 0) & 0xF
            return ESP32Opcode(va, b, "add.n", [_areg(r), _areg(s), _areg(t)], 0, C.INS_ADD_N)

        # MOVI.N small immediate
        if hi == 0xC:
            r = (hw >> 8) & 0xF
            imm8 = hw & 0xFF
            return ESP32Opcode(va, b, "movi.n", [_areg(r), EspImmOper(imm8)], 0, C.INS_MOVI_N)

        # Fallback: unknown narrow -> mark as ILL (still 2 bytes)
        return ESP32Opcode(va, b, "ill", [], 0, C.INS_INVALID)

    # -------- 24-bit wide helpers --------
    def _dis_wide(self, va, b):
        op0, t, s, r, op1, op2 = _get_nibbles24(b)

        # Root by op0:
        # op0==1 : L32R
        if op0 == 0x1:
            # L32R: a[r] = *(PC-rel literal address); immediate is 18b PC-rel word address
            # The real L32R forms literal pool addressing; here we just present the target PC.
            off = _call_off18(b)  # same signed 18b<<2 behavior
            target = (va + 4 + off) & 0xFFFFFFFF
            return ESP32Opcode(va, b, "l32r", [_areg(r), EspImmOper(target)], C.IF_LOAD, C.INS_L32R)

        # op0==7 : B (multiple conditional branch families indexed by r)
        if op0 == 0x7:
            # r selects condition group; op1/op2 contain the imm8 typically.
            imm8 = (op2 << 4) | op1
            target = _branch_target_imm8(va, imm8)
            # Map r -> mnemonic per public tables:
            cond_map = {
                0x1: "beq",  0x2: "blt",  0x3: "bltu",
                0x4: "ball", 0x5: "beq", 0x0: "bnone"
            }
            # But SI-root (op0=6) handles BEQZ/BNEZ and immediates more commonly used on ESP32.
            # For op0=7 we use common pairs:
            if r == 1: mnem, insn = "beq", C.INS_BEQ
            elif r == 2: mnem, insn = "blt", C.INS_BLT
            elif r == 3: mnem, insn = "bltu", C.INS_BLTU
            elif r == 0: mnem, insn = "bnone", C.INS_BLT
            else: mnem, insn = "b", C.INS_B
            # RRRN/BRI8 variants carry regs in s/t sometimes; we present generic (a{s}, a{t})
            return ESP32Opcode(va, b, mnem, [_areg(s), _areg(t), EspImmOper(target)], C.IF_B | C.IF_COND, insn)

        # op0==6 : SI table (J / BEQZ/BNEZ/BLTZ/BGEZ and immediate forms, ENTRY)
        if op0 == 0x6:
            # "mn" lives in op1/op2 combo often; easier: detect by op1 (low nibble) + op2 (high)
            mn = (op2 << 4) | op1
            # Common:
            # 0x0: J, 0x1: BEQZ, 0x2: BEQI, 0x3: ENTRY
            # 0x5: BNEZ, 0x6: BNEI, 0x9: BLTZ, 0xA: BLTI, 0xD: BGEZ, 0xE: BGEI, 0xB: BLTUI, 0xF: BGEUI
            if mn in (0x0, 0x4, 0x8, 0xC):  # J in multiple lanes
                off = _j_off18(b)
                target = (va + 4 + off) & 0xFFFFFFFF
                return ESP32Opcode(va, b, "j", [EspImmOper(target)], C.IF_B, C.INS_J)
            if mn == 0x1:
                # BEQZ: if a{s} == 0 goto PC+off8
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "beqz", [_areg(s), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BEQZ)
            if mn == 0x5:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bnez", [_areg(s), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BNEZ)
            if mn == 0x9:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bltz", [_areg(s), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BLTZ)
            if mn == 0xD:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bgez", [_areg(s), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BGEZ)
            if mn == 0x2:
                # BEQI  (a{s} == imm8)
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                # Xtensa BEQI encodes the imm in 't' sometimes; here we show immediate compare with 't'
                return ESP32Opcode(va, b, "beqi", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BEQI)
            if mn == 0x6:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bnei", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BNEI)
            if mn == 0xA:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "blti", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BLTI)
            if mn == 0xE:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bgei", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BGEI)
            if mn == 0xB:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bltui", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BLTUI)
            if mn == 0xF:
                imm8 = (op2 << 4) | op1
                tgt = _branch_target_imm8(va, imm8)
                return ESP32Opcode(va, b, "bgeui", [_areg(s), EspImmOper(t), EspImmOper(tgt)], C.IF_B | C.IF_COND, C.INS_BGEUI)
            if mn == 0x3:
                # ENTRY a1, imm12 (stack frame alloc)
                # Common: r=??, s encodes a1, imm from b-field: we’ll use (op2:op1:t) or immediate 12 built from fields.
                imm12 = (op2 << 8) | (op1 << 4) | t
                return ESP32Opcode(va, b, "entry", [_areg(1), EspImmOper(imm12)], 0, C.INS_ENTRY)

        # op0==5 : CALLN group (CALL0/4/8/12 using 18-bit offset)
        if op0 == 0x5:
            off = _call_off18(b)
            target = (va + 4 + off) & 0xFFFFFFFF
            # op1/op2/mn select 0/4/8/12 window variant; we can reflect mnemonic by (op1&3) or present generic "call"
            lane = ((op2 << 4) | op1) & 0x3
            m, insn = {
                    0: ("call0", C.INS_CALL0), 
                    1: ("call4", C.INS_CALL4), 
                    2: ("call8",C.INS_CALL8), 
                    3: ("call12", C.INS_CALL12),
                    }.get(lane, ("call0", C.INS_CALL0))
            return ESP32Opcode(va, b, m, [EspImmOper(target)], C.IF_CALL, insn)

        # Root QRST (op0==0) subtables include: returns/jumps/callx/misc
        if op0 == 0x0:
            # Detect CALLX/JX/RET/RETW/MEMW/NOP, etc. op1/op2 + r/t encode variants.
            # Based on common encodings (see public tables):
            if op1 == 0 and op2 == 0:
                # r selects: ILL(0), RET(8), RETW(9), JX(A), CALLX0..F (C..F), MEMW(15)
                if r == 0x0 and t == 0x0:
                    return ESP32Opcode(va, b, "ill", [], 0, C.INS_INVALID)
                if r == 0x8:
                    return ESP32Opcode(va, b, "ret", [], C.IF_RET, C.INS_RET)
                if r == 0x9:
                    return ESP32Opcode(va, b, "retw", [], C.IF_RET, C.INS_RETW)
                if r == 0xA:
                    return ESP32Opcode(va, b, "jx", [_areg(s)], C.IF_B, C.INS_JX)
                if r in (0xC, 0xD, 0xE, 0xF):
                    # CALLX{0,4,8,12} a{s}
                    idx = r - 0xC
                    m, insn = [("call0", C.INS_CALL0), ("call4", C.INS_CALL4), ("call8",C.INS_CALL8), ("call12", C.INS_CALL12),][idx]
                    return ESP32Opcode(va, b, m, [_areg(s)], C.IF_CALL, insn)
                if r == 0xF and t == 0x0:
                    return ESP32Opcode(va, b, "nop", [], 0, C.INS_NOP)
                if r == 0xF and t == 0x1:
                    return ESP32Opcode(va, b, "memw", [], 0, C.INS_MEMW)
            # SYSCALL/BREAK/RSIL/WAITI etc live in nearby slots; add a couple common ones:
            if op1 == 0 and op2 == 3:
                # RSR/WSR live elsewhere; here add WAITI when t==0 and r==7? (common encoding shows WAITI in QRST\ST0)
                if r == 0x7 and t == 0x0:
                    return ESP32Opcode(va, b, "waiti", [EspImmOper(s)], 0, C.INS_WAITI)

        # op0==8/9/A/B/C/D.. : arithmetic/logical/load/store families via QRST columns
        # Use op1 selection to identify the ALU groups (AND/OR/XOR/ADD/ADDX*/SUB*), and the LSCx for loads/stores

        # ALU in QRST\RS column (op0 0..F, op1 2.. etc). We’ll cover common ones by pattern (op1 varies by column):
        # ADD/ADDX/SUB/SUBX family usually when op1==? and op2 selects variant; but the public table provides:
        #   op0 column "RST2" (op1==2) => SUB/SUBX*, etc; "RST1" (op1==1) => SLLI/SRLI/SRAI/...
        # Simpler approach for practicality: detect via (op1,op2) pairs that map to widely used mnemonics.

        # ---------- Common loads/stores ----------
        # L8UI/L16UI/L16SI/L32I: ROOT\LSAI (op0=2) or ROOT\LSAI (cached): op0=2 with r selecting L8UI/L16UI/L32I etc
        if op0 == 0x2:
            # r selects which LS op; t carries element size and op1 holds imm8; form is RRI8
            imm8 = (op2 << 4) | op1
            if r == 0x0:
                # L8UI  a[r?] form is weird in table; in practice: a{r}, [a{s}+imm8]
                return ESP32Opcode(va, b, "l8ui", [_areg(t), EspMemOper(imm8, s, tsize=1)], C.IF_LOAD, C.INS_L8UI)
            if r == 0x1:
                return ESP32Opcode(va, b, "l16ui", [_areg(t), EspMemOper(imm8<<1, s, tsize=2)], C.IF_LOAD, C.INS_L16UI)
            if r == 0x2:
                return ESP32Opcode(va, b, "l32i", [_areg(t), EspMemOper(imm8<<2, s, tsize=4)], C.IF_LOAD, C.INS_L32I)
            if r == 0x6:
                return ESP32Opcode(va, b, "l16si", [_areg(t), EspMemOper(imm8<<1, s, tsize=2)], C.IF_LOAD, C.INS_L16SI)
            # MOVI, ADDI live here as well (op0=2, r=A/C/D for movi/addi/addmi per tables). Handle below.

            # MOVI (op0=2, r=0xA)
            if r == 0xA:
                # MOVI  a{t}, imm12 (RI7/RI6 styles). Build 12-bit imm from (op2:op1:t) as common assemblers do.
                imm12 = (op2 << 8) | (op1 << 4) | t
                return ESP32Opcode(va, b, "movi", [_areg(s), EspImmOper(imm12)], 0, C.INS_MOVI)
            # ADDI (op0=2, r=0xC)
            if r == 0xC:
                imm12 = (op2 << 8) | (op1 << 4) | t
                return ESP32Opcode(va, b, "addi", [_areg(s), EspImmOper(imm12)], 0, C.INS_ADDI)
            # ADDMI is also here (r=0xD)
            if r == 0xD:
                imm12 = (op2 << 8) | (op1 << 4) | t
                return ESP32Opcode(va, b, "addmi", [_areg(s), EspImmOper(imm12)], 0, C.INS_ADDMI)

        # Stores cluster (op0 = 0xD root ST3 or 0xC root ST2). Many encodings; we’ll map most common:
        if op0 in (0xC, 0xD):
            # Use r/t selection: S8I/S16I/S32I show up in LSAI\root as well (op0=2,r=4/5/6/7 are S8I/S16I/S32I or cache)
            # But many toolchains encode stores under op0=0xD (ST3) with r field tagging size.
            imm8 = (op2 << 4) | op1
            if op0 == 0xD:
                if r == 0x4:
                    return ESP32Opcode(va, b, "s8i", [EspMemOper(imm8, s, tsize=1), _areg(t)], C.IF_STORE, C.INS_S8I)
                if r == 0x5:
                    return ESP32Opcode(va, b, "s16i", [EspMemOper(imm8<<1, s, tsize=2), _areg(t)], C.IF_STORE, C.INS_S16I)
                if r == 0x6:
                    return ESP32Opcode(va, b, "s32i", [EspMemOper(imm8<<2, s, tsize=4), _areg(t)], C.IF_STORE, C.INS_S32I)

        # ---------- Logic/ALU clusters ----------
        # AND/OR/XOR in QRST\RS (op1==?) with r= op selects mnem, operands a[r],a[s],a[t]
        # From tables: at op0 column "RST" (op1 varies), the set AND/OR/XOR live with op0 in [1..3] and op1 referencing RST2.
        if op1 == 0x2:
            # SUB/SUBX*
            if op2 in (0xC, 0xD, 0xE, 0xF):
                # These are used elsewhere; skip here.
                pass

        # Shortcut explicit patterns widely seen:
        # AND/OR/XOR often: op0==0,1,2,3 with "RST" column = actual instruction. We can detect by op1==? and op2==?
        # Use a pragmatic map on common compiler outputs:
        if op1 in (0x2, 0x3) and op0 in (0x1, 0x2, 0x3):
            # Try to identify classic trio AND/OR/XOR by op0 column (1->AND, 2->OR, 3->XOR per summary row L10)
            col_map = {0x1: ("and", C.INS_AND), 0x2: ("or", C.INS_AND), 0x3: ("xor", C.INS_AND)}
            mnem, insn = col_map.get(op0)
            if mnem:
                return ESP32Opcode(va, b, mnem, [_areg(r), _areg(s), _areg(t)], insn)

        # ADD/ADDX in QRST rows (op0 8/9/A/B columns map to ADD/ADDX2/4/8)
        if op0 in (0x8, 0x9, 0xA, 0xB) and op1 in (0x2,):  # per summary table row L11-L12
            add_map = {0x8: ("add", C.INS_ADD), 0x9: ("addx2", C.INS_ADDX2), 0xA: ("addx4", C.INS_ADDX4), 0xB: ("addx8", C.INS_ADDX8)}
            mnem, insn = add_map[op0]
            return ESP32Opcode(va, b, mnem, [_areg(r), _areg(s), _areg(t)], insn)

        # SUB/SUBX2/4/8 at op0 in (0xC,0xD,0xE,0xF) and op1==2 per table
        if op0 in (0xC, 0xD, 0xE, 0xF) and op1 in (0x2,):
            sub_map = {0xC: ("sub", C.INS_SUB), 0xD: ("subx2", C.INS_SUBX2), 0xE: ("subx4", C.INS_SUBX4), 0xF: ("subx8", C.INS_SUBX8)}
            mnem, insn = sub_map[op0]
            return ESP32Opcode(va, b, mnem, [_areg(r), _areg(s), _areg(t)], insn)

        # Shifts immediates SLLI/SRAI/SRLI from RST1 (op0==0, op1==1, op2 choose)
        if op0 == 0x0 and op1 == 0x1:
            # op2 selects SLLI/SRAI/SRLI; 't' holds shift amount; dst=r, src=s
            if op2 == 0x0 or op2 == 0x1:
                return ESP32Opcode(va, b, "slli", [_areg(r), _areg(s), EspImmOper(t)], 0, C.INS_SLLI)
            if op2 == 0x2 or op2 == 0x3:
                return ESP32Opcode(va, b, "srai", [_areg(r), _areg(s), EspImmOper(t)], 0, C.INS_SRAI)
            if op2 == 0x4:
                return ESP32Opcode(va, b, "srli", [_areg(r), _areg(s), EspImmOper(t)], 0, C.INS_SRLI)

        # Register shifts SLL/SRL/SRA live under RST1 too (rows A/B/9 in the table)
        if op0 == 0x0 and op1 == 0x1 and op2 in (0x9, 0xA, 0xB):
            if op2 == 0x9:  # SRL (s=0)
                return ESP32Opcode(va, b, "srl", [_areg(r), _areg(t)], 0, C.INS_SRL)
            if op2 == 0xA:  # SLL (t=0)
                return ESP32Opcode(va, b, "sll", [_areg(r), _areg(s)], 0, C.INS_SLL)
            if op2 == 0xB:  # SRA (s=0)
                return ESP32Opcode(va, b, "sra", [_areg(r), _areg(t)], 0, C.INS_SRA)

        # EXTUI (extract unsigned immediate) exists in QRST root (row 4 col 0/1 per tables); pragmatic mapping:
        if op0 == 0x4 and op1 in (0x0, 0x1):
            # EXTUI  r = (s >> sh) & ((1<<len)-1); 't' often holds len or sh parts; public assemblers show RI6/RI7 forms
            # Here show 'r,s,sh,len' as (imm from (op2:op1:t) split). Pragmatic: pack a 7-bit imm and split into (len, sh).
            imm7 = (op2 << 3) | (t & 0x7)
            sh = imm7 & 0x1F
            ln = (imm7 >> 5) & 0x3
            return ESP32Opcode(va, b, "extui", [_areg(r), _areg(s), EspImmOper(sh), EspImmOper(ln)], 0, C.INS_EXTUI)

        # NEG/ABS live in RST0\RT0 (op0=0,op1=0,op2=6) by s selection:
        if op0 == 0x0 and op1 == 0x0 and op2 == 0x6:
            if s == 0x0:
                return ESP32Opcode(va, b, "neg", [_areg(r), _areg(t)], 0, C.INS_NEG)
            if s == 0x1:
                return ESP32Opcode(va, b, "abs", [_areg(r), _areg(t)], 0, C.INS_ABS)

        # NSAU/NSAU (count leading zeros-like) under RST1 op2 in (0xE,0xF):
        if op0 == 0x0 and op1 == 0x1 and op2 in (0xE, 0xF):
            # NSAU/NSAU variants. Keep one mnemonic 'nsau' widely used on ESP32.
            return ESP32Opcode(va, b, "nsau", [_areg(r), _areg(t)], 0, C.INS_NSAU)

        # Special-register moves: RSR/WSR (root RST3 column op2 in {0x8..0xF} families)
        # Pragmatic recognizable forms used by ESP-IDF:
        if op0 == 0x0 and op1 == 0x3:
            # op2 selects RSR/WSR; common encodings show op2=0 => RSR, 1=>WSR; but table shows RSR/WSR in RST3.
            if op2 == 0x0:
                # RSR r, SRnum (s or t carry sr# depending on sub-form)
                srnum = (s << 4) | t
                return ESP32Opcode(va, b, "rsr", [_areg(r), EspImmOper(srnum)], 0, C.INS_RSR)
            if op2 == 0x1:
                srnum = (s << 4) | t
                return ESP32Opcode(va, b, "wsr", [EspImmOper(srnum), _areg(r)], 0, C.INS_WSR)
            if op2 == 0x2:
                # XSR r, SRnum
                srnum = (s << 4) | t
                return ESP32Opcode(va, b, "xsr", [_areg(r), EspImmOper(srnum)], 0, C.INS_XSR)

        # MOV: many encodings; when we see a pure register copy in RRR column with op selecting MOV, emit it
        # Heuristic: if op0==0 and op2/op1 pattern doesn't match others, emit 'mov r,t'
        if op0 == 0x0 and op1 == 0x9 and r != s:
            return ESP32Opcode(va, b, "mov", [_areg(r), _areg(t)], 0, C.INS_MOV)

        # Fallback: unrecognized -> ill
        return ESP32Opcode(va, b, "ill", [], 0, C.INS_INVALID)


    # -------- public API --------
    def disasm(self, va, bytez, offset=0, va_offset=None):
        """
        Decode one Xtensa/ESP32 instruction at va.
        Chooses 16-bit narrow vs 24-bit wide based on op0 patterns; many narrow opcodes have op0 in {0x8..0xD} ranges,
        but safest approach is try-narrow first if not enough bytes for 3-byte read, else sniff known .N prefixes.
        """
        b = memoryview(bytez)[offset:]
        blen = len(b)
        if blen < 2:
            raise envi.InvalidInstruction("truncated")

        # Try to detect 16-bit .N by looking at lower nibble patterns used by narrow encodings.
        # If 3 bytes available, we still need to choose; strategy:
        #   - Many .N encodings have op0 in {0x0..0xF} with specific hi-nibble classes; since distinguishing is messy,
        #     prefer decoding as 24-bit if the op0 clearly maps to known wide roots {0,1,2,5,6,7,C,D}. Otherwise try .N.
        if blen >= 3:
            # Peek wide op0:
            op0 = b[0] & 0xF
            if op0 in (0x0, 0x1, 0x2, 0x5, 0x6, 0x7, 0xC, 0xD, 0x8, 0x9, 0xA, 0xB, 0xE, 0xF):
                # Prefer wide path first; if it yields ILL, fall back to narrow try.
                opc = self._dis_wide(va, b[:3])
                if opc.mnem != "ill":
                    return opc

        # Try narrow
        opc16 = self._dis_narrow(va, b[:2])
        if opc16.mnem != "ill":
            return opc16

        # If narrow failed and we have 3 bytes, fall back to wide
        if blen >= 3:
            return self._dis_wide(va, b[:3])

        # Give up
        return ESP32Opcode(va, b[:2], "ill", [], 0, C.INS_INVALID)

