# vivisect/envi/archs/esp32/__init__.py
"""
ESP32 (Xtensa LX6) ENVI architecture module.

This module glues together:
  - Register context (regs.ESP32RegisterContext)
  - Disassembler (disasm.ESP32Disasm)
  - Arch metadata (endian, pointer size)
to match the ArchitectureModule interface used throughout Vivisect.

Usage (typical):
    from vivisect.envi.archs.esp32 import ESP32Module
    arch = ESP32Module()
    rctx = arch.getRegisterContext()
    dis  = arch.getDisassembler()

Legacy helpers:
    getRegisterContext(), getDisassembler()
"""

import envi

from . import const as C
from .regs import ESP32RegisterContext
from .disasm import ESP32Disasm, ESP32Opcode


class ESP32Module(envi.ArchitectureModule):
    """
    ArchitectureModule for ESP32/Xtensa-LX6.

    Mirrors the interface of other arch modules (e.g., MSP430), providing:
      - getRegisterContext()
      - getDisassembler()
      - getPointerSize()
      - getEndian()
    """

    def __init__(self):
        super().__init__("esp32")
        self._endian = envi.ENDIAN_LSB
        self._ptrsz = 4

        # Build the shared register context and disassembler
        self._rctx = ESP32RegisterContext()
        self._dis = ESP32Disasm(regctx=self._rctx)

        # Optional: expose opcode class and consts for tooling
        self.Opcode = ESP32Opcode
        self.const = C

    # ---- ArchitectureModule API ----
    def getPointerSize(self):
        return self._ptrsz

    def getEndian(self):
        return self._endian

    def getRegisterContext(self):
        return self._rctx

    def getDisassembler(self):
        return self._dis

    # Some modules also expose a short arch name; keep it handy
    def getArchName(self):
        return "esp32"

    def archGetRegCtx(self):
        """
        Return a *new* register context for emulation.
        This ensures each emulator has its own register file.
        """
        return ESP32RegisterContext()

    def archGetEmulator(self):
        """
        Return an ESP32 emulator instance.

        This expects an `ESP32Emulator` class in `envi/archs/esp32/emu.py`
        with a constructor like: ESP32Emulator(archmod: ESP32Module).

        Keeping this import here (instead of top-level) avoids circular imports
        during module initialization.
        """
        from .emu import ESP32Emulator
        return ESP32Emulator(self)


# ---- Legacy convenience factories (kept for parity with other arch modules) ----
def getRegisterContext():
    return ESP32Module().getRegisterContext()

def getDisassembler():
    return ESP32Module().getDisassembler()


