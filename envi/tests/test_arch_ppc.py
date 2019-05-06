
import envi.archs.ppc
import unittest

class PpcInstructionSet(unittest.TestCase):
    def test_envi_ppcvle_disasm(self):
        test_pass = 0

        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        va = 0x00000000
        vw.addMemoryMap(va, 7, 'firmware', '\xff' * 16384*1024)

        import ppc_vle_instructions
        for test_bytes, result_instr in ppc_vle_instructions.instructions:
            op = vw.arch.archParseOpcode(test_bytes.decode('hex'), 0, va)
            if repr(op) == result_instr:
                test_pass += 1
            self.assertEqual(repr(op), result_instr, 'decode {}'.format(test_bytes))

        self.assertEqual(test_pass, len(ppc_vle_instructions.instructions))

    def test_envi_ppc64_disasm(self):
        test_pass = 0

        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        va = 0x00000000
        vw.addMemoryMap(va, 7, 'firmware', '\xff' * 16384*1024)

        import ppc64_gcc_instructions
        for test_bytes, result_instr in ppc64_gcc_instructions.instructions:
            op = vw.arch.archParseOpcode(test_bytes.decode('hex'), 0, va)
            if repr(op) == result_instr:
                test_pass += 1
            self.assertEqual(repr(op), result_instr, 'decode {}'.format(test_bytes))

        self.assertEqual(test_pass, len(ppc64_gcc_instructions.instructions))
