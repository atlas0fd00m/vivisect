import struct

import envi
import envi.memory as e_mem
import envi.registers as e_reg
import envi.memcanvas as e_memcanvas
import envi.memcanvas.renderers as e_rend
import envi.archs.arm as arm
import vivisect
import platform
import unittest
from envi import IF_RET, IF_NOFALL, IF_BRANCH, IF_CALL, IF_COND
from envi.archs.arm.regs import *
from envi.archs.arm.const import *
from envi.archs.arm.disasm import *
import binascii   # temporarily included for testing purposes only - allows to print out binary values




''' 
  This dictionary will contain all commands supported by ARM to test
  Fields will contain following information:
  archVersionBitmask, ophex, va, repr, flags, emutests
'''
#items commented out are either not yet implimented or raise exceptions due to bugs.
#all errors found are commented for instruction involved
#note that cmn, cmp, teq and tst all have s's improperly attached to them for testing.
#this will be the case until the 's' issue is resolved

instrs = [
        (REV_ALL, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL, '0830bbe5', 0xbfb00000, 'ldr r3, [r11, #0x8]!', 0, ()),
        (REV_ALL, '08309be4', 0xbfb00000, 'ldr r3, [r11], #0x8', 0, ()),
        (REV_ALL, '08301be4', 0xbfb00000, 'ldr r3, [r11], #-0x8', 0, ()),
        (REV_ALL, '02209ae7', 0xbfb00000, 'ldr r2, [r10, r2]', 0, ()),
        (REV_ALL, '02209ae6', 0xbfb00000, 'ldr r2, [r10], r2', 0, ()),
        (REV_ALL, '02203ae7', 0xbfb00000, 'ldr r2, [r10, -r2]!', 0, ()),
        (REV_ALL, '0220bae7', 0xbfb00000, 'ldr r2, [r10, r2]!', 0, ()),
        (REV_ALL, '22209ae7', 0xbfb00000, 'ldr r2, [r10, r2 lsr #32]', 0, ()),
        (REV_ALL, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL, '674503e0', 0x4560, 'and r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674513e0', 0x4560, 'ands r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674523e0', 0x4560, 'eor r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674533e0', 0x4560, 'eors r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674543e0', 0x4560, 'sub r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674553e0', 0x4560, 'subs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674563e0', 0x4560, 'rsb r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674573e0', 0x4560, 'rsbs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674583e0', 0x4560, 'add r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674593e0', 0x4560, 'adds r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745a3e0', 0x4560, 'adc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745b3e0', 0x4560, 'adcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745c3e0', 0x4560, 'sbc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745e3e0', 0x4560, 'rsc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745f3e0', 0x4560, 'rscs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674513e1', 0x4560, 'tsts r3, r7, ror #10', 0, ()),
        (REV_ALL, '674533e1', 0x4560, 'teqs r3, r7, ror #10', 0, ()),
        (REV_ALL, '674553e1', 0x4560, 'cmps r3, r7, ror #10', 0, ()),
        (REV_ALL, '674573e1', 0x4560, 'cmns r3, r7, ror #10', 0, ()),
        (REV_ALL, '674583e1', 0x4560, 'orr r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674593e1', 0x4560, 'orrs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745a3e1', 0x4560, 'mov r4, r7, ror #10', 0, ()),
        (REV_ALL, '6745b3e1', 0x4560, 'movs r4, r7, ror #10', 0, ()),
        (REV_ALL, '6745c3e1', 0x4560, 'bic r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745d3e1', 0x4560, 'bics r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745e3e1', 0x4560, 'mvn r4, r7, ror #10', 0, ()),
        (REV_ALL, '6745f3e1', 0x4560, 'mvns r4, r7, ror #10', 0, ()),
        (REV_ALL, '774503e0', 0x4560, 'and r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774513e0', 0x4560, 'ands r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774523e0', 0x4560, 'eor r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774533e0', 0x4560, 'eors r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774543e0', 0x4560, 'sub r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774553e0', 0x4560, 'subs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774563e0', 0x4560, 'rsb r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774573e0', 0x4560, 'rsbs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774583e0', 0x4560, 'add r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774593e0', 0x4560, 'adds r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745a3e0', 0x4560, 'adc r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745b3e0', 0x4560, 'adcs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745c3e0', 0x4560, 'sbc r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745d3e0', 0x4560, 'sbcs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745e3e0', 0x4560, 'rsc r4, r3, r7, ror r5', 0, ()), 
        (REV_ALL, '7745f3e0', 0x4560, 'rscs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774513e1', 0x4560, 'tsts r3, r7, ror r5', 0, ()),  # s added
        (REV_ALL, '774523e1', 0x4560, 'bkpt #0x3457', 0, ()),  # v6 book shows no #, IDA and ODA show no #. v7 book does show a # so putting it in for now
        #(REV_ALL, '774533e1', 0x4560, 'teqs r3, r7, ror r5', 0, ()), # s added    # invalid instruction
        #(REV_ALL, '774543e1', 0x4560, 'hvc #0x3457', 0, ()), # invalid instruction
        (REV_ALL, '774553e1', 0x4560, 'cmps r3, r7, ror r5', 0, ()), # s added
        #(REV_ALL, '774563e1', 0x4560, 'smc #0x3457', 0, ()), # invalid instruction
        (REV_ALL, '774573e1', 0x4560, 'cmns r3, r7, ror r5', 0, ()), # s added
        (REV_ALL, '774583e1', 0x4560, 'orr r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '774593e1', 0x4560, 'orrs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745a3e1', 0x4560, 'mov r4, r7, ror r5', 0, ()),
        (REV_ALL, '7745b3e1', 0x4560, 'movs r4, r7, ror r5', 0, ()),
        (REV_ALL, '7745c3e1', 0x4560, 'bic r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745d3e1', 0x4560, 'bics r4, r3, r7, ror r5', 0, ()),
        (REV_ALL, '7745e3e1', 0x4560, 'mvn r4, r7, ror r5', 0, ()),
        (REV_ALL, '7745f3e1', 0x4560, 'mvns r4, r7, ror r5', 0, ()),
        (REV_ALL, '874503e0', 0x4560, 'and r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '874513e0', 0x4560, 'ands r4, r3, r7, lsl #11', 0, ()),   
        (REV_ALL, '874523e0', 0x4560, 'eor r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '874533e0', 0x4560, 'eors r4, r3, r7, lsl #11', 0, ()),  
        (REV_ALL, '874543e0', 0x4560, 'sub r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '874553e0', 0x4560, 'subs r4, r3, r7, lsl #11', 0, ()),   
        (REV_ALL, '874563e0', 0x4560, 'rsb r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '874573e0', 0x4560, 'rsbs r4, r3, r7, lsl #11', 0, ()),   
        (REV_ALL, '874583e0', 0x4560, 'add r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '874593e0', 0x4560, 'adds r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '8745a3e0', 0x4560, 'adc r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '8745b3e0', 0x4560, 'adcs r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '8745c3e0', 0x4560, 'sbc r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '8745d3e0', 0x4560, 'sbcs r4, r3, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745e3e0', 0x4560, 'rsc r4, r3, r7, lsl #11', 0, ()),    
        (REV_ALL, '8745f3e0', 0x4560, 'rscs r4, r3, r7, lsl #11', 0, ()),   
        #(REV_ALL, '874503e1', 0x4560, 'smlabb r3, r7, r5, r4', 0, ()),  #TypeError: cannot concatenate 'str' and 'NoneType' objects
        (REV_ALL, '874513e1', 0x4560, 'tsts r3, r7, lsl #11', 0, ()),  # s added  
        #(REV_ALL, '874523e1', 0x4560, 'smlawb r3, r7, r5, r4', 0, ()), #TypeError: cannot concatenate 'str' and 'NoneType' objects
        (REV_ALL, '874533e1', 0x4560, 'teqs r3, r7, lsl #11', 0, ()),   # s added  
        #(REV_ALL, '874543e1', 0x4560, 'smlalbb r4, r3, r7, r5', 0, ()),  #UnboundLocalError: local variable 'Rn' referenced before assignment
        (REV_ALL, '874553e1', 0x4560, 'cmps r3, r7, lsl #11', 0, ()),  # s added  
        (REV_ALL, '874563e1', 0x4560, 'smulbb r3, r7, r5', 0, ()),  
        (REV_ALL, '874573e1', 0x4560, 'cmns r3, r7, lsl #11', 0, ()),   # s added   
        (REV_ALL, '874583e1', 0x4560, 'orr r4, r3, r7, lsl #11', 0, ()),  
        (REV_ALL, '874593e1', 0x4560, 'orrs r4, r3, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745a3e1', 0x4560, 'mov r4, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745b3e1', 0x4560, 'movs r4, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745c3e1', 0x4560, 'bic r4, r3, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745d3e1', 0x4560, 'bics r4, r3, r7, lsl #11', 0, ()), 
        (REV_ALL, '8745e3e1', 0x4560, 'mvn r4, r7, lsl #11', 0, ()),  
        (REV_ALL, '8745f3e1', 0x4560, 'mvns r4, r7, lsl #11', 0, ()),  
        (REV_ALL, '974523e0', 0x4560, 'mla r3, r7, r5, r4', 0, ()),
        (REV_ALL, '974533e0', 0x4560, 'mlas r3, r7, r5, r4', 0, ()),
        #(REV_ALL, '974543e0', 0x4560, 'umaal r4, r3, r7, r5', 0, ()),  # invalid instruction
        #(REV_ALL, '974553e0', 0x4560, 'umaals r4, r3, r7, r5', 0, ()), # invalid instruction
        #(REV_ALL, '974563e0', 0x4560, 'mls r3, r7, r5, r4', 0, ()),  # invalid instruction
        #(REV_ALL, '974573e0', 0x4560, 'mlss r3, r7, r5, r4', 0, ()),   # invalid instruction
        (REV_ALL, '974583e0', 0x4560, 'umull r4, r3, r7, r5', 0, ()),
        (REV_ALL, '974593e0', 0x4560, 'umulls r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745a3e0', 0x4560, 'umlal r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745b3e0', 0x4560, 'umlals r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745c3e0', 0x4560, 'smull r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745d3e0', 0x4560, 'smulls r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745e3e0', 0x4560, 'smlal r4, r3, r7, r5', 0, ()),
        (REV_ALL, '9745f3e0', 0x4560, 'smlals r4, r3, r7, r5', 0, ()),
        (REV_ALL, '974503e1', 0x4560, 'swp r4, r7, [r3]', 0, ()),  # ida shows tst r3, r7, lsl r5
        #(REV_ALL, '974513e1', 0x4560, 'tst r3, r7, lsl r5', 0, ()), # invalid instruction
        #(REV_ALL, '974523e1', 0x4560, 'teq r3, r7, lsl r5', 0, ()), # invalid instruction
        #(REV_ALL, '974533e1', 0x4560, 'teq r3, r7, lsl r5', 0, ()), # invalid instruction
        (REV_ALL, '974543e1', 0x4560, 'swpb r4, r7, [r3]', 0, ()), # ida shows cmp r3, r7, lsl r5
        #(REV_ALL, '974553e1', 0x4560, 'cmp r3, r7, lsl r5', 0, ()), # invalid instruction
        #(REV_ALL, '974563e1', 0x4560, 'cmn r3, r7, lsl r5', 0, ()), # invalid instruction
        #(REV_ALL, '974573e1', 0x4560, 'cmn r3, r7, lsl r5', 0, ()), # invalid instruction
        (REV_ALL, '974583e1', 0x4560, 'strex r4, r7, r3', 0, ()), # ida shows orr r4, r3, r7, lsl r5
        (REV_ALL, '974593e1', 0x4560, 'ldrex r4, r7, r3', 0, ()), # ida shows orrs r4, r3, r7, lsl r5
        #(REV_ALL, '9745a3e1', 0x4560, 'mov r4, r7, lsl r5', 0, ()),
        #(REV_ALL, '9745b3e1', 0x4560, 'movs r4, r7, lsl r5', 0, ()),
        #(REV_ALL, '9745c3e1', 0x4560, 'bic r4, r3, r7, lsl r5', 0, ()),
        #(REV_ALL, '9745d3e1', 0x4560, 'bics r4, r3, r7, lsl r5', 0, ()),
        #(REV_ALL, '9745e3e1', 0x4560, 'mvn r4, r7, lsl r5', 0, ()),
        #(REV_ALL, '9745f3e1', 0x4560, 'mvns r4, r7, lsl r5', 0, ()),
        (REV_ALL, 'a74503e0', 0x4560, 'and r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74513e0', 0x4560, 'ands r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74523e0', 0x4560, 'eor r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74533e0', 0x4560, 'eors r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74543e0', 0x4560, 'sub r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74553e0', 0x4560, 'subs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74563e0', 0x4560, 'rsb r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74573e0', 0x4560, 'rsbs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74583e0', 0x4560, 'add r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74593e0', 0x4560, 'adds r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745a3e0', 0x4560, 'adc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745b3e0', 0x4560, 'adcs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745c3e0', 0x4560, 'sbc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745d3e0', 0x4560, 'sbcs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745e3e0', 0x4560, 'rsc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745f3e0', 0x4560, 'rscs r4, r3, r7, lsr #11', 0, ()),
        #(REV_ALL, 'a74503e1', 0x4560, 'smlatb r3, r7, r5, r4', 0, ()),
        (REV_ALL, 'a74513e1', 0x4560, 'tsts r3, r7, lsr #11', 0, ()),   # s added 
        #(REV_ALL, 'a74523e1', 0x4560, 'smulwb r3, r7, r5', 0, ()),   
        (REV_ALL, 'a74533e1', 0x4560, 'teqs r3, r7, lsr #11', 0, ()),    # s added 
        #(REV_ALL, 'a74543e1', 0x4560, 'smlaltb r4, r3, r7, r5', 0, ()),
        (REV_ALL, 'a74553e1', 0x4560, 'cmps r3, r7, lsr #11', 0, ()),  # s added 
        (REV_ALL, 'a74563e1', 0x4560, 'smultb r3, r7, r5', 0, ()),
        (REV_ALL, 'a74573e1', 0x4560, 'cmns r3, r7, lsr #11', 0, ()),  # s added 
        (REV_ALL, 'a74583e1', 0x4560, 'orr r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a74593e1', 0x4560, 'orrs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745a3e1', 0x4560, 'mov r4, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745b3e1', 0x4560, 'movs r4, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745c3e1', 0x4560, 'bic r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745d3e1', 0x4560, 'bics r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745e3e1', 0x4560, 'mvn r4, r7, lsr #11', 0, ()),
        (REV_ALL, 'a745f3e1', 0x4560, 'mvns r4, r7, lsr #11', 0, ()),
        (REV_ALL, 'b74503e0', 0x4560, 'strh r4, [r3], -r7 ', 0, ()),
        (REV_ALL, 'b74513e0', 0x4560, 'ldrh r4, [r3], -r7 ', 0, ()),
        #(REV_ALL, 'b74523e0', 0x4560, 'strht r4, [r3], -r7 ', 0, ()),    # not implimented yet
        #(REV_ALL, 'b74533e0', 0x4560, 'ldrht r4, [r3], -r7 ', 0, ()), # not implimented yet
        (REV_ALL, 'b74543e0', 0x4560, 'strh r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL, 'b74553e0', 0x4560, 'ldrh r4, [r3], #-0x57 ', 0, ()),
        #(REV_ALL, 'b74563e0', 0x4560, 'strht r4, [r3], #-0x57 ', 0, ()),  # not implimented yet
        #(REV_ALL, 'b74573e0', 0x4560, 'ldrht r4, [r3], #-0x57 ', 0, ()),  # not implimented yet
        (REV_ALL, 'b74583e0', 0x4560, 'strh r4, [r3], r7 ', 0, ()),
        (REV_ALL, 'b74593e0', 0x4560, 'ldrh r4, [r3], r7 ', 0, ()),
        #(REV_ALL, 'b745a3e0', 0x4560, 'strht r4, [r3], r7 ', 0, ()),   # not implimented yet
        #(REV_ALL, 'b745b3e0', 0x4560, 'ldrht r4, [r3], r7 ', 0, ()),   # not implimented yet
        (REV_ALL, 'b745c3e0', 0x4560, 'strh r4, [r3], #0x57 ', 0, ()),
        (REV_ALL, 'b745d3e0', 0x4560, 'ldrh r4, [r3], #0x57 ', 0, ()),
        #(REV_ALL, 'b745e3e0', 0x4560, 'strht r4, [r3], #0x57 ', 0, ()), # not implimented yet
        #(REV_ALL, 'b745f3e0', 0x4560, 'ldrht r4, [r3], #0x57 ', 0, ()),  # not implimented yet
        (REV_ALL, 'b74503e1', 0x4560, 'strh r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'b74513e1', 0x4560, 'ldrh r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'b74523e1', 0x4560, 'strh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'b74533e1', 0x4560, 'ldrh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'b74543e1', 0x4560, 'strh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'b74553e1', 0x4560, 'ldrh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'b74563e1', 0x4560, 'strh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'b74573e1', 0x4560, 'ldrh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'b74583e1', 0x4560, 'strh r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'b74593e1', 0x4560, 'ldrh r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'b745a3e1', 0x4560, 'strh r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'b745b3e1', 0x4560, 'ldrh r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'b745c3e1', 0x4560, 'strh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'b745d3e1', 0x4560, 'ldrh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'b745e3e1', 0x4560, 'strh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, 'b745f3e1', 0x4560, 'ldrh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, 'c74503e0', 0x4560, 'and r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74513e0', 0x4560, 'ands r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74523e0', 0x4560, 'eor r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74533e0', 0x4560, 'eors r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74543e0', 0x4560, 'sub r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74553e0', 0x4560, 'subs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74563e0', 0x4560, 'rsb r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74573e0', 0x4560, 'rsbs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74583e0', 0x4560, 'add r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74593e0', 0x4560, 'adds r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745a3e0', 0x4560, 'adc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745b3e0', 0x4560, 'adcs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745c3e0', 0x4560, 'sbc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745d3e0', 0x4560, 'sbcs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745e3e0', 0x4560, 'rsc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745f3e0', 0x4560, 'rscs r4, r3, r7, asr #11', 0, ()),
        #(REV_ALL, 'c74503e1', 0x4560, 'smlabt r3, r7, r5, r4', 0, ()),   
        (REV_ALL, 'c74513e1', 0x4560, 'tsts r3, r7, asr #11', 0, ()),    #added s
        #(REV_ALL, 'c74523e1', 0x4560, 'smlawt r3, r7, r5, r4', 0, ()),
        (REV_ALL, 'c74533e1', 0x4560, 'teqs r3, r7, asr #11', 0, ()),     #added s
        #(REV_ALL, 'c74543e1', 0x4560, 'smlalbt r4, r3, r7, r5', 0, ()),
        (REV_ALL, 'c74553e1', 0x4560, 'cmps r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74563e1', 0x4560, 'smulbt r3, r7, r5', 0, ()),
        (REV_ALL, 'c74573e1', 0x4560, 'cmns r3, r7, asr #11', 0, ()),      #added s
        (REV_ALL, 'c74583e1', 0x4560, 'orr r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c74593e1', 0x4560, 'orrs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745a3e1', 0x4560, 'mov r4, r7, asr #11', 0, ()),
        (REV_ALL, 'c745b3e1', 0x4560, 'movs r4, r7, asr #11', 0, ()),
        (REV_ALL, 'c745c3e1', 0x4560, 'bic r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745d3e1', 0x4560, 'bics r4, r3, r7, asr #11', 0, ()),
        (REV_ALL, 'c745e3e1', 0x4560, 'mvn r4, r7, asr #11', 0, ()),
        (REV_ALL, 'c745f3e1', 0x4560, 'mvns r4, r7, asr #11', 0, ()),
        (REV_ALL, 'd74503e0', 0x4560, 'ldrd r4, [r3], -r7 ', 0, ()),
        (REV_ALL, 'd74513e0', 0x4560, 'ldrsb r4, [r3], -r7 ', 0, ()),
        (REV_ALL, 'd74523e0', 0x4560, 'ldrd r4, [r3], -r7 ', 0, ()),    #ida says ldrtd but ldrt bits 26 & 25 need to be 1's and are 0's which is ldrd
        #(REV_ALL, 'd74533e0', 0x4560, 'ldrsbt r4, [r3], -r7 ', 0, ()),  # not implimented yet
        (REV_ALL, 'd74543e0', 0x4560, 'ldrd r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL, 'd74553e0', 0x4560, 'ldrsb r4, [r3], #-0x57 ', 0, ()),
        #(REV_ALL, 'd74563e0', 0x4560, 'ldrtd r4, [r3], #-0x57 ', 0, ()), # not implimented yet
        #(REV_ALL, 'd74573e0', 0x4560, 'ldrsbt r4, [r3], #-0x57 ', 0, ()), # not implimented yet
        (REV_ALL, 'd74583e0', 0x4560, 'ldrd r4, [r3], r7 ', 0, ()),
        (REV_ALL, 'd74593e0', 0x4560, 'ldrsb r4, [r3], r7 ', 0, ()),
        #(REV_ALL, 'd745a3e0', 0x4560, 'ldrtd r4, [r3], r7 ', 0, ()), # not implimented yet
        #(REV_ALL, 'd745b3e0', 0x4560, 'ldrsbt r4, [r3], r7 ', 0, ()), # not implimented yet
        (REV_ALL, 'd745c3e0', 0x4560, 'ldrd r4, [r3], #0x57 ', 0, ()),
        (REV_ALL, 'd745d3e0', 0x4560, 'ldrsb r4, [r3], #0x57 ', 0, ()),
        #(REV_ALL, 'd745e3e0', 0x4560, 'ldrtd r4, [r3], #0x57 ', 0, ()), # not implimented yet
        #(REV_ALL, 'd745f3e0', 0x4560, 'ldrsbt r4, [r3], #0x57 ', 0, ()), # not implimented yet
        (REV_ALL, 'd74503e1', 0x4560, 'ldrd r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'd74513e1', 0x4560, 'ldrsb r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'd74523e1', 0x4560, 'ldrd r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'd74533e1', 0x4560, 'ldrsb r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'd74543e1', 0x4560, 'ldrd r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'd74553e1', 0x4560, 'ldrsb r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'd74563e1', 0x4560, 'ldrd r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'd74573e1', 0x4560, 'ldrsb r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'd74583e1', 0x4560, 'ldrd r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'd74593e1', 0x4560, 'ldrsb r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'd745a3e1', 0x4560, 'ldrd r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'd745b3e1', 0x4560, 'ldrsb r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'd745c3e1', 0x4560, 'ldrd r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'd745d3e1', 0x4560, 'ldrsb r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'd745e3e1', 0x4560, 'ldrd r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, 'd745f3e1', 0x4560, 'ldrsb r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, 'e74503e0', 0x4560, 'and r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74513e0', 0x4560, 'ands r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74523e0', 0x4560, 'eor r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74533e0', 0x4560, 'eors r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74543e0', 0x4560, 'sub r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74553e0', 0x4560, 'subs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74563e0', 0x4560, 'rsb r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74573e0', 0x4560, 'rsbs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74583e0', 0x4560, 'add r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74593e0', 0x4560, 'adds r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745a3e0', 0x4560, 'adc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745b3e0', 0x4560, 'adcs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745c3e0', 0x4560, 'sbc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745e3e0', 0x4560, 'rsc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745f3e0', 0x4560, 'rscs r4, r3, r7, ror #11', 0, ()),
        #(REV_ALL, 'e74503e1', 0x4560, 'smlatt r3, r7, r5, r4', 0, ()),
        (REV_ALL, 'e74513e1', 0x4560, 'tsts r3, r7, ror #11', 0, ()),   #added s
        #(REV_ALL, 'e74523e1', 0x4560, 'smulwt r3, r7, r5', 0, ()), 
        (REV_ALL, 'e74533e1', 0x4560, 'teqs r3, r7, ror #11', 0, ()),    #added s
        #(REV_ALL, 'e74543e1', 0x4560, 'smlaltt r4, r3, r7, r5', 0, ()),
        (REV_ALL, 'e74553e1', 0x4560, 'cmps r3, r7, ror #11', 0, ()),   #added s
        (REV_ALL, 'e74563e1', 0x4560, 'smultt r3, r7, r5', 0, ()),
        (REV_ALL, 'e74573e1', 0x4560, 'cmns r3, r7, ror #11', 0, ()),   #added s
        (REV_ALL, 'e74583e1', 0x4560, 'orr r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e74593e1', 0x4560, 'orrs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745a3e1', 0x4560, 'mov r4, r7, ror #11', 0, ()),
        (REV_ALL, 'e745b3e1', 0x4560, 'movs r4, r7, ror #11', 0, ()),
        (REV_ALL, 'e745c3e1', 0x4560, 'bic r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745d3e1', 0x4560, 'bics r4, r3, r7, ror #11', 0, ()),
        (REV_ALL, 'e745e3e1', 0x4560, 'mvn r4, r7, ror #11', 0, ()),
        (REV_ALL, 'e745f3e1', 0x4560, 'mvns r4, r7, ror #11', 0, ()),
        (REV_ALL, 'f74503e0', 0x4560, 'strd r4, [r3], -r7 ', 0, ()),
        (REV_ALL, 'f74513e0', 0x4560, 'ldrsh r4, [r3], -r7 ', 0, ()),
        #(REV_ALL, 'f74523e0', 0x4560, 'strtd r4, [r3], -r7 ', 0, ()),  # not implimented yet
        #(REV_ALL, 'f74533e0', 0x4560, 'ldrsht r4, [r3], -r7 ', 0, ()), # not implimented yet
        (REV_ALL, 'f74543e0', 0x4560, 'strd r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL, 'f74553e0', 0x4560, 'ldrsh r4, [r3], #-0x57 ', 0, ()),
        #(REV_ALL, 'f74563e0', 0x4560, 'strtd r4, [r3], #-0x57 ', 0, ()), # not implimented yet
        #(REV_ALL, 'f74573e0', 0x4560, 'ldrsht r4, [r3], #-0x57 ', 0, ()), # not implimented yet
        (REV_ALL, 'f74583e0', 0x4560, 'strd r4, [r3], r7 ', 0, ()),
        (REV_ALL, 'f74593e0', 0x4560, 'ldrsh r4, [r3], r7 ', 0, ()),
        #(REV_ALL, 'f745a3e0', 0x4560, 'strtd r4, [r3], r7 ', 0, ()), # not implimented yet
        #(REV_ALL, 'f745b3e0', 0x4560, 'ldrsht r4, [r3], r7 ', 0, ()), # not implimented yet
        (REV_ALL, 'f745c3e0', 0x4560, 'strd r4, [r3], #0x57 ', 0, ()),
        (REV_ALL, 'f745d3e0', 0x4560, 'ldrsh r4, [r3], #0x57 ', 0, ()),
        #(REV_ALL, 'f745e3e0', 0x4560, 'strtd r4, [r3], #0x57 ', 0, ()), # not implimented yet
        #(REV_ALL, 'f745f3e0', 0x4560, 'ldrsht r4, [r3], #0x57 ', 0, ()), # not implimented yet
        (REV_ALL, 'f74503e1', 0x4560, 'strd r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'f74513e1', 0x4560, 'ldrsh r4, [r3, -r7] ', 0, ()),
        (REV_ALL, 'f74523e1', 0x4560, 'strd r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'f74533e1', 0x4560, 'ldrsh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL, 'f74543e1', 0x4560, 'strd r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'f74553e1', 0x4560, 'ldrsh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL, 'f74563e1', 0x4560, 'strd r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'f74573e1', 0x4560, 'ldrsh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL, 'f74583e1', 0x4560, 'strd r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'f74593e1', 0x4560, 'ldrsh r4, [r3, r7] ', 0, ()),
        (REV_ALL, 'f745a3e1', 0x4560, 'strd r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'f745b3e1', 0x4560, 'ldrsh r4, [r3, r7]! ', 0, ()),
        (REV_ALL, 'f745c3e1', 0x4560, 'strd r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'f745d3e1', 0x4560, 'ldrsh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL, 'f745e3e1', 0x4560, 'strd r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, 'f745f3e1', 0x4560, 'ldrsh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL, '074603e0', 0x4560, 'and r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074613e0', 0x4560, 'ands r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074623e0', 0x4560, 'eor r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074633e0', 0x4560, 'eors r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074643e0', 0x4560, 'sub r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074653e0', 0x4560, 'subs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074663e0', 0x4560, 'rsb r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074673e0', 0x4560, 'rsbs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074683e0', 0x4560, 'add r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074693e0', 0x4560, 'adds r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746a3e0', 0x4560, 'adc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746b3e0', 0x4560, 'adcs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746c3e0', 0x4560, 'sbc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746d3e0', 0x4560, 'sbcs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746e3e0', 0x4560, 'rsc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746f3e0', 0x4560, 'rscs r4, r3, r7, lsl #12', 0, ()),
        #(REV_ALL, '074603e1', 0x4560, 'tsts r3, r7, lsl #12', 0, ()), #added s , doesn't decode even close and doesn't match ref
        (REV_ALL, '074613e1', 0x4560, 'tsts r3, r7, lsl #12', 0, ()), #added s
        #(REV_ALL, '074623e1', 0x4560, 'teqs r3, r7, lsl #12', 0, ()), #added s, doesn't decode even close and doesn't match ref
        (REV_ALL, '074633e1', 0x4560, 'teqs r3, r7, lsl #12', 0, ()), #added s
        #(REV_ALL, '074643e1', 0x4560, 'cmps r3, r7, lsl #12', 0, ()), #added s not implimented
        (REV_ALL, '074653e1', 0x4560, 'cmps r3, r7, lsl #12', 0, ()), #added s
        #(REV_ALL, '074663e1', 0x4560, 'cmns r3, r7, lsl #12', 0, ()), #added s not implimented
        (REV_ALL, '074673e1', 0x4560, 'cmns r3, r7, lsl #12', 0, ()), #added s
        (REV_ALL, '074683e1', 0x4560, 'orr r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '074693e1', 0x4560, 'orrs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746a3e1', 0x4560, 'mov r4, r7, lsl #12', 0, ()),
        (REV_ALL, '0746b3e1', 0x4560, 'movs r4, r7, lsl #12', 0, ()),
        (REV_ALL, '0746c3e1', 0x4560, 'bic r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746d3e1', 0x4560, 'bics r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL, '0746e3e1', 0x4560, 'mvn r4, r7, lsl #12', 0, ()),
        (REV_ALL, '0746f3e1', 0x4560, 'mvns r4, r7, lsl #12', 0, ()),
        (REV_ALL, '174603e0', 0x4560, 'and r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174613e0', 0x4560, 'ands r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174623e0', 0x4560, 'eor r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174633e0', 0x4560, 'eors r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174643e0', 0x4560, 'sub r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174653e0', 0x4560, 'subs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174663e0', 0x4560, 'rsb r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174673e0', 0x4560, 'rsbs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174683e0', 0x4560, 'add r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174693e0', 0x4560, 'adds r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746a3e0', 0x4560, 'adc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746b3e0', 0x4560, 'adcs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746c3e0', 0x4560, 'sbc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746d3e0', 0x4560, 'sbcs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746e3e0', 0x4560, 'rsc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746f3e0', 0x4560, 'rscs r4, r3, r7, lsl r6', 0, ()),
        #(REV_ALL, '174603e1', 0x4560, 'tst r3, r7, lsl r6', 0, ()),     # not implimented
        (REV_ALL, '174613e1', 0x4560, 'tsts r3, r7, lsl r6', 0, ()),    #added s
        (REV_ALL, '174623e1', 0x4560, 'bx r7', 0, ()),
        #(REV_ALL, '174643e1', 0x4560, 'cmp r3, r7, lsl r6', 0, ()), # not implimented
        (REV_ALL, '174653e1', 0x4560, 'cmps r3, r7, lsl r6', 0, ()),  #added s
        (REV_ALL, '174663e1', 0x4560, 'clz r4, r7', 0, ()),
        (REV_ALL, '174673e1', 0x4560, 'cmns r3, r7, lsl r6', 0, ()),  #added s
        (REV_ALL, '174683e1', 0x4560, 'orr r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '174693e1', 0x4560, 'orrs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746a3e1', 0x4560, 'mov r4, r7, lsl r6', 0, ()),
        (REV_ALL, '1746b3e1', 0x4560, 'movs r4, r7, lsl r6', 0, ()),
        (REV_ALL, '1746c3e1', 0x4560, 'bic r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746d3e1', 0x4560, 'bics r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL, '1746e3e1', 0x4560, 'mvn r4, r7, lsl r6', 0, ()),
        (REV_ALL, '1746f3e1', 0x4560, 'mvns r4, r7, lsl r6', 0, ()),
        (REV_ALL, '274603e0', 0x4560, 'and r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274613e0', 0x4560, 'ands r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274623e0', 0x4560, 'eor r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274633e0', 0x4560, 'eors r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274643e0', 0x4560, 'sub r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274653e0', 0x4560, 'subs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274663e0', 0x4560, 'rsb r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274673e0', 0x4560, 'rsbs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274683e0', 0x4560, 'add r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274693e0', 0x4560, 'adds r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746a3e0', 0x4560, 'adc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746b3e0', 0x4560, 'adcs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746c3e0', 0x4560, 'sbc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746d3e0', 0x4560, 'sbcs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746e3e0', 0x4560, 'rsc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746f3e0', 0x4560, 'rscs r4, r3, r7, lsr #12', 0, ()),
        #(REV_ALL, '274603e1', 0x4560, 'tst r3, r7, lsr #12', 0, ()),  #should be: tst r3, r7, lsr #12  - is: mrs r4, CPSR
        (REV_ALL, '274613e1', 0x4560, 'tsts r3, r7, lsr #12', 0, ()),
        #(REV_ALL, '274623e1', 0x4560, 'bxj r7', 0, ()),  # should be: bxj r7  - is: mrs r4, CPSR
        #(REV_ALL, '274643e1', 0x4560, 'cmp r3, r7, lsr #12', 0, ()),  
        (REV_ALL, '274653e1', 0x4560, 'cmps r3, r7, lsr #12', 0, ()),  #added s
        #(REV_ALL, '274663e1', 0x4560, 'cmns r3, r7, lsr #12', 0, ()),  #added s   # not implimented
        (REV_ALL, '274673e1', 0x4560, 'cmns r3, r7, lsr #12', 0, ()),  #added s
        (REV_ALL, '274683e1', 0x4560, 'orr r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '274693e1', 0x4560, 'orrs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746a3e1', 0x4560, 'mov r4, r7, lsr #12', 0, ()),
        (REV_ALL, '2746b3e1', 0x4560, 'movs r4, r7, lsr #12', 0, ()),
        (REV_ALL, '2746c3e1', 0x4560, 'bic r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746d3e1', 0x4560, 'bics r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL, '2746e3e1', 0x4560, 'mvn r4, r7, lsr #12', 0, ()),
        (REV_ALL, '2746f3e1', 0x4560, 'mvns r4, r7, lsr #12', 0, ()),
        (REV_ALL, '374603e0', 0x4560, 'and r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374613e0', 0x4560, 'ands r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374623e0', 0x4560, 'eor r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374633e0', 0x4560, 'eors r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374643e0', 0x4560, 'sub r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374653e0', 0x4560, 'subs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374663e0', 0x4560, 'rsb r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374673e0', 0x4560, 'rsbs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374683e0', 0x4560, 'add r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374693e0', 0x4560, 'adds r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746a3e0', 0x4560, 'adc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746b3e0', 0x4560, 'adcs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746c3e0', 0x4560, 'sbc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746d3e0', 0x4560, 'sbcs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746e3e0', 0x4560, 'rsc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746f3e0', 0x4560, 'rscs r4, r3, r7, lsr r6', 0, ()),
        #(REV_ALL, '374603e1', 0x4560, 'tstS r3, r7, lsr r6', 0, ()),   #added s   # not implimented
        (REV_ALL, '374613e1', 0x4560, 'tsts r3, r7, lsr r6', 0, ()),  #added s
        (REV_ALL, '374623e1', 0x4560, 'blx r7', 0, ()),
        (REV_ALL, '374633e1', 0x4560, 'teqs r3, r7, lsr r6', 0, ()), #added s
        #(REV_ALL, '374643e1', 0x4560, 'cmps r3, r7, lsr r6', 0, ()),    #added s   # not implimented
        (REV_ALL, '374653e1', 0x4560, 'cmps r3, r7, lsr r6', 0, ()), #added s
        #(REV_ALL, '374663e1', 0x4560, 'cmns r3, r7, lsr r6', 0, ()),   #added s   # not implimented
        (REV_ALL, '374673e1', 0x4560, 'cmns r3, r7, lsr r6', 0, ()),  #added s 
        (REV_ALL, '374683e1', 0x4560, 'orr r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '374693e1', 0x4560, 'orrs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746a3e1', 0x4560, 'mov r4, r7, lsr r6', 0, ()),
        (REV_ALL, '3746b3e1', 0x4560, 'movs r4, r7, lsr r6', 0, ()),
        (REV_ALL, '3746c3e1', 0x4560, 'bic r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746d3e1', 0x4560, 'bics r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL, '3746e3e1', 0x4560, 'mvn r4, r7, lsr r6', 0, ()),
        (REV_ALL, '3746f3e1', 0x4560, 'mvns r4, r7, lsr r6', 0, ()),
        (REV_ALL, '474603e0', 0x4560, 'and r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474613e0', 0x4560, 'ands r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474623e0', 0x4560, 'eor r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474633e0', 0x4560, 'eors r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474643e0', 0x4560, 'sub r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474653e0', 0x4560, 'subs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474663e0', 0x4560, 'rsb r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474673e0', 0x4560, 'rsbs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474683e0', 0x4560, 'add r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474693e0', 0x4560, 'adds r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746a3e0', 0x4560, 'adc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746b3e0', 0x4560, 'adcs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746c3e0', 0x4560, 'sbc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746d3e0', 0x4560, 'sbcs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746e3e0', 0x4560, 'rsc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746f3e0', 0x4560, 'rscs r4, r3, r7, asr #12', 0, ()),
        #(REV_ALL, '474603e1', 0x4560, 'tsts r3, r7, asr #12', 0, ()),  #added s   # should be: tsts r3, r7, asr #12  - is: mrs r4, CPSR
        (REV_ALL, '474613e1', 0x4560, 'tsts r3, r7, asr #12', 0, ()), #added s 
        #(REV_ALL, '474623e1', 0x4560, 'teqs r3, r7, asr #12', 0, ()), #added s   # should be: teqs r3, r7, asr #12  - is: mrs r4, CPSR
        (REV_ALL, '474633e1', 0x4560, 'teqs r3, r7, asr #12', 0, ()), #added s 
        #(REV_ALL, '474643e1', 0x4560, 'cmps r3, r7, asr #12', 0, ()), #added s   # not implimented
        (REV_ALL, '474653e1', 0x4560, 'cmps r3, r7, asr #12', 0, ()), #added s 
        #(REV_ALL, '474663e1', 0x4560, 'cmns r3, r7, asr #12', 0, ()), #added s   # not implimented
        (REV_ALL, '474673e1', 0x4560, 'cmns r3, r7, asr #12', 0, ()), #added s 
        (REV_ALL, '474683e1', 0x4560, 'orr r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '474693e1', 0x4560, 'orrs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746a3e1', 0x4560, 'mov r4, r7, asr #12', 0, ()),
        (REV_ALL, '4746b3e1', 0x4560, 'movs r4, r7, asr #12', 0, ()),
        (REV_ALL, '4746c3e1', 0x4560, 'bic r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746d3e1', 0x4560, 'bics r4, r3, r7, asr #12', 0, ()),
        (REV_ALL, '4746e3e1', 0x4560, 'mvn r4, r7, asr #12', 0, ()),
        (REV_ALL, '4746f3e1', 0x4560, 'mvns r4, r7, asr #12', 0, ()),
        (REV_ALL, '574603e0', 0x4560, 'and r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574613e0', 0x4560, 'ands r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574623e0', 0x4560, 'eor r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574633e0', 0x4560, 'eors r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574643e0', 0x4560, 'sub r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574653e0', 0x4560, 'subs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574663e0', 0x4560, 'rsb r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574673e0', 0x4560, 'rsbs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574683e0', 0x4560, 'add r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574693e0', 0x4560, 'adds r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746a3e0', 0x4560, 'adc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746b3e0', 0x4560, 'adcs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746c3e0', 0x4560, 'sbc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746d3e0', 0x4560, 'sbcs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746e3e0', 0x4560, 'rsc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746f3e0', 0x4560, 'rscs r4, r3, r7, asr r6', 0, ()),
        #(REV_ALL, '574603e1', 0x4560, 'tst r3, r7, asr r6', 0, ()), # should be: tst r3, r7, asr r6  - is: qadd r4, r7, r3
        (REV_ALL, '574613e1', 0x4560, 'tsts r3, r7, asr r6', 0, ()),  #added s
        #(REV_ALL, '574623e1', 0x4560, 'teq r3, r7, asr r6', 0, ()),  #should be: teq r3, r7, asr r6  - is: qsub r4, r7, r3
        (REV_ALL, '574633e1', 0x4560, 'teqs r3, r7, asr r6', 0, ()),  #added s
        #(REV_ALL, '574643e1', 0x4560, 'cmp r3, r7, asr r6', 0, ()),  # should be: cmp r3, r7, asr r6  - is: qdadd r4, r7, r3
        (REV_ALL, '574653e1', 0x4560, 'cmps r3, r7, asr r6', 0, ()),  #added s
        #(REV_ALL, '574663e1', 0x4560, 'cmn r3, r7, asr r6', 0, ()), #should be: cmp r3, r7, asr r6  - is: qdadd r4, r7, r3
        (REV_ALL, '574673e1', 0x4560, 'cmns r3, r7, asr r6', 0, ()),  #added s
        (REV_ALL, '574683e1', 0x4560, 'orr r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '574693e1', 0x4560, 'orrs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746a3e1', 0x4560, 'mov r4, r7, asr r6', 0, ()),
        (REV_ALL, '5746b3e1', 0x4560, 'movs r4, r7, asr r6', 0, ()),
        (REV_ALL, '5746c3e1', 0x4560, 'bic r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746d3e1', 0x4560, 'bics r4, r3, r7, asr r6', 0, ()),
        (REV_ALL, '5746e3e1', 0x4560, 'mvn r4, r7, asr r6', 0, ()),
        (REV_ALL, '5746f3e1', 0x4560, 'mvns r4, r7, asr r6', 0, ()),
        #(REV_ALL, '674503e6', 0x4560, 'str r4, [r3], -r7, ror #10', 0, ()),  #should be: str r4, [r3], -r7, ror #10  - is: str r4, [r3], -r7 ror #10
        #(REV_ALL, '674523e6', 0x4560, 'strt r4, [r3], -r7, ror #10', 0, ()),  #should be: strt r4, [r3], -r7, ror #10  - is: strt r4, [r3], -r7 ror #10
        #(REV_ALL, '674543e6', 0x4560, 'strb r4, [r3], -r7, ror #10', 0, ()), #should be: strb r4, [r3], -r7, ror #10  - is: strb r4, [r3], -r7 ror #10
        #(REV_ALL, '674563e6', 0x4560, 'strbt r4, [r3], -r7, ror #10', 0, ())  # missing last ',' same as above
        #(REV_ALL, '674583e6', 0x4560, 'str r4, [r3], r7, ror #10', 0, ()), # missing last ',' same as above
        #(REV_ALL, '6745a3e6', 0x4560, 'strt r4, [r3], r7, ror #10', 0, ()), # missing last ',' same as above
        #(REV_ALL, '6745c3e6', 0x4560, 'strb r4, [r3], r7, ror #10', 0, ()), # missing last ',' same as above
        #(REV_ALL, '6745e3e6', 0x4560, 'strbt r4, [r3], r7, ror #10', 0, ()), # missing last ',' same as above
        #(REV_ALL, '674503e7', 0x4560, 'str r4, [r3, -r7, ror #10]', 0, ()), # missing last ',' same as above
        #(REV_ALL, '674523e7', 0x4560, 'str r4, [r3, -r7, ror #10]!', 0, ()), # missing last ',' same as above
        #(REV_ALL, '674543e7', 0x4560, 'strb r4, [r3, -r7, ror #10]', 0, ()), # missing last ',' same as above
        #(REV_ALL, '674563e7', 0x4560, 'strb r4, [r3, -r7, ror #10]!', 0, ()),  # missing last ',' same as above
        #(REV_ALL, '674583e7', 0x4560, 'str r4, [r3, r7, ror #10]', 0, ()), # missing last ',' same as above
        #(REV_ALL, '6745a3e7', 0x4560, 'str r4, [r3, r7, ror #10]!', 0, ()), # missing last ',' same as above
        #(REV_ALL, '6745c3e7', 0x4560, 'strb r4, [r3, r7, ror #10]', 0, ()), # missing last ',' same as above
        (REV_ALL, '6745e3e7', 0x4560, 'strb r4, [r3, r7, ror #10]!', 0, ()), # missing last ',' same as above
        (REV_ALL, '674503e0', 0x4560, 'and r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674513e0', 0x4560, 'ands r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674523e0', 0x4560, 'eor r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674533e0', 0x4560, 'eors r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674543e0', 0x4560, 'sub r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674553e0', 0x4560, 'subs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674563e0', 0x4560, 'rsb r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674573e0', 0x4560, 'rsbs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674583e0', 0x4560, 'add r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '674593e0', 0x4560, 'adds r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745a3e0', 0x4560, 'adc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745b3e0', 0x4560, 'adcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745c3e0', 0x4560, 'sbc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745e3e0', 0x4560, 'rsc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL, '6745f3e0', 0x4560, 'rscs r4, r3, r7, ror #10', 0, ()) 
        ] 

# FIXME: create list of this from IDA flow below - THIS CURRENT DATA IS FOR H8!  NOT ARM/THUMB
        
'''
        leaving here for reference.
        will remove this section once the emulation test code is started
        Currently emulation is disabled until disassembly is all done
        ( '1a83', 0x4560, 'sub.l er0, er3', IF_L, (
            {'setup':(('er0',0xaa),('CCR_C',0),('er3',0x1a)), 
                'tests':(('er3',0x90),('CCR_H',0),('CCR_N',0),('CCR_Z',0),('CCR_V',0),('CCR_C',0)) },
            {'setup':(('er0',0xab),('CCR_C',0),('er3',0xb0)), 
                'tests':(('er3',0xfffffffb),('CCR_H',1),('CCR_N',1),('CCR_Z',0),('CCR_V',0),('CCR_C',1)) },
            ) ),
'''

# temp scratch: generated these while testing
['0de803c0','8de903c0','ade903c0','2de803c0','1de803c0','3de803c0','9de903c0','bde903c0',]
['srsdb.w sp, svc',
         'srsia.w sp, svc',
          'srsia.w sp!, svc',
           'srsdb.w sp!, svc',
            'rfedb.w sp',
             'rfedb.w sp!',
              'rfeia.w sp',
               'rfeia.w sp!']

import struct
def getThumbStr(val, val2):
    return struct.pack('<HH', val, val2)

def getThumbOps(vw, numtups):
    return [vw.arch.archParseOpcode(getThumbStr(val,val2), 1, 0x8000001) for val,val2 in numtups]

# more scratch
#ops = getThumbOps(vw, [(0x0df7,0x03b0),(0x00f7,0xaa8a),(0xf7fe,0xbdbc),(0xf385,0x8424)]) ;op=ops[0];ops
#ops = getThumbOps(vw, [(0xf386,0x8424),(0xf385,0x8400)]) ;op=ops[0];ops
#Out[1]: [msr.w APSR_s, r5]

# testing PSR stuff - not actually working unittesting...
import envi.memcanvas as ememc
import envi.archs.thumb16.disasm as eatd
oper = eatd.ArmPgmStatRegOper(1,15)
#smc = ememc.StringMemoryCanvas(vw)
#oper.render(smc, None, 0)
#smc.strval == 'SPSR_fcxs'
###############################################33

class ArmInstructionSet(unittest.TestCase):
    ''' main unit test with all tests to run '''
    
    # defaults for settings - not fully implimented and won't be so until after ARMv8 is completed.
    armTestVersion = 0x100
    armTestOnce = True

    def test_msr(self):
        # test the MSR instruction
        import envi.archs.arm as e_arm;reload(e_arm)
        am=e_arm.ArmModule()
        op = am.archParseOpcode('d3f021e3'.decode('hex'))
        self.assertEqual('msr CPSR_c, #0xd3', repr(op))

    def test_envi_arm_operands(self):
        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        vw.addMemoryMap(0, 7, 'firmware', '\xff' * 16384*1024)
        #vw.addMemoryMap(0x400000, 7, 'firmware', '\xff' * 16384*1024)
        vw.addMemoryMap(0xbfb00000, 7, 'firmware', '\xfe' * 16384*1024)


        # testing the ArmImmOffsetOper

        # ldr r3, [#0xbfb00010]
        emu = vw.getEmulator()
        emu._forrealz = True    # cause base_reg updates on certain Operands.

        emu.writeMemory(0xbfb00010, "abcdef98".decode('hex'))
        op = vw.arch.archParseOpcode('\x080\x9f\xe5', va=0xbfb00000)
        print repr(op)
        print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))



        # ldr r3, [r11, #0x8]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.setRegister(11, 0xbfb00010)
        op = vw.arch.archParseOpcode('\x08\x30\xbb\xe5', va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(11))

        self.assertEqual(hex(0xccddeeff), hex(value))


        
        # ldr r3, [r11], #0x8
        emu.writeMemory(0xbfb00010, "ABCDEF10".decode('hex'))
        emu.setRegister(11, 0xbfb00010)
        op = vw.arch.archParseOpcode('\x08\x30\x9b\xe4', va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(11))

        self.assertEqual(hex(0xbfb00018), hex(emu.getRegister(11)))
        self.assertEqual(hex(0x10efcdab), hex(value))


        # ldr r3, [r11], #-0x8
        emu.writeMemory(0xbfb00010, "ABCDEF10".decode('hex'))
        emu.setRegister(11, 0xbfb00010)
        op = vw.arch.archParseOpcode('\x08\x30\x1b\xe4', va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(11))

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(11)))
        self.assertEqual(hex(0x10efcdab), hex(value))


        # testing the ArmScaledOffsetOper
        
        # ldr r2, [r10, r2 ]
        emu = vw.getEmulator()
        op = vw.arch.archParseOpcode('02209ae7'.decode('hex'), va=0xbfb00000)
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00010, "abcdef98".decode('hex'))
        print repr(op)
        print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        self.assertEqual(hex(8), hex(emu.getRegister(2)))



        # ldr r2, [r10], r2 
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00008, "ABCDEF10".decode('hex'))
        op = vw.arch.archParseOpcode('02209ae6'.decode('hex'), va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(10))

        self.assertEqual(hex(0xbfb00010), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x10efcdab), hex(value))

        
        
        # ldr r2, [r10, -r2 ]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.writeMemory(0xbfb00008, "f000f000".decode('hex'))
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)
        op = vw.arch.archParseOpcode('02203ae7'.decode('hex'), va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(10))

        self.assertEqual(hex(0x00f000f0), hex(value))
        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))


        
        # ldr r2, [r10, r2 ]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)
        op = vw.arch.archParseOpcode('0220bae7'.decode('hex'), va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(10))

        self.assertEqual(hex(0xccddeeff), hex(value))
        self.assertEqual(hex(0xbfb00018), hex(emu.getRegister(10)))

        # Scaled with shifts/roll
        # ldr r2, [r10, r2 lsr #32]
        emu = vw.getEmulator()
        op = vw.arch.archParseOpcode('22209ae7'.decode('hex'), va=0xbfb00000)
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00010, "abcdef98".decode('hex'))
        print repr(op)
        print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(8), hex(emu.getRegister(2)))



        # ldr r2, [r10], r2 
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00008, "ABCDEF10".decode('hex'))
        op = vw.arch.archParseOpcode('22219ae6'.decode('hex'), va=0xbfb00000)
        value = op.getOperValue(1, emu)
        print repr(op)
        print hex(value)
        print hex(emu.getRegister(10))

        self.assertEqual(hex(0xbfb00010), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(8), hex(emu.getRegister(2)))
        self.assertEqual(hex(0x10efcdab), hex(value))


        # testing the ArmRegOffsetOper
        


        
    def test_envi_arm_assorted_instrs(self):
        #setup initial work space for test
        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        vw.addMemoryMap(0, 7, 'firmware', '\xff' * 16384*1024)
        vw.addMemoryMap(0x400000, 7, 'firmware', '\xff' * 16384*1024)
        emu = vw.getEmulator()
        #took out next line while testing routine
        #mu.logread = 
        emu.logwrite = True
        badcount = 0
        goodcount = 0
        for archz, bytez, va, reprOp, iflags, emutests in instrs:
            ranAlready = False  # support for run once only
            #itterate through architectures 
            #for arch_mask in range(ARCH_REVSLEN): # will have to redo when architecture version dictionary is finalized for now will just run once
            for arch_mask in range(1): # place holder for now. Run once
                #test_arch = int(pow(2,arch_mask)) #mask for architecture to test
                test_arch = 0 # temporary until dictionary finalized
                #if ((not ranAlready) or (not self.armTestOnce)) and ((archz & test_arch & self.armTestVersion) != 0): # until dictionary finalized
                if not ranAlready: # until dictionary is finalized - allows to run once
                    ranAlready = True
                    #arm.ThumbModule.archVersion = arm.ArmModule.archVersion = archBitMask[arch_mask][0]   # todo once arch dict is done
                    op = vw.arch.archParseOpcode(bytez.decode('hex'), 0, va)
                    redoprepr = repr(op).replace(' ','').lower()
                    redgoodop = reprOp.replace(' ','')
                    if redoprepr != redgoodop:
                        print  bytez,redgoodop
                        print  bytez,redoprepr
                        print
                        #print out binary representation of opcode for checking
                        num, = struct.unpack("<I", bytez.decode('hex'))
                        print hex(num)
                        bs = bin(num)[2:].zfill(32)
                        ''' For reference
        00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
                        print out fields to check against bible
                        '''
                        print bs
                        #to help with bit decoding - will be removed when done
                        choice = 2
                        def zero():
                            print bs[0:4], bs[4:6], bs[6], bs[7:12], bs[12:24], bs[24:28], bs[28:],'  ; dataprocessing and misc'
                            print '         ', bs[7:11], bs[11], bs[12:16], bs[16:20], bs[20:], '  ; and, '
                            print '                          ', bs[20:25], bs[25:28], bs[28:], ' ; lsr (Middle should be 010)'
                        def one():
                            print bs[0:4], bs[4:6], bs[6], bs[7:11], bs[11], bs[12:16], bs[16:20], bs[20:25], bs[25:27], bs[27], bs[28:] + '  ; register'
                            print '                           '+bs[20:]+ '  ; immediate'
                            print '                           '+bs[20:24], bs[24], bs[25:27], bs[27], bs[28:] + '  ; register shift'
                        def two():
                            print bs[0:4], bs[4:6], bs[6], bs[7:11],bs[11],bs[12:16] , bs[16:20], bs[20:], '  ; tst (immediate)'
                            print '                          ', bs[20:25], bs[25:27], bs[27], bs[28:], ' ; register'
                            print '                          ', bs[20:24], bs[24], bs[25:27], bs[27], bs[28:], ' ; register shift'
                            print
                        def three():
                            pass
                        case = {0:zero,
                                1:one,
                                2:two,
                                3:three,
                                }
                        case[choice]()
                        print
                        
                        badcount += 1
                        
                        raise Exception("FAILED to decode instr:  %.8x %s - should be: %s  - is: %s" % \
                                ( va, bytez, reprOp, repr(op) ) )
                        self.assertEqual((bytez, redoprepr), (bytez, redgoodop))
                        
                    # test some things
                    # will comment out when just testing disassembly - don't know that emulation stuff works yet
                    '''
                    if not len(emutests):
                        # if we don't have tests, let's just run it in the emulator anyway and see if things break
                        if not self.validateEmulation(emu, op, (), ()):
                            goodcount += 1
                        else:
                            raise Exception( "FAILED emulation:  %s" % op )
                            badcount += 1
                    else:
                        raise Exception( "FAILED emulation:  %s" % op )
                        badcount += 1
                    '''

        #op = vw.arch.archParseOpcode('12c3'.decode('hex'))
        ##rotl.b #2, r3h
        ##print( op, hex(0x7a) )
        #emu.setRegisterByName('r3h', 0x7a)
        #emu.executeOpcode(op)
        ##print( hex(emu.getRegisterByName('r3h')), emu.getFlag(CCR_C) )
        ##0xef False

    def test_envi_arm_thumb_switches(self):
        pass

    def validateEmulation(self, emu, op, setters, tests):
        # first set any environment stuff necessary
        ## defaults
        emu.setRegister(REG_ER3, 0x414141)
        emu.setRegister(REG_ER4, 0x444444)
        emu.setRegister(REG_ER5, 0x454545)
        emu.setRegister(REG_ER6, 0x464646)
        emu.setRegister(REG_SP, 0x450000)

        ## special cases
        for tgt, val in setters:
            try:
                # try register first
                emu.setRegisterByName(tgt, val)
            except e_reg.InvalidRegisterName, e:
                # it's not a register
                if type(tgt) == str and tgt.startswith("CCR_"):
                    # it's a flag
                    emu.setFlag(eval(tgt), val)
                elif type(tgt) in (long, int):
                    # it's an address
                    emu.writeMemValue(tgt, val, 1) # limited to 1-byte writes currently
                else:
                    raise Exception( "Funkt up Setting:  %s = 0x%x" % (tgt, val) )

        emu.executeOpcode(op)

        # do tests
        success = 1
        for tgt, val in tests:
            try:
                # try register first
                testval = emu.getRegisterByName(tgt)
                if testval == val:
                    #print("SUCCESS: %s  ==  0x%x" % (tgt, val))
                    continue
                success = 0
                raise Exception("FAILED(reg): %s  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))

            except e_reg.InvalidRegisterName, e:
                # it's not a register
                if type(tgt) == str and tgt.startswith("CCR_"):
                    # it's a flag
                    testval = emu.getFlag(eval(tgt)) 
                    if testval == val:
                        #print("SUCCESS: %s  ==  0x%x" % (tgt, val))
                        continue
                    success = 0
                    raise Exception("FAILED(flag): %s  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))

                elif type(tgt) in (long, int):
                    # it's an address
                    testval = emu.readMemValue(tgt, 1)
                    if testval == val:
                        #print("SUCCESS: 0x%x  ==  0x%x" % (tgt, val))
                        continue
                    success = 0
                    raise Exception("FAILED(mem): 0x%x  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))

                else:
                    raise Exception( "Funkt up test: %s == %s" % (tgt, val) )

        # do some read/write tracking/testing
        #print emu.curpath
        if len(emu.curpath[2]['readlog']):
            outstr = emu.curpath[2]['readlog']
            if len(outstr) > 10000: outstr = outstr[:10000]
            #print( repr(op) + '\t\tRead: ' + repr(outstr) )
        if len(emu.curpath[2]['writelog']):
            outstr = emu.curpath[2]['writelog']
            if len(outstr) > 10000: outstr = outstr[:10000]
            #print( repr(op) + '\t\tWrite: '+ repr(outstr) )
        emu.curpath[2]['readlog'] = []
        emu.curpath[2]['writelog'] = []

        return not success
"""
def generateTestInfo(ophexbytez='6e'):
    '''
    Helper function to help generate test cases that can easily be copy-pasta
    '''
    h8 = e_h8.H8Module()
    opbytez = ophexbytez
    op = h8.archParseOpcode(opbytez.decode('hex'), 0, 0x4000)
    print( "opbytez = '%s'\noprepr = '%s'"%(opbytez,repr(op)) )
    opvars=vars(op)
    opers = opvars.pop('opers')
    print( "opcheck = ",repr(opvars) )

    opersvars = []
    for x in range(len(opers)):
        opervars = vars(opers[x])
        opervars.pop('_dis_regctx')
        opersvars.append(opervars)

    print( "opercheck = %s" % (repr(opersvars)) )



raw_instrs = [
    ]


def genDPArm():
    out = []
    for z in range(16):
        for x in range(32):
            y = 0xe0034567 + (x<<20) + (z<<4)
            try:
                bytez = struct.pack("<I", y)
                out.append(bytez)
                op = vw.arch.archParseOpcode(bytez)
                print "%x %s" % (y, op)

            except:
                print "%x error" % y

    file('dpArmTest','w').write(''.join(out))   

        
def genMediaInstructionBytes():
    # Media Instructions
    out = []
    for x in range(32):
        for z in range(8):
            y = 0xe6034f17 + (x<<20) + (z<<5)
            try:
                bytez = struct.pack("<I", y)
                out.append(bytez)
                op = vw.arch.archParseOpcode(bytez)
                print "%x %s" % (y, op)

            except:
                print "%x error" % y

    file('mediaArmTest','w').write(''.join(out))

def genAdvSIMD():
    # thumb
    outthumb = []
    outarm = []
    base = 0xe0043002 # generic Adv SIMD with Vn=8, Vd=6, Vm=4 (or 4,3,2, depending)
    # thumb dp, arm dp (with both 0/1 for U)
    for option in (0xf000000, 0x2000000, 0x3000000, 0x1f000000):
        for A in range(16): # three registers of same length
            for B in range(16): # three registers of same length
                for C in range(16):
                    val = base + (A<<19) + (B<<8) + (C<<4)
                    bytez = struct.pack("<I", val)
                    outarm.append(bytez)
                    bytez = struct.pack("<HH", val>>16, val&0xffff)
                    outthumb.append(bytez)

                    #op = vw.arch.archParseOpcode(bytez)
                    #print "%x %s" % (val, op)

    out = outarm
    out.extend(outthumb)
    file('advSIMD', 'wb').write(''.join(out))
   


# thumb 16bit IT, CNBZ, CBZ
