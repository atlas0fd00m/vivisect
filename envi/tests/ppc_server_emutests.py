'''
Ways to access registers, flags or memory:
    'regname'       eg: 'f30'                   - get/set register by name
    'REG_CONSTANT'  eg: 'REG_R3' or 'REG_XER'   - get/set register by constant (good for
                                                        specific, hard to reach flags)
    0xADDRESS       eg: 0xdeadb33f              - read/write memory at address
    '[expression]'  eg: '[r0 + 4]'              - read/write memory at expression
                    or '[0xdeadbeef + 243]'
    '[expr:20]'     eg: '[r0+4:20]'             - read/write 20 bytes of memory at expr
'''


emutests = {
    #'FC00F024': [
    #    {
    #        'setup': (
    #            ('f30', 0x4010000000000000),
    #            ('f0', 0x4030000000000000),
    #            ('[r1-20]', 'abcdef'),      # test memory/expression setter
    #        ),
    #        'tests': (
    #            ('f30', 0x4010000000000000),
    #            ('f0', 0x4010000000000000),
    #            ('[r1-20]', 'abcdef'),      # test tester for memory/expression (nop, but)
    #        ),
    #    }
    #],  # fdiv f0,f0,f30 FAILING?

    '7C002214': [
        {
            'setup': (
                ('r0', 42),
                ('r4', 31337),
            ),
            'tests': (
                ('r0', 42 + 31337),
                ('r4', 31337),
            ),
        }
    ],  # 'add r0,r0,r4' GOOD TEST.  CR is not changed nor set

    '7C005214': [
        {
            'setup': (
                ('r0', 69),
                ('r10', 420),
                ('cr0', 0),
            ),
            'tests': (
                ('r0', 69 + 420),
                ('r10', 420),
                ('cr0', 0),
            ),
        }
    ],  # 'add r0,r0,r10' GOOD TEST

    '7C634A15': [
        {
            'setup': (
                ('r3', 1337),
                ('r9', 7331),
                ('cr0', 0),
            ),
            'tests': (
                ('r3', 1337 + 7331),
                ('r9', 7331),
                ('cr0', 4),
            ),
        },
    ],  # 'add. r3,r3,r9' GOOD TEST

    '7C002814': [
        {
            'setup': (
                ('r0', 1234),
                ('r5', 4321),
            ),
            'tests': (
                ('r0', 1234 + 4321),
                ('r5', 4321),
            ),
        }
    ],  # 'addc r0,r0,r5' GOOD TEST

    '3000FFFF': [
        {
            'setup': (
                ('r0', 0),
                ('CA', 0),
            ),
            'tests': (
                ('r0', 0xffffffffffffffff),
                ('CA', 1),
            ),
            # GOOD TEST BUT IS 64bit.  32bit r0 == 0xffffffff
        },
        {
            'setup': (
                ('r0', 1337),
                ('CA', 0),
            ),
            'tests': (
                ('r0', 1336),
                ('CA', 0),
            ),
        }

    ],  # 'addic r0,r0,-0x1' GOOD TEST,  2 SETUPS IN HERE.  ONE NEGATIVE AND ONE POSITIVE

    '7C005114': [
        {
            'setup': (
                ('r0', 10),
                ('r10', 11),
            ),
            'tests': (
                ('r0', 21),
                ('r10', 11),
            ),
        },
        {
            'setup': (
                ('r0', -50),
                ('r10', 60),
            ),
            'tests': (
                ('r0', 10),
                ('r10', 60),
            ),
        },
        {
            'setup': (
                ('r0', -60),
                ('r10', 50),
            ),
            'tests': (
                ('r0', 0xfffffffffffffff6),
                ('r10', 50),
            ),
        }

    ],  # adde r0,r0,r10' GOOD TEST, 3 SETUPS IN HERE

    '3801FFC0': [
        {
            'setup': (
                ('r0', 255),
                ('r1', 0),
            ),
            'tests': (
                ('r0', 0xffffffffffffffc0),
                ('r1', 0),
            ),
        }
    ],  # 'addi r0,r1,-0x40' GOOD TEST

    '38010100': [
        {
            'setup': (
                ('r0', 255),
                ('r1', 0),
            ),
            'tests': (
                ('r0', 0x100),
                ('r1', 0),
            ),
        },
        {
            'setup': (
                ('r0', 255),
                ('r1', 1),
            ),
            'tests': (
                ('r0', 0x101),
                ('r1', 1),
            ),
        }
    ],  # 'addi r0,r1,0x100' GOOD TEST, 2 SETUPS

    '3400FFFF': [

        {
            'setup': (
                ('r0', 0),
                ('CA', 0),
            ),
            'tests': (
                ('r0', 0xffffffffffffffff),
                ('CA', 1),
                ('cr0', 0b1000),
            ),
            #
        },
        {
            'setup': (
                ('r0', 1337),
                ('CA', 0),
            ),
            'tests': (
                ('r0', 1336),
                ('CA', 0),
                ('cr0', 0b0100),
            ),
        }
    ],  # 'addic. r0,r1,-0x1' GOOD TEST, 2 SETUPS

    '3C02FFFC': [
        {
            'setup': (
                ('r0', 0),
                ('r2', 0x40000),
            ),
            'tests': (
                ('r0', 0),
                ('r2', 0x40000),
            ),
        },
        {
            'setup': (
                ('r0', 0),
                ('r2', 0x04000),
            ),
            'tests': (
                ('r0', 0xfffffffffffc4000),
            ),
        },
        {
            'setup': (
                ('r0', 0x50000),
                ('r2', 0x40000),
            ),
            'tests': (
                ('r0', 0),
                ('r2', 0x40000),

            ),
        }
    ],  # 'addis r0,r2,-0x4' GOOD TEST, 3 SETUPS

    '7C000194': [
        {
            'setup': (
                ('r0', 197),
                ('CA', 0),
            ),
            'tests': (
                ('r0', 197),
                ('CA', 0),
            ),
        }
    ],  # '7C000194', 'addze r0,r0

    '7c005838': [
        {
            'setup': (
                ('r0', 0b00001010),
                ('r11', 0b01011111),
            ),
            'tests': (
                ('r0', 0b00001010),
                ('r11', 0b01011111),
            ),
        }
    ],  # '7C000194', 'and r0,r0,r11'

    '7c00B039': [
        {
            'setup': (
                ('r0', 0b00001010),
                ('r22', 0b01011111),
                ('cr0', 0b0000),
            ),
            'tests': (
                ('r0', 0b00001010),
                ('r22', 0b01011111),
                ('cr0', 0b0100),
            ),
        }
    ],  # '7C000B039', 'and. r0,r0,r22'

    '7C003878': [
        {
            'setup': (
                ('r0', 0b00001010),
                ('r7', 0b01011111),  # r0 is ANDed with the One's complement of the value in this register (0b10100000)
                ('cr0', 0b0000),
            ),
            'tests': (
                ('r0', 0b00000000),
                ('r7', 0b01011111),
                ('cr0', 0b0000),
            ),
        },
        {
            'setup': (
                ('r0', 0b11111010),  # 0b11111010
                ('r7', 0b01011111),  # r0 is ANDed with the One's complement of the value in this register (0b10100000)
                ('cr0', 0b0000),
            ),
            'tests': (
                ('r0', 0b10100000),
                ('r7', 0b01011111),
                ('cr0', 0b0000),
            ),
        },
        {
            'setup': (
                ('r0', 0b11111010),  # 0b11111010
                ('r7', 0b0),  # ANDed with the One's complement of the value in this register (0b11111111)
                ('cr0', 0b0000),
            ),
            'tests': (
                ('r0', 0b11111010),
                ('r7', 0b0),
                ('cr0', 0b0000),
            ),
        }
    ],  # 7C003878', 'andc r0,r0,r7

    '7EC0E079': [
        {
            'setup': (
                ('r0', 0b0),
                ('r22', 0b01011111),  # 0b01011111
                ('r28', 0b01000000),  # 0b10111111
                ('cr0', 0b0),
            ),
            'tests': (
                ('r0', 0b00011111),
                ('r22', 0b01011111),
                ('r28', 0b01000000),
                ('cr0', 0b0100),
            ),
        }
    ],  # '7EC0E079', 'andc. r0,r22,r28'

    '70000007': [
        {
            'setup': (
                ('r0', 0b10000),  # (ANDed with 0b0111
                ('cr0', 0b0),
            ),
            'tests': (
                ('r0', 0b0000),
                ('cr0', 0b0010),
            ),
        },
        {
            'setup': (
                ('r0', 0b0111),
                ('cr0', 0),
            ),
            'tests': (
                ('r0', 0b0111),
                ('cr0', 0b0100),
            ),
        }
    ],  # '7EC0E079', 'andi. r0,r0,0x7'

    '7780FFF8': [
        {
            'setup': (
                ('r28', 0b10001111110111101000),
                ('cr0', 0),
            ),
            'tests': (
                ('r0', 0b10000000000000000000),
                ('cr0', 0b0100),
            ),
        },
        {
            'setup': (
                ('r28', 0),
                ('cr0', 0),
            ),
            'tests': (
                ('r0', 0),
                ('cr0', 0b0010),
            ),
        }
    ],  # '7780FFF8', 'andis r0,r28,0xfff8'

    '4BFFFFF0': [
        {
            'setup': (
                ('PC', 0x10000534),
            ),
            'tests': (
                ('PC', 0x10000524),
            ),
        }
    ],  # '4BFFFFF0', 'b -0x10'

    '429F0005': [  # ('429F0005', 'bcl 0x4') actually
        {
            'setup': (
                ('PC', 0x10000534),
            ),
            'tests': (
                ('PC', 0x10000538),
            ),
        }
    ],  # ('429F0005', 'bcl 0x4')

    '7CAF5000': [  # L = 1
        {
            'setup': (
                ('r15', 55000),
                ('r10', 65000),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
        {
            'setup': (
                ('r15', 65000),
                ('r10', 65000),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
        {
            'setup': (
                ('r15', 55000),
                ('r10', 5000),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        }
    ],  # '7CAF5000', 'cmpd cr1,r15,r10'

    '2CA00000': [
        {
            'setup': (
                ('r0', 55000),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },  # test#0
        {
            'setup': (
                ('r0', 0),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },  # test#1
        {
            'setup': (
                ('r0', -2),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        }
    ],  # '2CA00000', 'cmpdi cr1,r0,0x0'

    '7CAA7840': [  # crfD = 0, L = 1
        {
            'setup': (
                ('r10', 55000),
                ('r15', 65000),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
        {
            'setup': (
                ('r10', 65000),
                ('r15', 55000),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },
        {
            'setup': (
                ('r10', 65000),
                ('r15', 65000),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
    ],  # '7CAA7840', 'cmpld 0,1,r10,r15

    '28AF0008': [  # cr1 = 0, L = 1
        {
            'setup': (
                ('r15', 65000),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },
        {
            'setup': (
                ('r15', 7),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
        {
            'setup': (
                ('r15', 8),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
    ],  # '28AF0008', 'cmpldi cr1,r15,0x8'

    '7C8A3840': [  # cmplw cr1,r10,r7 (cmp crD,0,rA,rB)
        {
            'setup': (
                ('r10', 10),
                ('r7', 9),
                ('cr1', 0)
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },
        {
            'setup': (
                ('r10', 10),
                ('r7', 10),
                ('cr1', 0)
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
        {
            'setup': (
                ('r10', 8),
                ('r7', 10),
                ('cr1', 0)
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
    ],  # '7C8A3840', 'cmplw cr1,r10,r7' (cmp crD,0,rA,rB)

    '288A0002': [  # cmpli crD,0,rA,UIMM
        {
            'setup': (
                ('r10', 10),
            ),
            'tests': (
                ('cr1', 0b0100
                 ),
            ),
        },
        {
            'setup': (
                ('r10', 1),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
        {
            'setup': (
                ('r10', 2),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
    ],  # '288A0002', 'cmplwi cr1,r10,0x2' (cmp crD,0,rA,rB)

    '7C90D000': [  # (cmp crD,0,rA,rB)
        {
            'setup': (
                ('r16', 10),
                ('r26', 1),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },
        {
            'setup': (
                ('r16', 1),
                ('r26', 1),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
        {
            'setup': (
                ('r16', 0),
                ('r26', 2),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
    ],  # '7C90D000', 'cmpw cr1,r16,r26'

    '2C800000': [  # cmp crD,0,rA,rB
        {
            'setup': (
                ('r0', 10),
            ),
            'tests': (
                ('cr1', 0b0100),
            ),
        },
        {
            'setup': (
                ('r0', 0),
            ),
            'tests': (
                ('cr1', 0b0010),
            ),
        },
        {
            'setup': (
                ('r0', -10),
            ),
            'tests': (
                ('cr1', 0b1000),
            ),
        },
    ],  # '2C800000', 'cmpwi cr1,r0,0x0'

    '7C000074': [
        {
            'setup': (
                ('r0', 0b000001),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r0', 0b111111),
                ('cr0', 0b0000),
            ),
        },
        {
            'setup': (
                ('r0', 0b0000011),
            ),
            'tests': (
                ('r0', 0b111110),
                ('cr0', 0b0000),
            ),
        },
    ],  # '7C000074', 'cntlzd r0,r0

    '7C000075': [
        {
            'setup': (
                ('r0', 0b000001),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r0', 0b111111),
                ('cr0', 0b0100),
            ),
        },
        {
            'setup': (
                ('r0', 0b0000011),
            ),
            'tests': (
                ('r0', 0b111110),
                ('cr0', 0b0100),
            ),
        },
    ],  # '7C000075', 'cntlzd. r0,r0


    '7C0C03D2': [
    {
            'setup': (
                ('r0', 9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 6),
            ),
        },

        {
            'setup': (
                ('r0', -9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0xfffffffffffffffa),
            ),
        },

        {
            'setup': (
                ('r0', 0),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0x0),
            ),
        },

        {
            'setup': (
                ('r0', 1),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 54),
            ),
        },

        {
            'setup': (
                ('r0', -1),
                ('r12', 54)
            ),
            'tests': (
                ('r0', 0xffffffffffffffca),
            ),
        },
    ],  # 'divd r0,r12,r0'

    '7C0C03D3': [
    {
            'setup': (
                ('r0', 9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 6),
                ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r0', -9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0xfffffffffffffffa),
                ('cr0', 0b1000)
            ),
        },

        {
            'setup': (
                ('r0', 0),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0),
                ('cr0', 0b010)
            ),
        },

        {
            'setup': (
                ('r0', 1),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 54),
                ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r0', -1),
                ('r12', 54)
            ),
            'tests': (
                ('r0', 0xffffffffffffffca),
                ('cr0', 0b1000)
            ),
        },

        {
            'setup': (
                ('r0', -1),
                ('r12', -1)
            ),
            'tests': (
                ('r0', 1),
                ('cr0', 0b0100)
            ),
        },
    ],  # 'divd. r0,r12,r0'

    '7c0c07d2': [
        {
            'setup': (
                ('r0', 9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 6),
                ('XER', 0)
            ),
        },

        {
            'setup': (
                ('r0', -9),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0xfffffffffffffffa),
                ('XER', 0)
            ),
        },

        {
            'setup': (
                ('r0', 0),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 0x0),
                ('XER', 0xc0000000)
            ),
        },

        {
            'setup': (
                ('r0', 1),
                ('r12', 54),
            ),
            'tests': (
                ('r0', 54),
                ('XER', 0)
            ),
        },

        {
            'setup': (
                ('r0', -1),
                ('r12', 54)
            ),
            'tests': (
                ('r0', 0xffffffffffffffca),
                ('XER', 0)
            ),
        },
    ],  # 'divdo r0,r12,r0'

    '7c0c07d3': [
        {
            'setup': (
                ('r0', 9),
                ('r12', 57),  # Remainder will not be supplied
                ('XER', 0),
                ('cr0', 0b0000)

            ),
            'tests': (
                ('r0', 6),
                ('XER', 0),
                ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r0', -9),
                ('r12', 54),
                ('cr0', 0b0000),
                ('XER', 0)

            ),
            'tests': (
                ('r0', 0xfffffffffffffffa),
                ('XER', 0),
                ('cr0', 0b1000)
            ),
        },

        {
            'setup': (
                ('r0', 0),
                ('r12', 54),
                ('cr0', 0b0000),
                ('XER', 0)

            ),
            'tests': (
                ('r0', 0x0),
                ('XER', 0xc0000000),
                ('cr0', 0b0011)
            ),
        },

        {
            'setup': (
                ('r0', 1),
                ('r12', 54),
                ('cr0', 0b0000),
                ('XER', 0)

            ),
            'tests': (
                ('r0', 54),
                ('XER', 0),
                ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r0', -1),
                ('r12', 54),
                ('cr0', 0b0000)

            ),
            'tests': (
                ('r0', 0xffffffffffffffca),
                ('XER', 0),
                ('cr0', 0b1000)
            ),
        },
    ],  # 'divdo. r0,r12,r0'


    '7D0A5238': [
        {
            'setup': (
                ('r10', 10),
                ('r8', 10),
            ),
            'tests': (
                ('r10', 0xffffffffffffffff),
            ),
        },
        {
                'setup': (
                    ('r10', 1),
                    ('r8', 10),
                ),
                'tests': (
                    ('r10', 0xfffffffffffffff4),
                ),
        },
        {
                'setup': (
                    ('r10', 10),
                    ('r8', 1),
                ),
                'tests': (
                    ('r10', 0xfffffffffffffff4),
                ),
        },


    ],  # '7D0A5238', 'eqv. r10,r8,r10'




    # '7D0A5239': [
    #     {
    #         'setup': (
    #             ('r10', 10),
    #             ('r8', 10),
    #         ),
    #         'tests': (
    #             ('r10', 0xffffffffffffffff),
    #             ('cr0', 0b1000)
    #         ),
    #     },
    #     {
    #             'setup': (
    #                 ('r10', 10),
    #                 ('r8', 1),
    #             ),
    #             'tests': (
    #                 ('r10', 0xfffffffffffffff4),
    #                 ('cr0', 0b1000)
    #             ),
    #     },
    #     {
    #             'setup': (
    #                 ('r10', 1),
    #                 ('r8', 10),
    #             ),
    #             'tests': (
    #                 ('r10', 0xfffffffffffffff4),
    #                 ('cr0', 0b1000)
    #             ),
    #     }
    #
    #     ], # '7D0A5238', 'eqv. r10,r8,r10'

    # For the following condition register tests:
    # - the third bit is the one being operated on
    # - the result goes into the third bit of cr0
    # - cr6 is checked to make sure it doesn't change
    '4C42D202': [  # ('4C42D202', 'crand eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D202', 'crand eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D102': [  # ('4C42D102', 'crandc eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1000),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D102', 'crandc eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D242': [  # ('4C42D242', 'creqv eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D242', 'creqv eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D1C2': [  # ('4C42D1C2', 'crnand eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1000),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D1C2', 'crnand eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D042': [  # ('4C42D042', 'crnor eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1000),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D042', 'crnor eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D382': [  # ('4C42D382', 'cror eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D382', 'cror eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D342': [  # ('4C42D342', 'crorc eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D342', 'crorc eq,eq,cr6.eq') crbD,crbA,crbB

    '4C42D182': [  # ('4C42D182', 'crxor eq,eq,cr6.eq')
       {
           'setup': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1101),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1010),
               ('cr6', 0b0010),
           ),
           'tests': (
               ('cr0', 0b1000),
               ('cr6', 0b0010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1010),
           ),
           'tests': (
               ('cr0', 0b1111),
               ('cr6', 0b1010),
           ),
       },
       {
           'setup': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
           'tests': (
               ('cr0', 0b1101),
               ('cr6', 0b1101),
           ),
       },
    ],  # ('4C42D182', 'crxor eq,eq,cr6.eq') crbD,crbA,crbB

    '7D4A0775': [  # ('7D4A0775', 'extsb. r10,r10') - Not working
        {
            'setup': (
                ('r10', 0x12345880),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0xffffffffffffff80),
                ('cr0', 0b1000)
            ),
        },
        {
            'setup': (
                ('r10', 0xffffff70),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0x70),
                ('cr0', 0b0100)
            ),
        },
        {
            'setup': (
                ('r10', 0x12345670),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0x70),
                ('cr0', 0b0100)
            ),
        },
        {
            'setup': (
                ('r10', 0x80),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0xffffffffffffff80),
                ('cr0', 0b1000)
            ),
        },
        {
            'setup': (
                ('r10', 0x0),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0x0),
                ('cr0', 0b0010)
            ),
        },
    ],

    '7D4A0735': [  # ('7D4A0735', 'extsh. r10,r10')
        {
            'setup': (
                ('r10', 0x8800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0xffffffffffff8800),
                ('cr0', 0b1000)
            ),
        },
        {
            'setup': (
                ('r10', 0x87800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0x7800),
                ('cr0', 0b0100)
            ),
        },        {
            'setup': (
                ('r10', 0x12348800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0xffffffffffff8800),
                ('cr0', 0b1000)
            ),
        },
        {
            'setup': (
                ('r10', 0x0),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r10', 0x0),
                ('cr0', 0b0010)
            ),
        },        
    ],  #  ('7D4A0735', 'extsh. r10,r10')

    '7c01ffb5': [  # ('7D4A0735', 'extsw. r1,r0')
        {
            'setup': (
                ('r0', 0x80008800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r1', 0xffffffff80008800),
                ('cr0', 0b1000)
            ),
        },
        {
            'setup': (
                ('r0', 0xffff70087800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r1', 0x70087800),
                ('cr0', 0b0100)
            ),
        },        {
            'setup': (
                ('r0', 0xf12348800),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r1', 0x12348800),
                ('cr0', 0b0100)
            ),
        },
        {
            'setup': (
                ('r0', 0x0),
                ('cr0', 0b0000)
            ),
            'tests': (
                ('r1', 0x0),
                ('cr0', 0b0010)
            ),
        },
        
    ],  #  ('7c01ffb5', 'extsw. r10,r10')


    # 'FC00002A': [  # ('FC00002A', 'fadd f0,f0,f0')
    #     {
    #         'setup': (
    #             ('f0', 0x4036c923a29c779a),  # IEEE754 double 22.785699999999999
    #         ),
    #         'tests': (
    #             ('f0', 0x4046c923a29c779a),  # IEEE754 double 45.571399999999997
    #         ),
    #     }
    # ],  # ('FC00002A', 'fadd f0,f0,f0')

    # Both 7C1E071E and 7C1E071F are  tested for isel because the last bit is
    # a "don't care" bit, and we want to make sure both states are tested.

    '7C1E071E': [  # ('7C1E071E', 'isel r0,r30,r0,cr7.lt')
        {
            'setup': (
                ('r0', 0xff),
                ('r30', 0x1234),
                ('cr7', 0b1000),

            ),

            'tests': (
                ('r0', 0x1234),
                ('r30', 0x1234),
                ('cr7', 0b1000),

            ),
        },

        {
            'setup': (
                ('r0', 64),
                ('r30', 0),
                ('cr7', 0b1000),

            ),

            'tests': (
                ('r0', 0),
                ('r30', 0),
                ('cr7', 0b1000),

            ),
        },

        {
            'setup': (
                ('r0', 64),
                ('r30', 55),
                ('cr7', 0b0000),

            ),

            'tests': (
                ('r0', 64),
                ('r30', 55),
                ('cr7', 0b0000),

            ),
        },

    ],  # ('7C1E071E', 'isel r0,r30,r0,cr7.lt')

    '7C1E071F': [  # ('7C1E071F', 'isel r0,r30,r0,cr7.lt')
        {
            'setup': (
                ('r0', 0xff),
                ('r30', 0x1234),
                ('cr7', 0b1000),

            ),

            'tests': (
                ('r0', 0x1234),
                ('r30', 0x1234),
                ('cr7', 0b1000),

            ),
        },

        {
            'setup': (
                ('r0', 64),
                ('r30', 0),
                ('cr7', 0b1000),

            ),

            'tests': (
                ('r0', 0),
                ('r30', 0),
                ('cr7', 0b1000),

            ),
        },

        {
            'setup': (
                ('r0', 64),
                ('r30', 55),
                ('cr7', 0b0000),

            ),

            'tests': (
                ('r0', 64),
                ('r30', 55),
                ('cr7', 0b0000),

            ),
        },

    ],  # ('7C1E071F', 'isel r0,r30,r0,cr7.lt')

    '880A0000': [  # ('880A0000', 'lbz r0,0x0(r10)')
        {
            'setup': (
                                # Set the register to be filled with some generic data
                        ('r0', 0x0102030405060708),
                                # Fill memory with an 8-byte pattern
                        (0x000000f8, bytes.fromhex('F1F2F3F4F5F6F7F8')),
                                # Set the address to be the last byte of the pattern
                        ('r10', 0x00000000000000FF),
            ),
            'tests': (
                ('r0', 0xF8),
            ),
        }
    ],  # ('880A0000', 'lbz r0,0x0(r10)')

    'A00A0000': [  # lhz r0,0x0(r10)
        {
            'setup': (
                # Set the register to be filled with some generic data
                ('r0', 0x0102030405060708),
                # Fill memory with an 8-byte pattern
                (0x000000f8, bytes.fromhex('F1F2F3F4F5F6F7F8')),
                # Set the address to be the last byte of the pattern
                ('r10', 0x00000000000000FE),
            ),
            'tests': (
                ('r0', 0xF7F8),
            ),
        }
    ],

    '6D29FF00': [  # ('6D29FF00', 'xoris r9,r9,)
        {
            'setup': (
                ('r9', 0b00110011),
            ),
            'tests': (
                ('r9', 0b11111111000000000000000000110011),

            ),
        }
    ],  # ('6D29FF00', 'xoris r9,r9,0xff00')

    '6929FFFF': [  # ('6929FFFF', 'xori r9,r9,0xffff)
        {
            'setup': (
                ('r9', 0b0000000000110011),
                #         1111111111111111
            ),
            'tests': (
                ('r9', 0b1111111111001100),

            ),
        }
    ],  # ('6929FFFF', 'xori r9,r9,0xffff)
#
    # '7D484279': [  # ('7D484279', 'xor. r8,r10,r8')
    #     {
    #         'setup': (
    #             ('r8', 0b0000000000110011),
    #             ('r10', 0b0000000000001011),
    #         ),
    #         'tests': (
    #             ('r8', 0b00111000),
    #             ('cr0', 0b0100),
    #         ),
    #     }
    # ],  # ('7D484279', 'xor. r8,r10,r8')

    '7D294278': [  # ('7D294278', 'xor r9,r9,r8')
        {
            'setup': (
                ('r9', 0b0000000000110011),
                ('r8', 0b0000000000001011),
            ),
            'tests': (
                ('r9', 0b00111000),
            ),
        }
    ],  # ('7D294278', 'xor r9,r9,r8')

    '38000011': [  # ('38000011', 'li r0,0x11')
        {
            'setup': (
                ('r0', 0x4),
            ),
            'tests': (
                ('r0', 0x11),
            ),
        }
    ],  # ('38000011', 'li r0,0x11')

    '3800FFFF': [  # ('3800FFFF', 'li r0,-0x1')
        {
            'setup': (
                ('r0', 0x4),
            ),
            'tests': (
                ('r0', 0xffffffffffffffff),
            ),
        }
    ],  # ('38000011', 'li r0,0x11')


    # 'FC00069C': [  # ('FC00069C', 'fcfid f0,f0') Unsupported
    #    {
    #        'setup': (
    #            ('f0', 0x428ad70a),
    #        ),
    #        'tests': (
    #            ('f0', 0x41d0a2b5c2800000),
    #        ),
    #    }
    # ],  # ('FC00069C', 'fcfid f0,f0')

    '8004FFF0': [ # ('8004FFF0', 'lwz r0,-0x10(r4)')
        {
            'setup': (
                        # Set the register to be filled with some generic data
                ('r0', 0x0102030405060708),
                        # Fill memory with an 8-byte pattern
                (0x000000f8, bytes.fromhex('F1F2F3F4F5F6F7F8')),
                        # Set r4 be the last 4 bytes of the pattern (0xFC) + 16
                        # (so r4 - 0x10 == 0xF8)
                ('r4', 0xFC + 16),
            ),
            'tests': (
                ('r0', 0x00000000F5F6F7F8),
            ),
        }
    ],  # ('8004FFF0', 'lwz r0,-0x10(r4)')

    '8004FFF1': [  # ('8004FFF1', 'lwz r0,-0x11(r4)')
        {
            'setup': (
                        # Set the register to be filled with some generic data
                ('r0', 0x0102030405060708),
                        # Fill memory with an 8-byte pattern
                        # 0x00001050 is the starting address.
                        # F1F2F3F4 gets put in 0x1050 - 0x1053
                        # Ultimatly this range is 0x1050 - 0x1057
                (0x00001050, bytes.fromhex('F1F2F3F4F5F6F7F8')),
                        # Set r4 be the last 4 bytes of the pattern (0x1054) + 16
                        # (so r4 - 0x10 == 0xF8)
                ('r4', 0x1054 + 15), #0x10c
            ),
            'tests': (
                #Takes the values stored in the memory range 0x1054 - 0x1057 and put is in r0
                ('r0', 0x00000000F5F6F7F8),
                ('r4', 0x1054 + 15)
            ),
        }
    ],      # ('8004FFF1', 'lwz r0,-0x11(r4)')

    '7C0AF8EE': [ #('7C0AF8EE', 'lbzux r0,r10,r31')  #Aaron is fixing this
        {
            'setup': (
                ('r0', 0x7740),
                ('r10', 0x10010100),
                ('r31', 0x100),
                (0x10010100 + 0x100, bytes.fromhex('11223344'))
                    ),
    
            'tests':(
                ('r0',0x11),
                ('r10',0x10010200),
                ('r31', 0x100)
    
            ),
        }
    ],  # ('7C0AF8EE', 'lbzux r0,r10,r31')

    # '7C0C00AE': [ # ('7C0C00AE', 'lbzx r0,r12,r0')
    #     {
    #         'setup': (
    #             ('r0', 0x10010123),
    #             ('r12', 0x0),
    #             (0x10010123, bytes.fromhex('1020304050607080'))
    #                 ),
    #
    #         'tests':(
    #             ('r0', 0x1),
    #             ('r12', 0)
    #         ),
    #     }
    # ],  # ('7C0C00AE', 'lbzx r0,r12,r0')


    'E8010000': [ # ld r0,0x0(r21)
        {
            'setup': (
                ('r0', 0x0),
                ('r1', 0x10000400),
                (0x10000400, bytes.fromhex('AB9371D0FEDCBA98'))
            ),
            'tests':(
                ('r0', 0xAB9371D0FEDCBA98),
            ),
        }
    ],

    '7C0C00AE': [ # ('7C0C00AE', 'lbzx r0,r12,r0')
        {
            'setup': (
                ('r0', 0x000000f8),
                ('r12', 0x0),
                (0x000000f8, bytes.fromhex('f1f2f3f4f5f6f7f8'))
                    ),

            'tests':(
                ('r0', 0xf1),

            ),
        }
    ],  # ('7C0C00AE', 'lbzx r0,r12,r0')

    # '7C0007B5': [  # ('7C0007B4', 'extsw. r0,r0')
    #     {
    #         'setup': (
    #             ('r0', -2),
    #         ),
    #         'tests': (
    #             ('r0', 0xfffffffffffffffe),
    #             ('cr0', 0b1000)
    #         ),
    #     },
    #     {
    #         'setup': (
    #             ('r0', 0),
    #             ('r30', 64),
    #             ('cr7', 0b1000),

    #         ),
    #         'tests': (
    #             ('r0', 0x2),
    #             ('cr0', 0b0100)
    #         ),
    #     },
    # ],  # ('7C0007B4', 'extsw. r0,r0')

    'F81FFFF0': [  # ('F81FFFF0', 'std r0,-0x10(r31)')
        {
            'setup': (
                ('r0', 0x12345678),
                ('r31', 0x000000e8 + 0x10),
                (0x000000e8, bytes.fromhex('0000000000000000')),

            ),

            'tests': (
            (0x000000e8, bytes.fromhex('0000000012345678')),

            ),
        },

        {
            'setup': (
                ('r0', 0x0123456789abcdef),
                ('r31', 0x000000e8 + 0x10),
                (0x000000e8, bytes.fromhex('0000000000000000')),

            ),

            'tests': (
            (0x000000e8, bytes.fromhex('0123456789abcdef')),

            ),
        },
    ],  # ('F81FFFF0', 'std r0,-0x10(r31)')

    '981CFFFF':  # ('981CFFFF', 'stb r0,-0x1(r28)')
        [
            {
                'setup': (
                    ('r0', 0x12345678),
                    ('r28', 0x000000e8 + 0x1),
                    (0x000000e8, bytes.fromhex('0000000000000000'))

                ),

                'tests': (
                    (0x000000e8, bytes.fromhex('7800000000000000')),

                ),
            },
        ],

    'B0030000':  # ('('B0030000', 'sth r0,0x0(r3)')
        [
            {
                'setup': (
                    ('r0', 0x12345678),
                    ('r3', 0x000000e8),
                    (0x000000e8, bytes.fromhex('0000000000000000'))

                ),

                'tests': (
                    (0x000000e8, bytes.fromhex('5678000000000000')),

                ),
            },
        ],  #  ('B0030000', 'sth r0,0x0(r3))

    '900AFFEC':  # ('900AFFEC', 'stw r0,-0x14(r10)')
        [
            {
                'setup': (
                    ('r0', 0x12345678),
                    ('r10', 0x000000e8 + 0x14),
                    (0x000000e8, bytes.fromhex('0000000000000000'))

                ),

                'tests': (
                    (0x000000e8, bytes.fromhex('1234567800000000')),

                ),
            },
        ],  #  ('900AFFEC', 'stw r0,-0x14(r10)')

      '78001788': [  # ('78001788', 'rldic r0,r0,0x2,0x1e')
        {
            'setup': (
                ('r0', 0),
            ),
            'tests': (
                ('r0', 0x0),
            ),
        }
    ], # ('7C0007B4', 'extsw r0,r0')

    # 'EC010024': [ # ('EC010024', 'fdivs f0,f1,f0') Unsupported 4/8/2021
    #     {
    #         'setup': (
    #             ('f1', 0x4010000000000000),
    #             ('f0', 0x4030000000000000),
    #         ),
    #         'tests': (
    #             ('f1', 0x4010000000000000),
    #             ('f0', 0x4010000000000000),
    #         ),
    #     }
    # ],  # ('EC010024', 'fdivs f0,f1,f0')

    '3C00FFFF': [  # ('3C00FFFF', 'lis r0,-0x1' (equivalent to addis rD,0,value))
        {
            'setup': (
                ('r0', 0x4),
            ),
            'tests': (
                ('r0', 0xffffffffffff0000),
            ),
        }
    ],  # ('3C00FFFF', 'lis r0,-0x1' )

    # 'E8070122': [  # ('E8070122', 'lwa r0,0b100101001(r7)')
    #     {
    #         'setup': (
    #             ('r7', 0x10010100),
    #             ('r0', 0x0102030405060708)
    #         ),
    #         'tests': (
    #             ('r0', 0xb),
    #         ),
    #     }
    # ],  # ('E8070122', 'lwa r0,0x120(r7)')

    '8C04FFFF': [ #('8C04FFFF', 'lbzu r0,-0x1(r4)')
        {
            'setup': (
                ('r0', 0x0102030405060708),
                (0x000000f8, bytes.fromhex('F1F2F3F4F5F6F7F8')),
                ('r4', 0xf9 -1),
            ),
            'tests':(
                ('r0', 0xff),
            ),
        }
    ],  # ('8C04FFFF', 'lbzu r0,-0x1(r4)')

    # '7C001828': [  # ('7C001828', 'lwarx r0,0x0,r3') unsupported
    #     {
    #         'setup': (
    #             ('r0', 0x10010124),
    #             ('r3', 0x4),  # (EA should be r0+r3 and a multiple of 4
    #         ),
    #
    #         'tests': (
    #             ('r0', 0x10010128),
    #         ),
    #     }
    # ],  # ('7C001828', 'lwarx r0,0x0,r3')
    #
    # '8404FFFC': [ # ('8404FFFC', 'lwzu r0,-0x4(r4)')
    #     {
    #         'setup': (
    #                     # Set the register to be filled with some generic data
    #             ('r0', 0x12345678),
    #             (0x10000150, bytes.fromhex('F1F2F3F4F5F6F7F8')),
    #             ('r4', 0x10000150 + 4),
    #         ),
    #         'tests': (
    #             ('r0', 0xf1f2f3f4),
    #             ('r4', 0x1000150)
    #         ),
    #     }
    # ],  # ('8404FFFC', 'lwzu r0,-0x4(r4)')

    # '4C100000': [ # ('4C100000', 'mcrf cr0,cr4')
    #     {
    #         'setup': (
    #             ('cr0', 0b0100),
    #             ('cr4', 0b0010)
    #         ),
    #
    #         'tests': (
    #             ('cr0', 0b0010),
    #             ),
    #     }
    # ], # ('4C100000', 'mcrf cr0,cr4')

    #
    # '7C000026': [  # ('7C000026', 'mfcr r0')
    #     {
    #         'setup': (
    #             ('cr0', 0b0010),
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 0b0010),
    #
    #         ),
    #     }
    # ],  # ('7C000026', 'mfcr r0')

    # 'FC00048E': [  # ('FC00048E', 'mffs f0')
    #     {
    #         'setup': (
    #             ('FPSCR', 0b0010),
    #             ('f0', 0)
    #
    #         ),
    #
    #         'tests': (
    #             ('f0', 0b0010),
    #
    #         ),
    #     }
    # ],  # ('FC00048E', 'mffs f0')

    # 'F81FFFF0': [  # ('F81FFFF0', 'std r0,-0x10(r31)')
    #     {
    #         'setup': (
    #             ('r0', 0x12345678),
    #             ('r31', 0x10000150 + 0x10),
    #             (0x10000160, bytes.fromhex('F1F2F3F4F5F6F7F8')),
    #
    #         ),
    #
    #         'tests': (
    #         (0x10000160, bytes.fromhex('12345678')),
    #         ),
    #     }
    # ],  # ('F81FFFF0', 'std r0,-0x10(r31)')

    '7C005850': [  # ('7C005850', 'subf r0,r0,r11')
        {
            'setup': (
                ('r0', 0b0000),
                ('r11', 0b00000000000000000000000000000011) # One's comp = 0b11111111111111111111111111111100

            ),

            'tests': (
                ('r0', 3),

            ),
        },
        {
            'setup': (
                ('r0', 0b0010),
                ('r11', 0b0000000000000000000000000000001)

            ),

            'tests': (
                ('r0', 0xffffffffffffffff),

            ),
        }
    ],  # ('7C005850', 'subf r0,r0,r11')

    '7C005851': [  # ('7C005850', 'subf r0,r0,r11')
        {
            'setup': (
                ('r0', 0b0000),
                ('r11', 0b00000000000000000000000000000011) # One's comp = 0b11111111111111111111111111111100

            ),

            'tests': (
                ('r0', 3),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r0', 0b0010),
                ('r11', 0b0000000000000000000000000000001)

            ),

            'tests': (
                ('r0', 0xffffffffffffffff),
                ('cr0', 0b1000)

            ),
        }
    ],  # ('7C005851', 'subf. r0,r0,r11')

     '7C044010': [  # ('7C044010', 'subfc r0,r4,r8')
        {
            'setup': (
                ('r4',50),
                ('r8', 255 )

            ),

            'tests': (
                ('r0', 205),

            ),
        },
         {
             'setup': (
                 ('r4', 100),
                 ('r8', 50)

             ),

             'tests': (
                 ('r0', 0xffffffffffffffce),

             ),
         },
         {
             'setup': (
                 ('r4', 100),
                 ('r8', 100)

             ),

             'tests': (
                 ('r0', 0),

             ),
         },
    ],  # ('7C044010', 'subfc r0,r4,r8')

    '7C044011': [  # ('7C044011', 'subfc. r0,r4,r8')
        {
            'setup': (
                ('r4',50),
                ('r8', 255 )

            ),

            'tests': (
                ('r0', 205),
                ('cr0', 0b0100)

            ),
        },
         {
             'setup': (
                 ('r4', 100),
                 ('r8', 50)

             ),

             'tests': (
                 ('r0', 0xffffffffffffffce),
                 ('cr0', 0b1000)

             ),
         },
         {
             'setup': (
                 ('r4', 100),
                 ('r8', 100)

             ),

             'tests': (
                 ('r0', 0),
                 ('cr0', 0b0010)

             ),
         },
    ],  # ('7C044011', 'subfc. r0,r4,r8')

    '7C044410': [  # ('7C044410', 'subfco r0,r4,r8')
        {
            'setup': (
                ('r4', 0xFFFFFFFFFFFFFFFF),
                ('r8', -0xFFFFFFFFFFFFFFFF)

            ),

            'tests': (
                ('r0', 0x2),
            ),
        },

        {
            'setup': (
                ('r4', 100),
                ('r8', 50)

            ),

            'tests': (
                ('r0', 0xffffffffffffffce),
            ),
        },

        {
            'setup': (
                ('r4', 100),
                ('r8', 100)

            ),

            'tests': (
                ('r0', 0),
            ),
        },
    ],  #  ('7C044410', 'subfco r0,r4,r8')

    '7C044411': [  # ('7C044411', 'subfco. r0,r4,r8')
        {
            'setup': (
                ('r4', 0xFFFFFFFFFFFFFFFF),
                ('r8', -0xFFFFFFFFFFFFFFFF)

            ),

            'tests': (
                ('r0', 0x2),
                ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r4', 100),
                ('r8', 50)

            ),

            'tests': (
                ('r0', 0xffffffffffffffce),
                ('cr0', 0b1000)
            ),
        },

        {
            'setup': (
                ('r4', 100),
                ('r8', 100)

            ),

            'tests': (
                ('r0', 0),
                ('cr0', 0b0010)
            ),
        },
    ],  # ('7C044411', 'subfco. r0,r4,r8')

    # '7C000110': [  # ('7C000110', 'subfe r0,r0,r0')
    #     {
    #         'setup': (
    #             ('r0',0x8000),
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 0xffffffffffffffff),
    #
    #         ),
    #     },
    #     {
    #          'setup': (
    #              ('r0', 100),
    #
    #          ),
    #
    #          'tests': (
    #              ('r0', 0xffffffffffffffff),
    #
    #          ),
    #     },
    #      {
    #          'setup': (
    #              ('r0', 100),
    #
    #          ),
    #
    #          'tests': (
    #              ('r0', 0xffffffffffffffff),
    #
    #          ),
    #      },
    # ],  # ('7C000110', 'subfe r0,r0,r0')

    # '7C0B5092': [  # ('7C0B5092', 'mulhd r0,r11,r10')
    #     {
    #         'setup': (
    #             ('r11',10),
    #             ('r10', 255 )
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 2550),
    #             # ('cr0', 0b0100)
    #
    #         ),
    #     },
    #      {
    #          'setup': (
    #              ('r11', 100),
    #              ('r10', 50)
    #
    #          ),
    #
    #          'tests': (
    #              ('r0', 5000),
    #              # ('cr0', 0b1000)
    #
    #          ),
    #      },
    #      {
    #          'setup': (
    #              ('r11', 100),
    #              ('r10', 100)
    #
    #          ),
    #
    #          'tests': (
    #              ('r0', 10000),
    #              # ('cr0', 0b0010)
    #
    #          ),
    #      },
    #  ],  # ('7C0B5092', 'mulhd r0,r11,r10')

    '7D4A53B8': [  # ('7D4A53B8', 'nand r10,r10,r10')
        {
            'setup': (
                ('r10', 0b11001100),

            ),

            'tests': (
                ('r10', 0xffffffffffffff33),
                # ('cr0', 0b0100)

            ),
        },
    ],

    '7D4A53B9': [  # ('7D4A53B9', 'nand. r10,r10,r10')
        {
            'setup': (
                ('r10', 0b11001100),

            ),

            'tests': (
                ('r10', 0xffffffffffffff33),
                ('cr0', 0b1000)

            ),
        },
    ],

    '7C0000D0': [  # ('7C0000D0', 'neg r0,r0')
        {
            'setup': (
                ('r0', 0xc),

            ),

            'tests': (
                ('r0', 0xfffffffffffffff4),
                # ('cr0', 0b1)

            ),
        },
        {
            'setup': (
                ('r0', 0xfffffffffffffff4),

            ),

            'tests': (
                ('r0', 0xc),
                # ('cr0', 0b1)

            ),
        },
    ],

    # '7D4900D1': [  # ('7D4900D1', 'neg. r10,r9')  Cr Isn't being set
    #     {
    #         'setup': (
    #             ('r9', 0xc),
    #
    #         ),
    #
    #         'tests': (
    #             ('r10', 0xfffffffffffffff4),
    #             ('cr0', 0b1000)
    #
    #         ),
    #     },
    #     {
    #         'setup': (
    #             ('r9', 0xfffffffffffffff4),
    #
    #         ),
    #
    #         'tests': (
    #             ('r10', 0xc),
    #             ('cr0', 0b0100)
    #
    #         ),
    #     },
    # ], # ('7D4900D1', 'neg. r10,r9')


    '7D4A40F8': [  # ('7D4A40F8', 'nor r10,r10,r8')
        {
            'setup': (
                ('r10', 0xc),
                ('r8', 0xc)

            ),

            'tests': (
                ('r10', 0xfffffffffffffff3),
                #('cr0', 0b1000)

            ),
        },
        {
            'setup': (
                ('r10', 0xffffffffffffff23),
                ('r8', 0x0)

            ),

            'tests': (
                ('r10', 0xdc),
                #('cr0', 0b0100)

            ),
        },
    ], # ('7D4A40F8', 'nor r10,r10,r8')

    '7D4A40F9': [  # ('7D4A40F8', 'nor. r10,r10,r8')
        {
            'setup': (
                ('r10', 0xc),
                ('r8', 0xc)

            ),

            'tests': (
                ('r10', 0xfffffffffffffff3),
                ('cr0', 0b1000)

            ),
        },
        {
            'setup': (
                ('r10', 0xffffffffffffff23),
                ('r8', 0x0)

            ),

            'tests': (
                ('r10', 0xdc),
                ('cr0', 0b0100)

            ),
        },
    ],  # ('7D4A40F9', 'nor. r10,r10,r8')

    '7C005378': [  # ('7C005378', 'or r0,r0,r10')
        {
            'setup': (
                ('r0', 0b0110),
                ('r10', 0b1001)

            ),

            'tests': (
                ('r0', 0b1111),
            ),
        },
        {
            'setup': (
                ('r0', 0b0001),
                ('r10', 0b0001)


            ),

            'tests': (
                ('r0', 0b0001),

            ),
        },
    ],  # ('7C005378', 'or r0,r0,r10')

    '7C005379': [  # ('7C005379', 'or. r0,r0,r10')
        {
            'setup': (
                ('r0', 0b0110),
                ('r10', 0b1001)

            ),

            'tests': (
                ('r0', 0b1111),
                ('cr0', 0b0100)
            ),
        },
        {
            'setup': (
                ('r0', 0b0001),
                ('r10', 0b0001)

            ),

            'tests': (
                ('r0', 0b0001),
                ('cr0', 0b0100)
            ),
        },
    ],  # ('7C005379', 'or. r0,r0,r10')

    '7E004339': [  # ('7E004338', 'orc. r0,r16,r8')
        {
            'setup': (
                ('r16', 0b0110),
                ('r8', 0b1001),
            ),

            'tests': (
                ('r0', 0xfffffffffffffff6),
                ('cr0', 0b1000)            ),
        },
        {
            'setup': (
                ('r16', 0b0001),
                ('r8', 0b0001)

            ),

            'tests': (
                ('r0', 0xffffffffffffffff),
                ('cr0', 0b1000)
            ),
        },
    ],  # ('7E004339', 'orc. r0,r16,r8')

    '60000001': [  # ('60000001', 'ori r0,r0,0x1')
        {
            'setup': (
                ('r0', 0b0110),


            ),

            'tests': (
                ('r0', 0b0111),
            ),
        },
        {
            'setup': (
                ('r0', 0b0001),
                ('r10', 0b0001)

            ),

            'tests': (
                ('r0', 0b0001),

            ),
        },
    ],  # ('60000001', 'ori r0,r0,0x1')

    '60000002': [  # ('60000002', 'ori r0,r0,0x2')
        {
            'setup': (
                ('r0', 0b0110),


            ),

            'tests': (
                ('r0', 0b0110),

            ),
        },
        {
            'setup': (
                ('r0', 0b0010),


            ),

            'tests': (
                ('r0', 0b0010),


            ),
        },
    ],  # ('60000002', 'ori r0,r0,0x2')

    '64000001': [  #('64000001', 'oris r0,r0,0x1')
        {
            'setup': (
                ('r0', 0b0110),

            ),

            'tests': (
                ('r0', 0x10006),

            ),
        },
        {
            'setup': (
                ('r0', 0b0010),

            ),

            'tests': (
                ('r0', 0x10002),

            ),
        },
    ],  # ('64000001', 'oris r0,r0,0x2')

    # '7C6300F4': [  # ('7C6300F4', 'popcntb r3,r3') unsupported
    #     {
    #         'setup': (
    #             ('r3', 0b0110),
    #
    #         ),
    #
    #         'tests': (
    #             ('r3', 0x10006),
    #
    #         ),
    #     },
    #     {
    #         'setup': (
    #             ('r3', 0b0010),
    #
    #         ),
    #
    #         'tests': (
    #             ('r3', 0x10002),
    #
    #         ),
    #     },
    # ],  # ('7C6300F4', 'popcntb r3,r3')

    # '7C6303F4': [  # ('7C6303F4', 'popcntd r3,r3') Unsupported
    #     {
    #         'setup': (
    #             ('r0', 0b0110),
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 0x10006),
    #
    #         ),
    #     },
    #     {
    #         'setup': (
    #             ('r0', 0b0010),
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 0x10002),
    #
    #         ),
    #     },
    # ],  # ('7C6303F4', 'popcntd r3,r3')

    '78001788':  # ('78001788', 'rldic r0,r0,0x2,0x1e')
    [
        {
            'setup': (
                ('r0', 0b1),

            ),

            'tests': (
                ('r0', 0b100),

            ),
        },
        {
            'setup': (
                ('r0', 0b0010),

            ),

            'tests': (
                ('r0', 0b1000),

            ),
        },
        {
            'setup': (
                ('r0', 0x80000000),

            ),

            'tests': (
                ('r0', 0x200000000),

            ),
        },
        #  This setup not working correctly in emulator.  Test case is correct though
        # { 'setup': (
        #         ('r0', 0x8000000000000000),
        #
        #     ),
        #
        #     'tests': (
        #         ('r0', 0x0),
        #
        #     ),
        # },

    ],  # ('78001788', 'rldic r0,r0,0x2,0x1e')


    '7EC00036':  # ('7EC00036', 'sld r0,r22,r0')
    [
        {
            'setup': (
                ('r0', 0b1),
                ('r22',0b1)

            ),

            'tests': (
                ('r0', 0b10),

            ),
        },

        {
            'setup': (
                ('r0', 0b1),
                ('r22',0b10)

            ),

            'tests': (
                ('r0', 0b100),

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r22',0b11)

            ),

            'tests': (
                ('r0', 0b11000),

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r22',0x8000000000000000)

            ),

            'tests': (
                ('r0', 0b0),

            ),
        },
    ],  # ('7EC00036', 'sld r0,r22,r0')

    '7EC00037':  # ('7EC00037', 'sld. r0,r22,r0')
    [
        {
            'setup': (
                ('r0', 0b1),
                ('r22',0b1)

            ),

            'tests': (
                ('r0', 0b10),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b1),
                ('r22',0b10)

            ),

            'tests': (
                ('r0', 0b100),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r22',0b11)

            ),

            'tests': (
                ('r0', 0b11000),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r22',0x8000000000000000)

            ),

            'tests': (
                ('r0', 0b0),
                ('cr0', 0b0010)

            ),
        },
    ],  # ('7EC00037', 'sld. r0,r22,r0') ('7C00F830', 'slw r0,r0,r31')

    '7C00F830':  # ('7C00F830', 'slw r0,r0,r31')
    [
        {
            'setup': (
                ('r0', 0b1),
                ('r31',0b1)

            ),

            'tests': (
                ('r0', 0b10),
                # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b1),
                ('r31',0b10)

            ),

            'tests': (
                ('r0', 0b100),
               # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r31',0b11)

            ),

            'tests': (
                ('r0', 0b11000),
                # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r31',0x8000000000000000)

            ),

            'tests': (
                ('r0', 0b11),
                # ('cr0', 0b0010)

            ),
        },
    ],  # ('7C00F830', 'slw r0,r0,r31')

    '7C00F831':  # ('7C00F831', 'slw. r0,r0,r31')
    [
        {
            'setup': (
                ('r0', 0b1),
                ('r31',0b1)

            ),

            'tests': (
                ('r0', 0b10),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b1),
                ('r31',0b10)

            ),

            'tests': (
                ('r0', 0b100),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r31',0b11)

            ),

            'tests': (
                ('r0', 0b11000),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r0', 0b11),
                ('r31',0x8000000000000000)

            ),

            'tests': (
                ('r0', 0b11),
                ('cr0', 0b0100)

            ),
        },
    ],  # ('7C00F831', 'slw. r0,r0,r31')

    '7D4A2E34':  # ('7D4A2E34', 'srad r10,r10,r5')
    [
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b1)

            ),

            'tests': (
                ('r10', 0b110),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b10)

            ),

            'tests': (
                ('r10', 0b11),
                # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b100)

            ),

            'tests': (
                ('r10', 0b0),
                # ('cr0', 0b0100)

            ),
        },
    ],

    '7D4A2E35':  # ('7D4A2E35', 'srad. r10,r10,r5')
    [
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b1)

            ),

            'tests': (
                ('r10', 0b110),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b10)

            ),

            'tests': (
                ('r10', 0b11),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r5',0b0100)

            ),

            'tests': (
                ('r10', 0b0),
                ('cr0', 0b0010)

            ),
        },
        # {  #  issue made
        #     'setup': (
        #         ('r10', -4),
        #         ('r5',0b100)
        #
        #     ),
        #
        #     'tests': (
        #         ('r10', 0xfffffffffffffff),
        #         ('cr0', 0b1000)
        #
        #     ),
        # },
    ],

    '7C009674':  # ('7C009674', 'sradi r0,r0,0x12')
    [
        {
            'setup': (
                ('r0', 0b1100),

            ),

            'tests': (
                ('r0', 0b0),
                #  ('cr0', 0b0010)

            ),
        },
        {
            'setup': (
                ('r0', 0b11000000000000000000),
            ),

            'tests': (
                ('r0', 0b11),
                # ('cr0', 0b0100)
            ),
        },

        {
            'setup': (
                ('r0', 0b11000000000000000000000000000000),
            ),
            'tests': (
                ('r0', 0b0011000000000000),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r0', 0b1100),
            ),

            'tests': (
                ('r0', 0b0),
                # ('cr0', 0b0010)

            ),
        },
        # {
        #     'setup': ( #still being weird about negative numbers
        #         ('r0', -4),
        #         ),
        #
        #     'tests': (
        #         ('r10', 0xfffffffffffffff),
        #         # ('cr0', 0b1000)
        #
        #     ),
        # },
    ],

    '7D4AEE30':  # ('7D4AEE30', 'sraw r10,r10,r29')
    [
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b1)

            ),

            'tests': (
                ('r10', 0b110),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                # ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b100)

            ),

            'tests': (
                ('r10', 0b0),
                # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r29',-128)

            ),

            'tests': (
                ('r10', 0b1100),
                # ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r29', -1)

            ),

            'tests': (
                ('r10', 0),
                # ('cr0', 0b0100)

            ),
        },
    ],

    '7D4AEE31':  # ('7D4AEE30', 'sraw. r10,r10,r29')
    [
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b1)

            ),

            'tests': (
                ('r10', 0b110),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b11)

            ),

            'tests': (
                ('r10', 0b1),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r10', 0b1100),
                ('r29',0b100)

            ),

            'tests': (
                ('r10', 0b0),
                ('cr0', 0b0010)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r29',-128)

            ),

            'tests': (
                ('r10', 0b1100),
                ('cr0', 0b0100)

            ),
        },

        {
            'setup': (
                ('r10', 0b1100),
                ('r29', -1)

            ),

            'tests': (
                ('r10', 0),
                ('cr0', 0b0010)

            ),
        },
    ],

    # '7C00FE70':  # ('7C00FE70', 'srawi r0,r0,0x1f')
    # [
    #     {
    #         'setup': (
    #             ('r0', 0x80000000),
    #
    #         ),
    #
    #         'tests': (
    #             ('r0', 0xffffffffffffffff),
    #             #  ('cr0', 0b0100)
    #
    #         ),
    #     },
    # ],

    '7c01c436':  # ('7C01C436', 'srd r1,r0,r24')
        [
            {
                'setup': (
                    ('r0', 0b1000),
                    ('r24', 0)

                ),

                'tests': (
                    ('r1', 0x8),
                    #  ('cr0', 0b0100)

                ),
            },
            {
                'setup': (
                    ('r0', 0x800),
                    ('r24', 4)

                ),

                'tests': (
                    ('r1', 0x80),
                    #  ('cr0', 0b0100)

                ),
            },

            {
                'setup': (
                    ('r0', 0x80000000),
                    ('r24', 1)

                ),

                'tests': (
                    ('r1', 0x40000000),
                    #  ('cr0', 0b0100)

                ),
            },

            {
                'setup': (
                    ('r0', 0x80000000),
                    ('r24', -1)

                ),

                'tests': (
                    ('r1', 0x0),
                    #  ('cr0', 0b0100)

                ),
            },
        ],

    '7D4ACC30':  # ('7D4ACC30', 'srw r10,r10,r25')
        [
            {
                'setup': (
                    ('r10', 0b1000),
                    ('r25', 0)

                ),

                'tests': (
                    ('r10', 0x8),
                    #  ('cr0', 0b0100)

                ),
            },
            {
                'setup': (
                    ('r10', 0x800),
                    ('r25', 4)

                ),

                'tests': (
                    ('r10', 0x80),
                    #  ('cr0', 0b0100)

                ),
            },

            {
                'setup': (
                    ('r10', 0x80000000),
                    ('r25', 1)

                ),

                'tests': (
                    ('r10', 0x40000000),
                    #  ('cr0', 0b0100)

                ),
            },

            {
                'setup': (
                    ('r10', 0x80000000),
                    ('r25', -1)

                ),

                'tests': (
                    ('r10', 0x0),
                    #  ('cr0', 0b0100)

                ),
            },
        ],

    # '981CFFFF':  # ('981CFFFF', 'stb r0,-0x1(r28)')
    #     [
    #         {
    #             'setup': (
    #                 ('r0', 0x3),
    #                 ('r28', 0x10000150 + 0x10)
    #
    #             ),
    #
    #             'tests': (
    #                 (0x00001050, bytes.fromhex('0003')),
    #                 #  ('cr0', 0b0100)
    #
    #             ),
    #         },
    #     ]

    '2000FFF8': [  # ('2000FFF8', 'subfic r0,r0,-0x8')
        {
            'setup': (
                ('r0', 8),

            ),

            'tests': (
                ('r0', 0xfffffffffffffff0),

            ),
        },

        {
            'setup': (
                ('r0', -8),

            ),

            'tests': (
                ('r0', 0),

            ),
        },

        {
            'setup': (
                ('r0', -16),

            ),

            'tests': (
                ('r0', 8),

            ),
        },

        {
            'setup': (
                ('r0', 0),

            ),

            'tests': (
                ('r0', 0xfffffffffffffff8),

            ),
        },
    ],  # ('64000001', 'oris r0,r0,0x2')

    '200000FF': [  # ('2000FFF8', 'subfic r0,r0,255')
        {
            'setup': (
                ('r0', 50),

            ),

            'tests': (
                ('r0', 205),

            ),
        },

        {
            'setup': (
                ('r0', -8),

            ),

            'tests': (
                ('r0', 263),

            ),
        },

        {
            'setup': (
                ('r0', 0),

            ),

            'tests': (
                ('r0', 255),

            ),
        },

    ],  # ('64000001', 'oris r0,r0,0x2')

    # '7D400106': [  # ('7D400106', 'wrtee r10')
    #     {
    #         'setup': (
    #             ('r10', 0xffffffffffffffff),
    #
    #         ),
    #
    #         'tests': (
    #             ('MSR', 0x8),
    #
    #         ),
    #     },
    #
    # ],  # ('7D400106', 'wrtee r10')

      '78001788': [  # ('78001788', 'rldic r0,r0,0x2,0x1e')
        {
            'setup': (
                ('r0', 0xffffffffffff0000),


            ),
            'tests': (
                ('r0', 0x3fffc0000),

            ),
        },
        {
            'setup': (
                ('r0', 0b1),


            ),
            'tests': (
                ('r0', 0b100),

            ),
        }
    ],  # ('78001788', 'rldic r0,r0,0x2,0x1e')

    '78001789': [  # ('78001788', 'rldic r0,r0,0x2,0x1e')
        {
            'setup': (
                ('r0', 0xffffffffffff0000),


            ),
            'tests': (
                ('r0', 0x3fffc0000),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r0', 0b1),


            ),
            'tests': (
                ('r0', 0b100),
                ('cr0', 0b0100)

            ),
        },
        {
            'setup': (
                ('r0', 0b11111000011111),
            ),
            'tests': (
                ('r0', 0b1111100001111100),
                ('cr0', 0b0100)
            ),
        },
        {
            'setup': (
                ('r0', 0x8000000000000000),


            ),
            'tests': (
                ('r0', 0x0),
                ('cr0', 0b0010)

            ),
        },
        {
            'setup': (
                ('r0', 0xf000000000000000),


            ),
            'tests': (
                ('r0', 0x0),
                ('cr0', 0b0010)

            ),
        },
    ],  # ('78001788', 'rldic r0,r0,0x2,0x1e')

     '7C000026': [  # ('7C000026', 'mfcr r0')
        {
            'setup': (
                ('r0', 0),
                ('CR', 0b0010),

            ),

            'tests': (
                ('CR', 0b0010),
                ('r0', 0b0010)
            ),
        },

        {
            'setup': (

                ('r0', 0),
                ('CR', 0x88882222),

            ),

            'tests': (

                ('r0', 0x88882222),
                ('CR', 0x88882222),

            ),
        }
    ],  # ('7C000026', 'mfcr r0')

    'E8070122': [ # ('E8070122', 'lwa r0,0x120(r7)')
        {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('EEDCBA98'))
                    ),

            'tests':(
                ('r0', 0xFFFFFFFFEEDCBA98),
            ),
        },

        {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('00000001'))
                    ),

            'tests':(
                ('r0', 0x1),
            ),
        },

                {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('1EDCBA98'))
                    ),

            'tests':(
                ('r0', 0x1EDCBA98),
            ),
        },

        {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('00000001'))
                    ),

            'tests':(
                ('r0', 0x1),
            ),
        },

        {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('8EDCBA98'))
                    ),

            'tests':(
                ('r0', 0xffffffff8EDCBA98),
            ),
        },

        {
            'setup': (
                ('r0', 0x0),
                ('r7', 0x10000200 - 0x120),
                (0x10000200, bytes.fromhex('7EDCBA98'))
                    ),

            'tests':(
                ('r0', 0x7EDCBA98),
            ),
        },

    ],  # ('E8070122', 'lwa r0,0x120(r7)')

    '5D4A383E': [ # ('5D4A383E', 'rlwnm r10,r10,r7,0x0,0x1f') (rotlw r10,r10,r7)

        {
            'setup': (
                ('r10', 0x84210124),
                ('r7', 0x11223344)
            ),

            'tests': (
                ('r10', 0x42101248),

            ),
        },

        {
            'setup': (
                ('r10', 0x84210124),
                ('r7', 0x11223345)
            ),

            'tests': (
                ('r10', 0x84202490),

            ),
        },
    ],

    ###### Unconditional Branch ######

    '48000000': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # b 0x40004560 (unconditional branch relative +0x0)

    '48000200': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004760 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # b 0x40004760 (unconditional branch relative +0x200)

    '4BFFD000': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40001560 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # b 0x40001560 (unconditional branch relative -0x3000)

    ##################################
    ###### Unconditional Branch ######
    ##################################

    ###### Unconditional Branch Absolute ######

    '48000002': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0x40004560 (unconditional branch relative 0x0)

    '48000202': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0x00000200 (unconditional branch absolute 0x200)

    '4BFFD002': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0xffffffffffffd000 (unconditional branch absolute -0x3000)

    ###### Unconditional Branch with Link ######

    '48000001': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004560 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004560 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40004560 (unconditional branch relative +0x0)

    '48000201': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004760 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004760 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40004760 (unconditional branch relative +0x200)

    '4BFFD001': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40001560 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40001560 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40001560 (unconditional branch relative -0x3000)

    ###### Unconditional Branch Absolute with Link ######

    '48000003': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0x40004560 (unconditional branch relative 0x0)

    '48000203': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0x00000200 (unconditional branch absolute 0x200)

    '4BFFD003': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0xffffffffffffd000 (unconditional branch absolute -0x3000)

    ###### Unconditional Conditional Branch (BO == 0b1x1xx) ######

    '42800002': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0x00000000 (unconditional branch absolute 0x0)

    '42800202': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0x00000200 (unconditional branch absolute 0x200)

    '428FD002': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # ba 0xffffffffffffd000 (unconditional branch absolute -0x3000)

    '42800001': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004560 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004560 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40004560 (unconditional branch relative +0x0)

    '42800201': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004760 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004760 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40004760 (unconditional branch relative +0x200)

    '4280D001': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40001560 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40001560 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bl 0x40001560 (unconditional branch relative -0x3000)

    '42800003': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000000 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0x40004560 (unconditional branch relative 0x0)

    '42800203': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000200 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0x00000200 (unconditional branch absolute 0x200)

    '4280D003': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xffffffffffffd000 ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bla 0xffffffffffffd000 (unconditional branch absolute -0x3000)

    ###### Unconditional Branch to CTR ######

    '4E800420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        },
    ], # bctr (unconditional branch to CTR)

    '4E800421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xFFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        },
    ], # bctrl (unconditional branch to CTR)

    ###### Unconditional Branch to LR ######

    '4E800020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
    ], # blr (unconditional branch to LR)

    '4E800021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xFFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # blrl (unconditional branch to LR)

    #####################################################
    ###### Branch Decrement and branch if CTR != 0 ######
    #####################################################

    '42000060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnz

    '42000061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnzl

    '42000062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnza

    '42000063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnzla

    #######################################################################
    ###### Branch Decrement and branch if CTR != 0 OR CONDITION TRUE ######
    #######################################################################

    ###### Branch Decrement and branch if CTR != 0 OR LT ######

    '41000060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzlt (branch LR if --CTR != 0 OR 4*cr0+lt == 1)

    '41000061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzltl (branch LR if --CTR != 0 OR 4*cr0+lt == 1)

    '41000062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzlta 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+lt == 1)

    '41000063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzltla 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+lt == 1)

    ###### Branch Decrement and branch if CTR != 0 OR GT ######

    '41010060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzgt (branch LR if --CTR != 0 OR 4*cr0+gt == 1)

    '41010061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgtl (branch LR if --CTR != 0 OR 4*cr0+gt == 1)

    '41010062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgta 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+gt == 1)

    '41010063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgtla 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+gt == 1)

    ###### Branch Decrement and branch if CTR != 0 OR EQ ######

    '41020060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzeq (branch LR if --CTR != 0 OR 4*cr0+eq == 1)

    '41020061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzeql (branch LR if --CTR != 0 OR 4*cr0+eq == 1)

    '41020062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzeqa 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+eq == 1)

    '41020063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzeqla 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+eq == 1)

    ###### Branch Decrement and branch if CTR != 0 OR SO ######

    '41030060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzso (branch LR if --CTR != 0 OR 4*cr0+so == 1)

    '41030061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzsol (branch LR if --CTR != 0 OR 4*cr0+so == 1)

    '41030062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzsoa 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+so == 1)

    '41030063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzsola 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+so == 1)

    ########################################################################
    ###### Branch Decrement and branch if CTR != 0 OR CONDITION FALSE ######
    ########################################################################

    ###### Branch Decrement and branch if CTR != 0 OR GE ######

    '40000060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzge (branch LR if --CTR != 0 OR 4*cr0+lt == 0)

    '40000061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgel (branch LR if --CTR != 0 OR 4*cr0+lt == 0)

    '40000062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgea 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+lt == 0)

    '40000063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgela 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+lt == 0)

    ###### Branch Decrement and branch if CTR != 0 OR LE ######

    '40010060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzle (branch LR if --CTR != 0 OR 4*cr0+gt == 0)

    '40010061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzlel (branch LR if --CTR != 0 OR 4*cr0+gt == 0)

    '40010062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzlea 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+gt == 0)

    '40010063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzlela 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+gt == 0)

    ###### Branch Decrement and branch if CTR != 0 OR NE ######

    '40020060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzne (branch LR if --CTR != 0 OR 4*cr0+eq == 0)

    '40020061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznel (branch LR if --CTR != 0 OR 4*cr0+eq == 0)

    '40020062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznea 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+eq == 0)

    '40020063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznela 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+eq == 0)

    ###### Branch Decrement and branch if CTR != 0 OR NS ######

    '40030060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzns (branch LR if --CTR != 0 OR 4*cr0+so == 0)

    '40030061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznsl (branch LR if --CTR != 0 OR 4*cr0+so == 0)

    '40030062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznsa 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+so == 0)

    '40030063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznsla 0x60 (branch 0x60 if --CTR != 0 OR 4*cr0+so == 0)

    #####################################################
    ###### Branch Decrement and branch if CTR == 0 ######
    #####################################################

    '42400060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdz

    '42400061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdzl

    '42400062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdza

    '42400063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdzla

    #######################################################################
    ###### Branch Decrement and branch if CTR == 0 OR CONDITION TRUE ######
    #######################################################################

    ###### Branch Decrement and branch if CTR == 0 OR LT ######

    '41400060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzlt (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    '41400061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzltl (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    '41400062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzlta 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+lt == 1)

    '41400063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzltla 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+lt == 1)

    ###### Branch Decrement and branch if CTR == 0 OR GT ######

    '41410060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzgt (branch LR if --CTR == 0 OR 4*cr0+gt == 1)

    '41410061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgtl (branch LR if --CTR == 0 OR 4*cr0+gt == 1)

    '41410062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgta 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+gt == 1)

    '41410063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgtla 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+gt == 1)

    ###### Branch Decrement and branch if CTR == 0 OR EQ ######

    '41420060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzeq (branch LR if --CTR == 0 OR 4*cr0+eq == 1)

    '41420061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzeql (branch LR if --CTR == 0 OR 4*cr0+eq == 1)

    '41420062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzeqa 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+eq == 1)

    '41420063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzeqla 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+eq == 1)

    ###### Branch Decrement and branch if CTR == 0 OR SO ######

    '41430060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzso (branch LR if --CTR == 0 OR 4*cr0+so == 1)

    '41430061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzsol (branch LR if --CTR == 0 OR 4*cr0+so == 1)

    '41430062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzsoa 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+so == 1)

    '41430063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzsola 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+so == 1)

    ########################################################################
    ###### Branch Decrement and branch if CTR == 0 OR CONDITION FALSE ######
    ########################################################################

    ###### Branch Decrement and branch if CTR == 0 OR GE ######

    '40400060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzge (branch LR if --CTR == 0 OR 4*cr0+lt == 0)

    '40400061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgel (branch LR if --CTR == 0 OR 4*cr0+lt == 0)

    '40400062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgea 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+lt == 0)

    '40400063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgela 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+lt == 0)

    ###### Branch Decrement and branch if CTR == 0 OR LE ######

    '40410060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzle (branch LR if --CTR == 0 OR 4*cr0+gt == 0)

    '40410061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzlel (branch LR if --CTR == 0 OR 4*cr0+gt == 0)

    '40410062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzlea 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+gt == 0)

    '40410063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzlela 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+gt == 0)

    ###### Branch Decrement and branch if CTR == 0 OR NE ######

    '40420060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzne (branch LR if --CTR == 0 OR 4*cr0+eq == 0)

    '40420061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznel (branch LR if --CTR == 0 OR 4*cr0+eq == 0)

    '40420062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznea 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+eq == 0)

    '40420063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznela 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+eq == 0)

    ###### Branch Decrement and branch if CTR == 0 OR NS ######

    '40430060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzns (branch LR if --CTR == 0 OR 4*cr0+so == 0)

    '40430061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznsl (branch LR if --CTR == 0 OR 4*cr0+so == 0)

    '40430062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznsa 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+so == 0)

    '40430063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznsla 0x60 (branch 0x60 if --CTR == 0 OR 4*cr0+so == 0)

    ###########################################################
    ###### Branch Decrement and branch to LR if CTR != 0 ######
    ###########################################################

    '4E000020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnzlr

    '4E000021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdnzlrl

    #######################################################################
    ###### Branch Decrement and branch to LR if CTR != 0 OR CONDITION TRUE ######
    #######################################################################

    ###### Branch Decrement and branch to LR if CTR != 0 OR LT ######

    '4D000020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzltlr (branch LR if --CTR != 0 OR 4*cr0+lt == 1)

    '4D000021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzltlrl (branch LR if --CTR != 0 OR 4*cr0+lt == 1)

    ###### Branch Decrement and branch to LR if CTR != 0 OR GT ######

    '4D010020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzgtlr (branch LR if --CTR != 0 OR 4*cr0+gt == 1)

    '4D010021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgtlrl (branch LR if --CTR != 0 OR 4*cr0+gt == 1)

    ###### Branch Decrement and branch to LR if CTR != 0 OR EQ ######

    '4D020020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzeqlr (branch LR if --CTR != 0 OR 4*cr0+eq == 1)

    '4D020021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzeqlrl (branch LR if --CTR != 0 OR 4*cr0+eq == 1)

    ###### Branch Decrement and branch to LR if CTR != 0 OR SO ######

    '4D030020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzsolr (branch LR if --CTR != 0 OR 4*cr0+so == 1)

    '4D030021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzsolrl (branch LR if --CTR != 0 OR 4*cr0+so == 1)

    ########################################################################
    ###### Branch Decrement and branch to LR if CTR != 0 OR CONDITION FALSE ######
    ########################################################################

    ###### Branch Decrement and branch to LR if CTR != 0 OR GE ######

    '4C000020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzgelr (branch LR if --CTR != 0 OR 4*cr0+lt == 0)

    '4C000021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzgelrl (branch LR if --CTR != 0 OR 4*cr0+lt == 0)

    ###### Branch Decrement and branch to LR if CTR != 0 OR LE ######

    '4C010020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnzlelr (branch LR if --CTR != 0 OR 4*cr0+gt == 0)

    '4C010021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnzlelrl (branch LR if --CTR != 0 OR 4*cr0+gt == 0)

    ###### Branch Decrement and branch to LR if CTR != 0 OR NE ######

    '4C020020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnznelr (branch LR if --CTR != 0 OR 4*cr0+eq == 0)

    '4C020021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznelrl (branch LR if --CTR != 0 OR 4*cr0+eq == 0)

    ###### Branch Decrement and branch to LR if CTR != 0 OR NS ######

    '4C030020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdnznslr (branch LR if --CTR != 0 OR 4*cr0+so == 0)

    '4C030021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
    ], # bdnznslrl (branch LR if --CTR != 0 OR 4*cr0+so == 0)

    #####################################################
    ###### Branch Decrement and branch to LR if CTR == 0 ######
    #####################################################

    '4E400020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdzlr

    '4E400021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x00000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        }
    ], # bdzlrl

    #######################################################################
    ###### Branch Decrement and branch to LR if CTR == 0 OR CONDITION TRUE ######
    #######################################################################

    ###### Branch Decrement and branch to LR if CTR == 0 OR LT ######
    '4D400020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzltlr (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    '4D400021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzltlrl (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    ###### Branch Decrement and branch to LR if CTR == 0 OR GT ######

    '4D410020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzgtlr (branch LR if --CTR == 0 OR 4*cr0+gt == 1)

    '4D410021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgtlrl (branch LR if --CTR == 0 OR 4*cr0+gt == 1)

    ###### Branch Decrement and branch to LR if CTR == 0 OR EQ ######

    '4D420020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzeqlr (branch LR if --CTR == 0 OR 4*cr0+eq == 1)

    '4D420021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzeqlrl (branch LR if --CTR == 0 OR 4*cr0+eq == 1)

    ###### Branch Decrement and branch to LR if CTR == 0 OR SO ######

    '4D430020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzsolr (branch LR if --CTR == 0 OR 4*cr0+so == 1)

    '4D430021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzsolrl (branch LR if --CTR == 0 OR 4*cr0+so == 1)

    ########################################################################
    ###### Branch Decrement and branch to LR if CTR == 0 OR CONDITION FALSE ######
    ########################################################################

    ###### Branch Decrement and branch to LR if CTR == 0 OR GE ######

    '4C400020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzgelr (branch LR if --CTR == 0 OR 4*cr0+lt == 0)

    '4C400021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzgelrl (branch LR if --CTR == 0 OR 4*cr0+lt == 0)

    ###### Branch Decrement and branch to LR if CTR == 0 OR LE ######

    '4C410020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdzlelr (branch LR if --CTR == 0 OR 4*cr0+gt == 0)

    '4C410021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdzlelrl (branch LR if --CTR == 0 OR 4*cr0+gt == 0)

    ###### Branch Decrement and branch to LR if CTR == 0 OR NE ######

    '4C420020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdznelr (branch LR if --CTR == 0 OR 4*cr0+eq == 0)

    '4C420021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznelrl (branch LR if --CTR == 0 OR 4*cr0+eq == 0)

    ###### Branch Decrement and branch to LR if CTR == 0 OR NS ######

    '4C430020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bdznslr (branch LR if --CTR == 0 OR 4*cr0+so == 0)

    '4C430021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bdznslrl LR (branch LR if --CTR == 0 OR 4*cr0+so == 0)

    ######################################################################
    ###### Branch Conditional (unsimplified, non-standard BO hints) ######
    ######################################################################

    '40A00060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bc 0x5,lt,0x400045c0 (branch LR if 4*cr0+lt == 0)

    '40A00062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bca 0x5,lt,0x60 (branch LR if 4*cr0+lt == 0)

    '40A00061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bcl 0x5,lt,0x400045c0 (branch LR if 4*cr0+lt == 0)

    '40A00063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bcla 0x5,lt,0x60 (branch LR if 4*cr0+lt == 0)

    ############################################################
    ###### Branch Conditional (simplified) CONDITION TRUE ######
    ############################################################

    ###### Branch if LT ######

    '41800060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # blt +0x60 (branch +0x60 if 4*cr0+lt == 1)

    '41800061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bltl +0x60 (branch +0x60 if 4*cr0+lt == 1)

    '41800062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # blta 0x000000060 (branch 0x60 if 4*cr0+lt == 1)

    '41800063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bltla 0x000000060 (branch 0x60 if 4*cr0+lt == 1)

    ###### Branch if GT ######

    '41810060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bgt +0x60 (branch +0x60 if 4*cr0+gt == 1)

    '41810061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgtl +0x60 (branch +0x60 if 4*cr0+gt == 1)

    '41810062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bgta 0x000000060 (branch 0x60 if 4*cr0+gt == 1)

    '41810063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgtla 0x000000060 (branch 0x60 if 4*cr0+gt == 1)

    ###### Branch if EQ ######

    '41820060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # beq +0x60 (branch +0x60 if 4*cr0+eq == 1)

    '41820061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # beql +0x60 (branch +0x60 if 4*cr0+eq == 1)

    '41820062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # beqa 0x000000060 (branch 0x60 if 4*cr0+eq == 1)

    '41820063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # beqla 0x000000060 (branch 0x60 if 4*cr0+eq == 1)

    ###### Branch if SO ######

    '41830060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bso +0x60 (branch +0x60 if 4*cr0+so == 1)

    '41830061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bsol +0x60 (branch +0x60 if 4*cr0+so == 1)

    '41830062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bsoa 0x000000060 (branch 0x60 if 4*cr0+so == 1)

    '41830063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bsola 0x000000060 (branch 0x60 if 4*cr0+so == 1)

    ############################################################
    ###### Branch Conditional (simplified) CONDITION FALSE ######
    ############################################################

    ###### Branch if GE ######

    '40800060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bge +0x60 (branch +0x60 if 4*cr0+lt == 0)

    '40800061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgel +0x60 (branch +0x60 if 4*cr0+lt == 0)

    '40800062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bgea 0x000000060 (branch 0x60 if 4*cr0+lt == 0)

    '40800063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgela 0x000000060 (branch 0x60 if 4*cr0+lt == 0)

    ###### Branch if LE ######

    '40810060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # ble +0x60 (branch +0x60 if 4*cr0+gt == 0)

    '40810061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # blel +0x60 (branch +0x60 if 4*cr0+gt == 0)

    '40810062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # blea 0x000000060 (branch 0x60 if 4*cr0+gt == 0)

    '40810063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # blela 0x000000060 (branch 0x60 if 4*cr0+gt == 0)

    ###### Branch if NE ######

    '40820060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bne +0x60 (branch +0x60 if 4*cr0+eq == 0)

    '40820061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnel +0x60 (branch +0x60 if 4*cr0+eq == 0)

    '40820062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bnea 0x000000060 (branch 0x60 if 4*cr0+eq == 0)

    '40820063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnela 0x000000060 (branch 0x60 if 4*cr0+eq == 0)

    ###### Branch if NS ######

    '40830060': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bns +0x60 (branch +0x60 if 4*cr0+so == 0)

    '40830061': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x400045c0 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnsl +0x60 (branch +0x60 if 4*cr0+so == 0)

    '40830062': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bnsa 0x000000060 (branch 0x60 if 4*cr0+so == 0)

    '40830063': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x00000060 ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnsla 0x000000060 (branch 0x60 if 4*cr0+so == 0)

    #############################################################################
    ###### Branch Conditional to CTR (unsimplified, non-standard BO hints) ######
    #############################################################################

    '4DA00420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
                ('CTR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
                ('CTR', 0xAAAAAAAA ),
            ),
        },
    ], # bcctr 0xD,lt,0x0 (branch CTR if 4*cr0+lt == 1)

    '4DA00421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0xAAAAAAAA ),
            ),
        },
    ], # bcctrl 0xD,lt,0x0 (branch CTR if 4*cr0+lt == 1)

    ###################################################################
    ###### Branch Conditional (simplified) to CTR CONDITION TRUE ######
    ###################################################################

    ###### Branch CTR if LT ######

    '4D800420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bltctr (branch CTR if 4*cr0+lt == 1)

    '4D800421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bltctrl (branch CTR if 4*cr0+lt == 1)

    ###### Branch CTR if GT ######

    '4D810420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bgtctr (branch CTR if 4*cr0+lt == 1)

    '4D810421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgtctrl (branch CTR if 4*cr0+lt == 1)

    ###### Branch CTR if EQ ######

    '4D820420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # beqctr (branch CTR if 4*cr0+eq == 1)

    '4D820421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # beqctrl (branch CTR if 4*cr0+eq == 1)

    ###### Branch CTR if SO ######

    '4D830420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bsoctr (branch CTR if 4*cr0+so == 1)

    '4D830421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bsoctrl (branch CTR if 4*cr0+so == 1)

    ####################################################################
    ###### Branch Conditional (simplified) to CTR CONDITION FALSE ######
    ####################################################################

    ###### Branch CTR if GE ######

    '4C800420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bgectr (branch CTR if 4*cr0+lt == 0)

    '4C800421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x80000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgectrl (branch CTR if 4*cr0+lt == 0)

    ###### Branch CTR if GT ######

    '4C810420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # blectr (branch CTR if 4*cr0+gt == 0)

    '4C810421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x40000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xBFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # blectrl (branch CTR if 4*cr0+gt == 0)

    ###### Branch CTR if NE ######

    '4C820420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bnectr (branch CTR if 4*cr0+eq == 0)

    '4C820421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x20000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xDFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnectrl (branch CTR if 4*cr0+eq == 0)

    ###### Branch CTR if NS ######

    '4C830420': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x12345678 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x12345678 ),
            ),
        }
    ], # bnsctr (branch CTR if 4*cr0+so == 0)

    '4C830421': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0x10000000 ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0x12345678 ),
                ('CR', 0xEFFFFFFF ),
                ('CTR', 0xAAAAAAAA ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnsctrl (branch CTR if 4*cr0+so == 0)

    ############################################################################
    ###### Branch Conditional to LR (unsimplified, non-standard BO hints) ######
    ############################################################################

    '4D600020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
                ('CTR', 0x00000001 ),
            ),
        }
    ], # bclr 0xB,lt,0x0 (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    '4D600021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
                ('CTR', 0xFFFFFFFFFFFFFFFF ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
                ('CTR', 0x00000001 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000000 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
                ('CTR', 0x00000002 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
                ('CTR', 0x00000001 ),
            ),
        },
    ], # bclrl 0xB,lt,0x0 (branch LR if --CTR == 0 OR 4*cr0+lt == 1)

    ##################################################################
    ###### Branch Conditional (simplified) to LR CONDITION TRUE ######
    ##################################################################

    ###### Branch LR if LT ######

    '4D800020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bltlr (branch LR if 4*cr0+lt == 1)

    '4D800021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bltlrl (branch LR if 4*cr0+lt == 1)

    ###### Branch LR if GT ######

    '4D810020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bgtlr (branch LR if 4*cr0+lt == 1)

    '4D810021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgtlrl (branch LR if 4*cr0+lt == 1)

    ###### Branch LR if EQ ######

    '4D820020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # beqlr (branch LR if 4*cr0+eq == 1)

    '4D820021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # beqlrl (branch LR if 4*cr0+eq == 1)

    ###### Branch LR if SO ######

    '4D830020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bsolr (branch LR if 4*cr0+so == 1)

    '4D830021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bsolrl (branch LR if 4*cr0+so == 1)

    ###################################################################
    ###### Branch Conditional (simplified) to LR CONDITION FALSE ######
    ###################################################################

    ###### Branch LR if GE ######

    '4C800020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bgelr (branch LR if 4*cr0+lt == 0)

    '4C800021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x80000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x7FFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bgelrl (branch LR if 4*cr0+lt == 0)

    ###### Branch LR if GT ######

    '4C810020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # blelr (branch LR if 4*cr0+gt == 0)

    '4C810021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x40000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xBFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # blelrl (branch LR if 4*cr0+gt == 0)

    ###### Branch LR if NE ######

    '4C820020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bnelr (branch LR if 4*cr0+eq == 0)

    '4C820021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x20000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xDFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnelrl (branch LR if 4*cr0+eq == 0)

    ###### Branch LR if NS ######

    '4C830020': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0xAAAAAAAA ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0xAAAAAAAA ),
            ),
        }
    ], # bnslr (branch LR if 4*cr0+so == 0)

    '4C830021': [
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0x10000000 ),
            ),
            'tests': (
                ('PC', 0x40004564 ),
                ('LR', 0x40004564 ),
            ),
        },
        {
            'setup': (
                ('PC', 0x40004560 ),
                ('LR', 0xAAAAAAAA ),
                ('CR', 0xEFFFFFFF ),
            ),
            'tests': (
                ('PC', 0xAAAAAAAA ),
                ('LR', 0x40004564 ),
            ),
        }
    ], # bnslrl (branch LR if 4*cr0+so == 0)

    # For the following load tests:
    # - r0 is the destination, which we initialize to 0
    # - r1 is the base address of the bytes that get written to r0
    'A8010400': [ # lha r0,0x400(r1) - load half word algebraic
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
                ('r1', 0x10000000)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011), # sign-extended with 0
                ('r1', 0x10000000)
            )
        }
    ],

    'A8000400': [ # lha r0,0x400(0) - load half word algebraic (with rA = 0)
        {
            'setup': (
                ('r0', 0),
                (0x400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
            )
        },

        {
            'setup': (
                ('r0', 0),
                (0x400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011), # sign-extended with 0
            )
        }
    ],

    # Note that rA = 0 is an invalid form for loads with updates, so we don't test it
    'AC010400': [ # lhau r0,0x400(r1) - load half word algebraic with update
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011), # sign-extended with 0
                ('r1', 0x10000400)
            )
        }
    ],

    '7C0112AE': [ # lhax r0,r1,r2 - load half word algebraic indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
                ('r1', 0x10000000)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011), # sign-extended with 0
                ('r1', 0x10000000)
            )
        }
    ],

    '7C0112AA': [ # lwax r0,r1,r2 - load word algebraic indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8C627311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFF8C627311), # sign-extended with 1
                ('r1', 0x10000000)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('7D9A4011'))
            ),
            'tests': (
                ('r0', 0x7D9A4011), # sign-extended with 0
                ('r1', 0x10000000)
            )
        }
    ],

    '7C0112EE': [ # lhaux r0,r1,r2 - load half word algebraic with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011), # sign-extended with 0
                ('r1', 0x10000400)
            )
        }
    ],

    '7C0112EA': [ # lwaux r0,r1,r2 - load word algebraic with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8C627311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFF8C627311), # sign-extended with 1
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('7D9A4011'))
            ),
            'tests': (
                ('r0', 0x7D9A4011), # sign-extended with 0
                ('r1', 0x10000400)
            )
        }
    ],

    'A4010400': [ # lhzu r0,0x400(r1) - load half word and zero with update
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0x8311),
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011),
                ('r1', 0x10000400)
            )
        }
    ],

    '84010400': [ # lwzu r0,0x400(r1) - load word and zero with update
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('8C627311'))
            ),
            'tests': (
                ('r0', 0x8C627311),
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('7D9A4011'))
            ),
            'tests': (
                ('r0', 0x7D9A4011),
                ('r1', 0x10000400)
            )
        }
    ],

    'E8010401': [ # ldu r0,0x400(r1) - load doubleword with update
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('AB9371D0FEDCBA98'))
            ),
            'tests': (
                ('r0', 0xAB9371D0FEDCBA98),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C01122E': [ # lhzx r0,r1,r2 - load half word and zero indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0x8311),
                ('r1', 0x10000000)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011),
                ('r1', 0x10000000)
            )
        }
    ],

    '7C01102E': [ # lwzx r0,r1,r2 - load word and zero indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8C627311'))
            ),
            'tests': (
                ('r0', 0x8C627311),
                ('r1', 0x10000000)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('7D9A4011'))
            ),
            'tests': (
                ('r0', 0x7D9A4011),
                ('r1', 0x10000000)
            )
        }
    ],

    '7C01102A': [ # ldx r0,r1,r2 - load doubleword indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('AB9371D0FEDCBA98'))
            ),
            'tests': (
                ('r0', 0xAB9371D0FEDCBA98),
                ('r1', 0x10000000)
            )
        },
    ],

    '7C0110EE': [ # lbzux r0,r1,r2 - load byte and zero with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('FB'))
            ),
            'tests': (
                ('r0', 0xFB),
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('4C'))
            ),
            'tests': (
                ('r0', 0x4C),
                ('r1', 0x10000400)
            )
        }
    ],

    '7C01126E': [ # lhzux r0,r1,r2 - load half word and zero with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0x8311),
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('4011'))
            ),
            'tests': (
                ('r0', 0x4011),
                ('r1', 0x10000400)
            )
        }
    ],

    '7C01106E': [ # lwzux r0,r1,r2 - load word and zero with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('8C627311'))
            ),
            'tests': (
                ('r0', 0x8C627311),
                ('r1', 0x10000400)
            )
        },

        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('7D9A4011'))
            ),
            'tests': (
                ('r0', 0x7D9A4011),
                ('r1', 0x10000400)
            )
        }
    ],

    '7C01106A': [ # ldux r0,r1,r2 - load doubleword with update indexed
        {
            'setup': (
                ('r0', 0),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('AB9371D0FEDCBA98'))
            ),
            'tests': (
                ('r0', 0xAB9371D0FEDCBA98),
                ('r1', 0x10000400)
            )
        },
    ],

    '9C010400': [ # stbu r0,0x400(r1) - store byte with update
        {
            'setup': (
                ('r0', 0xAB),
                ('r1', 0x10000000),
                (0x10000400, b"\x00")
            ),
            'tests': (
                (0x10000400, b"\xAB"),
                ('r1', 0x10000400)
            )
        },
    ],

    'B4010400': [ # sthu r0,0x400(r1) - store half word with update
        {
            'setup': (
                ('r0', 0xABDF),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('0000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF')),
                ('r1', 0x10000400)
            )
        },
    ],

    '94010400': [ # stwu r0,0x400(r1) - store word with update
        {
            'setup': (
                ('r0', 0xABDF1539),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('00000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF1539')),
                ('r1', 0x10000400)
            )
        },
    ],

    'F8010401': [ # stdu r0,0x400(r1) - store doubleword with update
        {
            'setup': (
                ('r0', 0xABDF153977820C0B),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('0000000000000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF153977820C0B')),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C0111AE': [ # stbx r0,r1,r2 - store byte indexed
        {
            'setup': (
                ('r0', 0xAB),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, b"\x00")
            ),
            'tests': (
                (0x10000400, b"\xAB"),
                ('r1', 0x10000000)
            )
        },
    ],

    '7C01132E': [ # sthx r0,r1,r2 - store half word indexed
        {
            'setup': (
                ('r0', 0xABDF),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('0000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF')),
                ('r1', 0x10000000)
            )
        },
    ],

    '7C01112E': [ # stwx r0,r1,r2 - store word indexed
        {
            'setup': (
                ('r0', 0xABDF1539),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('00000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF1539')),
                ('r1', 0x10000000)
            )
        },
    ],

    '7C01112A': [ # stdx r0,r1,r2 - store doubleword indexed
        {
            'setup': (
                ('r0', 0xABDF153977820C0B),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('0000000000000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF153977820C0B')),
                ('r1', 0x10000000)
            )
        },
    ],

    '7C0111EE': [ # stbux r0,r1,r2 - store byte with update indexed
        {
            'setup': (
                ('r0', 0xAB),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, b"\x00")
            ),
            'tests': (
                (0x10000400, b"\xAB"),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C01136E': [ # sthux r0,r1,r2 - store half word with update indexed
        {
            'setup': (
                ('r0', 0xABDF),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('0000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF')),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C01116E': [ # stwux r0,r1,r2 - store word with update indexed
        {
            'setup': (
                ('r0', 0xABDF1539),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('00000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF1539')),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C01116A': [ # stdux r0,r1,r2 - store doubleword with update indexed
        {
            'setup': (
                ('r0', 0xABDF153977820C0B),
                ('r1', 0x10000000),
                ('r2', 0x400),
                (0x10000400, bytes.fromhex('0000000000000000'))
            ),
            'tests': (
                (0x10000400, bytes.fromhex('ABDF153977820C0B')),
                ('r1', 0x10000400)
            )
        },
    ],

    # These check the case where rD == rB
    '7C0100EE': [ # lbzux r0,r1,r0 - load byte and zero with update indexed
        {
            'setup': (
                ('r0', 0x400),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('FB'))
            ),
            'tests': (
                ('r0', 0xFB),
                ('r1', 0x10000400)
            )
        },
    ],

    '7C0102EE': [ # lhaux r0,r1,r0 - load half word algebraic with update indexed
        {
            'setup': (
                ('r0', 0x400),
                ('r1', 0x10000000),
                (0x10000400, bytes.fromhex('8311'))
            ),
            'tests': (
                ('r0', 0xFFFFFFFFFFFF8311), # sign-extended with 1
                ('r1', 0x10000400)
            )
        },
    ],
}

GOOD_EMU_TESTS = 920
