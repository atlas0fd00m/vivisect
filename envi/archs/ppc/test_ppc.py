
import sys
import struct
import envi.archs.ppc.disasm as eapd

for cat in eapd.CATEGORIES.keys():
    d = eapd.PpcDisasm(options=cat)
    out = []
    print "\n====== CAT: %r ======" % eapd.CATEGORIES.get(cat)
    for key,instrlist in eapd.instr_dict.items():
        for instrline in instrlist:
            opcodenum = instrline[1]
            opcat = instrline[2][3]
            if not opcat & cat:
                continue

            shifters = [(shl, mask) for nm,tp,shl,mask in instrline[2][-2]]
            shifters.sort()
            for oidx in range(len(shifters)):
                shl, mask = shifters[oidx]
                opcodenum |= (((len(shifters)-oidx) & mask) << shl)
            opbin = struct.pack(">I", opcodenum)
            try:
                op = d.disasm(opbin, 0, 0x4000)
                print "0x%.8x:  %s" % (opcodenum, op)
            except Exception, e:
                sys.stderr.write("ERROR: 0x%x: %r\n" % (opcodenum, e))
            out.append(opbin)
file("test_ppc.bin", "wb").write("".join(out))
