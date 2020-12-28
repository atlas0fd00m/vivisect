FIELD_BD = 0
FIELD_BH = 1
FIELD_BI = 2
FIELD_BO = 3
FIELD_CRM = 4
FIELD_CT = 5
FIELD_D = 6
FIELD_DCRN0_4 = 7
FIELD_DCRN5_9 = 8
FIELD_DCTL = 9
FIELD_DE = 10
FIELD_DS = 11
FIELD_DUI = 12
FIELD_E = 13
FIELD_FM = 14
FIELD_IU = 15
FIELD_LEV = 16
FIELD_LI = 17
FIELD_MB = 18
FIELD_ME = 19
FIELD_MO = 20
FIELD_OC = 21
FIELD_OU = 22
FIELD_PMRN0_4 = 23
FIELD_PMRN5_9 = 24
FIELD_SA = 25
FIELD_SIMM16 = 26
FIELD_SIMM5 = 27
FIELD_SPRN0_4 = 28
FIELD_SPRN5_9 = 29
FIELD_SS = 30
FIELD_STRM = 31
FIELD_T = 32
FIELD_TBRN0_4 = 33
FIELD_TBRN5_9 = 34
FIELD_TH = 35
FIELD_TMRN0_4 = 36
FIELD_TMRN5_9 = 37
FIELD_TO = 38
FIELD_W = 39
FIELD_WC = 40
FIELD_WH = 41
FIELD_crD = 42
FIELD_crb = 43
FIELD_crbA = 44
FIELD_crbB = 45
FIELD_crbC = 46
FIELD_crbD = 47
FIELD_crfD = 48
FIELD_frA = 49
FIELD_frB = 50
FIELD_frC = 51
FIELD_frD = 52
FIELD_frS = 53
FIELD_mb0 = 54
FIELD_mb1_5 = 55
FIELD_me0 = 56
FIELD_me1_5 = 57
FIELD_rA = 58
FIELD_rB = 59
FIELD_rC = 60
FIELD_rD = 61
FIELD_rS = 62
FIELD_sh0 = 63
FIELD_sh1_5 = 64
FIELD_vA = 65
FIELD_vB = 66
FIELD_vC = 67
FIELD_vD = 68
FIELD_vS = 69
FIELD_IMM = 70
FIELD_L = 71
FIELD_SH = 72
FIELD_SIMM = 73
FIELD_UIMM = 74
FIELD_UIMM1 = 75
FIELD_UIMM2 = 76
FIELD_UIMM3 = 77
FIELD_crfS = 78

CAT_NONE = 1<<0
CAT_64 = 1<<1
CAT_E = 1<<2
CAT_V = 1<<3
CAT_SP = 1<<4
CAT_SP_FV = 1<<5
CAT_SP_FS = 1<<6
CAT_SP_FD = 1<<7
CAT_EMBEDDED = 1<<8
CAT_E_ED = 1<<9
CAT_E_HV = 1<<10
CAT_E_PD = 1<<11
CAT_ER = 1<<12
CAT_WT = 1<<13
CAT_E_CL = 1<<14
CAT_E_PC = 1<<15
CAT_ISAT = 1<<16
CAT_E_DC = 1<<17
CAT_E_PM = 1<<18
CAT_EM_TM = 1<<19
CAT_DS = 1<<20
CAT_FP = 1<<21
CAT_DEO = 1<<22
CAT_FP_R = 1<<23

CATEGORIES = { y : x  for x,y in globals().items() if x.startswith("CAT_")}

FORM_A = 0
FORM_B = 1
FORM_D = 2
FORM_DS = 3
FORM_EVX = 4
FORM_I = 5
FORM_M = 6
FORM_MD = 7
FORM_MDS = 8
FORM_SC = 9
FORM_VA = 10
FORM_VC = 11
FORM_VX = 12
FORM_X = 13
FORM_XFX = 14
FORM_XL = 15
FORM_XO = 16
FORM_XS = 17
FORM_X_2 = 18

form_names = {
    0 : 'FORM_A',
    1 : 'FORM_B',
    2 : 'FORM_D',
    3 : 'FORM_DS',
    4 : 'FORM_EVX',
    5 : 'FORM_I',
    6 : 'FORM_M',
    7 : 'FORM_MD',
    8 : 'FORM_MDS',
    9 : 'FORM_SC',
    10 : 'FORM_VA',
    11 : 'FORM_VC',
    12 : 'FORM_VX',
    13 : 'FORM_X',
    14 : 'FORM_XFX',
    15 : 'FORM_XL',
    16 : 'FORM_XO',
    17 : 'FORM_XS',
    18 : 'FORM_X_2',
}

mnems = (
    'tdi',
    'twi',
    'vaddubm',
    'vmaxub',
    'vrlb',
    'vcmpequb',
    'vmuloub',
    'vaddfp',
    'vmrghb',
    'vpkuhum',
    'vmhaddshs',
    'vmhraddshs',
    'vmladduhm',
    'vmsumubm',
    'vmsummbm',
    'vmsumuhm',
    'vmsumuhs',
    'vmsumshm',
    'vmsumshs',
    'vsel',
    'vperm',
    'vsldoi',
    'vmaddfp',
    'vnmsubfp',
    'vadduhm',
    'vmaxuh',
    'vrlh',
    'vcmpequh',
    'vmulouh',
    'vsubfp',
    'vmrghh',
    'vpkuwum',
    'vadduwm',
    'vmaxuw',
    'vrlw',
    'vcmpequw',
    'vmrghw',
    'vpkuhus',
    'vcmpeqfp',
    'vpkuwus',
    'vmaxsb',
    'vslb',
    'vmulosb',
    'vrefp',
    'vmrglb',
    'vpkshus',
    'vmaxsh',
    'vslh',
    'vmulosh',
    'vrsqrtefp',
    'vmrglh',
    'vpkswus',
    'vaddcuw',
    'vmaxsw',
    'vslw',
    'vexptefp',
    'vmrglw',
    'vpkshss',
    'vsl',
    'vcmpgefp',
    'vlogefp',
    'vpkswss',
    'evaddw',
    'vaddubs',
    'evaddiw',
    'vminub',
    'evsubfw',
    'vsrb',
    'evsubifw',
    'vcmpgtub',
    'evabs',
    'vmuleub',
    'evneg',
    'evextsb',
    'vrfin',
    'evextsh',
    'evrndw',
    'vspltb',
    'evcntlzw',
    'evcntlsw',
    'vupkhsb',
    'brinc',
    'evand',
    'evandc',
    'evxor',
    'evor',
    'evnor',
    'eveqv',
    'evorc',
    'evnand',
    'evsrwu',
    'evsrws',
    'evsrwiu',
    'evsrwis',
    'evslw',
    'evslwi',
    'evrlw',
    'evsplati',
    'evrlwi',
    'evsplatfi',
    'evmergehi',
    'evmergelo',
    'evmergehilo',
    'evmergelohi',
    'evcmpgtu',
    'evcmpgts',
    'evcmpltu',
    'evcmplts',
    'evcmpeq',
    'vadduhs',
    'vminuh',
    'vsrh',
    'vcmpgtuh',
    'vmuleuh',
    'vrfiz',
    'vsplth',
    'vupkhsh',
    'evsel',
    'evfsadd',
    'vadduws',
    'evfssub',
    'vminuw',
    'evfsabs',
    'vsrw',
    'evfsnabs',
    'evfsneg',
    'vcmpgtuw',
    'evfsmul',
    'evfsdiv',
    'vrfip',
    'evfscmpgt',
    'vspltw',
    'evfscmplt',
    'evfscmpeq',
    'vupklsb',
    'evfscfui',
    'evfscfsi',
    'evfscfuf',
    'evfscfsf',
    'evfsctui',
    'evfsctsi',
    'evfsctuf',
    'evfsctsf',
    'evfsctuiz',
    'evfsctsiz',
    'evfststgt',
    'evfststlt',
    'evfststeq',
    'efsadd',
    'efssub',
    'efsabs',
    'vsr',
    'efsnabs',
    'efsneg',
    'vcmpgtfp',
    'efsmul',
    'efsdiv',
    'vrfim',
    'efscmpgt',
    'efscmplt',
    'efscmpeq',
    'vupklsh',
    'efscfd',
    'efscfui',
    'efscfsi',
    'efscfuf',
    'efscfsf',
    'efsctui',
    'efsctsi',
    'efsctuf',
    'efsctsf',
    'efsctuiz',
    'efsctsiz',
    'efststgt',
    'efststlt',
    'efststeq',
    'efdadd',
    'efdsub',
    'efdabs',
    'efdnabs',
    'efdneg',
    'efdmul',
    'efddiv',
    'efdcmpgt',
    'efdcmplt',
    'efdcmpeq',
    'efdcfs',
    'efdcfui',
    'efdcfsi',
    'efdcfuf',
    'efdcfsf',
    'efdctui',
    'efdctsi',
    'efdctuf',
    'efdctsf',
    'efdctuiz',
    'efdctsiz',
    'efdtstgt',
    'efdtstlt',
    'efdtsteq',
    'evlddx',
    'vaddsbs',
    'evldd',
    'evldwx',
    'vminsb',
    'evldw',
    'evldhx',
    'vsrab',
    'evldh',
    'vcmpgtsb',
    'evlhhesplatx',
    'vmulesb',
    'evlhhesplat',
    'vcfux',
    'evlhhousplatx',
    'vspltisb',
    'evlhhousplat',
    'evlhhossplatx',
    'vpkpx',
    'evlhhossplat',
    'evlwhex',
    'evlwhe',
    'evlwhoux',
    'evlwhou',
    'evlwhosx',
    'evlwhos',
    'evlwwsplatx',
    'evlwwsplat',
    'evlwhsplatx',
    'evlwhsplat',
    'evstddx',
    'evstdd',
    'evstdwx',
    'evstdw',
    'evstdhx',
    'evstdh',
    'evstwhex',
    'evstwhe',
    'evstwhox',
    'evstwho',
    'evstwwex',
    'evstwwe',
    'evstwwox',
    'evstwwo',
    'vaddshs',
    'vminsh',
    'vsrah',
    'vcmpgtsh',
    'vmulesh',
    'vcfsx',
    'vspltish',
    'vupkhpx',
    'vaddsws',
    'vminsw',
    'vsraw',
    'vcmpgtsw',
    'vctuxs',
    'vspltisw',
    'vcmpbfp',
    'vctsxs',
    'vupklpx',
    'vsububm',
    'vavgub',
    'evmhessf',
    'vabsdub',
    'vand',
    'evmhossf',
    'evmheumi',
    'evmhesmi',
    'vmaxfp',
    'evmhesmf',
    'evmhoumi',
    'vslo',
    'evmhosmi',
    'evmhosmf',
    'evmhessfa',
    'evmhossfa',
    'evmheumia',
    'evmhesmia',
    'evmhesmfa',
    'evmhoumia',
    'evmhosmia',
    'evmhosmfa',
    'vsubuhm',
    'vavguh',
    'vabsduh',
    'vandc',
    'evmwhssf',
    'evmwlumi',
    'vminfp',
    'evmwhumi',
    'vsro',
    'evmwhsmi',
    'evmwhsmf',
    'evmwssf',
    'evmwumi',
    'evmwsmi',
    'evmwsmf',
    'evmwhssfa',
    'evmwlumia',
    'evmwhumia',
    'evmwhsmia',
    'evmwhsmfa',
    'evmwssfa',
    'evmwumia',
    'evmwsmia',
    'evmwsmfa',
    'vsubuwm',
    'vavguw',
    'vabsduw',
    'vor',
    'evaddusiaaw',
    'evaddssiaaw',
    'evsubfusiaaw',
    'evsubfssiaaw',
    'evmra',
    'vxor',
    'evdivws',
    'evdivwu',
    'evaddumiaaw',
    'evaddsmiaaw',
    'evsubfumiaaw',
    'evsubfsmiaaw',
    'evmheusiaaw',
    'evmhessiaaw',
    'vavgsb',
    'evmhessfaaw',
    'evmhousiaaw',
    'vnor',
    'evmhossiaaw',
    'evmhossfaaw',
    'evmheumiaaw',
    'evmhesmiaaw',
    'evmhesmfaaw',
    'evmhoumiaaw',
    'evmhosmiaaw',
    'evmhosmfaaw',
    'evmhegumiaa',
    'evmhegsmiaa',
    'evmhegsmfaa',
    'evmhogumiaa',
    'evmhogsmiaa',
    'evmhogsmfaa',
    'evmwlusiaaw',
    'evmwlssiaaw',
    'vavgsh',
    'evmwhssmaaw',
    'evmwlumiaaw',
    'evmwlsmiaaw',
    'evmwssfaa',
    'evmwumiaa',
    'evmwsmiaa',
    'evmwsmfaa',
    'evmheusianw',
    'vsubcuw',
    'evmhessianw',
    'vavgsw',
    'evmhessfanw',
    'evmhousianw',
    'evmhossianw',
    'evmhossfanw',
    'evmheumianw',
    'evmhesmianw',
    'evmhesmfanw',
    'evmhoumianw',
    'evmhosmianw',
    'evmhosmfanw',
    'evmhegumian',
    'evmhegsmian',
    'evmhegsmfan',
    'evmhogumian',
    'evmhogsmian',
    'evmhogsmfan',
    'evmwlusianw',
    'evmwlssianw',
    'evmwlumianw',
    'evmwlsmianw',
    'evmwssfan',
    'evmwumian',
    'evmwsmian',
    'evmwsmfan',
    'vsububs',
    'mfvscr',
    'vsum4ubs',
    'vsubuhs',
    'mtvscr',
    'vsum4shs',
    'vsubuws',
    'vsum2sws',
    'vsubsbs',
    'vsum4sbs',
    'vsubshs',
    'vsubsws',
    'vsumsws',
    'mulli',
    'subfic',
    'cmpli',
    'cmpi',
    'addic',
    'addi',
    'addis',
    'bc',
    'bcl',
    'bca',
    'bcla',
    'sc',
    'b',
    'bl',
    'ba',
    'bla',
    'mcrf',
    'bclr',
    'bclrl',
    'crnor',
    'rfmci',
    'rfdi',
    'rfi',
    'rfci',
    'rfgi',
    'crandc',
    'isync',
    'crxor',
    'dnh',
    'crnand',
    'crand',
    'creqv',
    'crorc',
    'cror',
    'bcctr',
    'bcctrl',
    'rlwimi',
    'rlwinm',
    'rlwnm',
    'ori',
    'oris',
    'xori',
    'xoris',
    'andi',
    'andis',
    'rldicl',
    'rldicr',
    'rldic',
    'rldimi',
    'rldcl',
    'rldcr',
    'cmp',
    'tw',
    'lvsl',
    'lvebx',
    'subfc',
    'mulhdu',
    'addc',
    'mulhwu',
    'isel',
    'tlbilx',
    'mfcr',
    'mfocrf',
    'lwarx',
    'ldx',
    'icbt',
    'lwzx',
    'slw',
    'cntlzw',
    'sld',
    'and',
    'ldepx',
    'lwepx',
    'cmpl',
    'lvsr',
    'lvehx',
    'subf',
    'mviwsplt',
    'lbarx',
    'ldux',
    'dcbst',
    'lwzux',
    'cntlzd',
    'andc',
    'wait',
    'dcbstep',
    'td',
    'lvewx',
    'mulhd',
    'mulhw',
    'mfmsr',
    'ldarx',
    'dcbf',
    'lbzx',
    'lbepx',
    'dni',
    'lvx',
    'neg',
    'mvidsplt',
    'lharx',
    'lbzux',
    'popcntb',
    'nor',
    'dcbfep',
    'wrtee',
    'dcbtstls',
    'stvebx',
    'subfe',
    'adde',
    'mtcrf',
    'mtocrf',
    'mtmsr',
    'stdx',
    'stwcx',
    'stwx',
    'prtyw',
    'stdepx',
    'stwepx',
    'wrteei',
    'dcbtls',
    'stvehx',
    'stdux',
    'stwux',
    'prtyd',
    'icblq',
    'stvewx',
    'subfze',
    'addze',
    'msgsnd',
    'stdcx',
    'stbx',
    'stbepx',
    'icblc',
    'stvx',
    'subfme',
    'mulld',
    'addme',
    'mullw',
    'msgclr',
    'dcbtst',
    'stbux',
    'bpermd',
    'dcbtstep',
    'lvexbx',
    'lvepxl',
    'sat',
    'add',
    'ehpriv',
    'dcbt',
    'lhzx',
    'eqv',
    'lhepx',
    'lvexhx',
    'lvepx',
    'mulhss',
    'lhzux',
    'xor',
    'dcbtep',
    'mfdcr',
    'lvexwx',
    'subfw',
    'addw',
    'mfpmr',
    'mfspr',
    'lwax',
    'dst',
    'dstt',
    'lhax',
    'lvxl',
    'subfwss',
    'addwss',
    'mulwss',
    'mftmr',
    'mftb',
    'lwaux',
    'dstst',
    'dststt',
    'lhaux',
    'popcntw',
    'stvexbx',
    'dcblc',
    'subfh',
    'addh',
    'divweu',
    'sthx',
    'orc',
    'sthepx',
    'stvexhx',
    'dcblq',
    'subfhss',
    'addhss',
    'divwe',
    'sthux',
    'miso',
    'or',
    'mtdcr',
    'stvexwx',
    'subfb',
    'divdu',
    'addb',
    'divwu',
    'mtpmr',
    'mtspr',
    'dcbi',
    'nand',
    'dsn',
    'icbtls',
    'stvxl',
    'subfbss',
    'divd',
    'addbss',
    'divw',
    'mttmr',
    'popcntd',
    'cmpb',
    'mcrxr',
    'lbdx',
    'subfco',
    'addco',
    'ldbrx',
    'lwbrx',
    'lfsx',
    'srw',
    'srd',
    'lhdx',
    'lvtrx',
    'subfo',
    'tlbsync',
    'lfsux',
    'lwdx',
    'lvtlx',
    'sync',
    'lfdx',
    'lfdepx',
    'lddx',
    'lvswx',
    'nego',
    'lfdux',
    'stbdx',
    'subfeo',
    'addeo',
    'stdbrx',
    'stwbrx',
    'stfsx',
    'sthdx',
    'stvfrx',
    'stbcx',
    'stfsux',
    'stwdx',
    'stvflx',
    'subfzeo',
    'addzeo',
    'sthcx',
    'stfdx',
    'stfdepx',
    'stddx',
    'stvswx',
    'subfmeo',
    'mulldo',
    'addmeo',
    'mullwo',
    'dcba',
    'dcbal',
    'stfdux',
    'lvsm',
    'stvepxl',
    'addo',
    'tlbivax',
    'lhbrx',
    'sraw',
    'srad',
    'evlddepx',
    'lfddx',
    'lvtrxl',
    'stvepx',
    'mulhus',
    'dss',
    'dssall',
    'srawi',
    'sradi',
    'lvtlxl',
    'subfwu',
    'addwu',
    'mbar',
    'lvswxl',
    'subfwus',
    'addwus',
    'mulwus',
    'subfhu',
    'addhu',
    'divweuo',
    'tlbsx',
    'sthbrx',
    'extsh',
    'evstddepx',
    'stfddx',
    'stvfrxl',
    'subfhus',
    'addhus',
    'divweo',
    'tlbre',
    'extsb',
    'stvflxl',
    'subfbu',
    'divduo',
    'addbu',
    'divwuo',
    'tlbwe',
    'icbi',
    'stfiwx',
    'extsw',
    'icbiep',
    'stvswxl',
    'subfbus',
    'divdo',
    'addbus',
    'divwo',
    'dcbz',
    'dcbzl',
    'dcbzep',
    'dcbzlep',
    'lwz',
    'lwzu',
    'lbz',
    'lbzu',
    'stw',
    'stwu',
    'stb',
    'stbu',
    'lhz',
    'lhzu',
    'lha',
    'lhau',
    'sth',
    'sthu',
    'lmw',
    'stmw',
    'lfs',
    'lfsu',
    'lfd',
    'lfdu',
    'stfs',
    'stfsu',
    'stfd',
    'stfdu',
    'ld',
    'ldu',
    'lwa',
    'fdivs',
    'fsubs',
    'fadds',
    'fres',
    'fmuls',
    'fmsubs',
    'fmadds',
    'fnmsubs',
    'fnmadds',
    'std',
    'stdu',
    'fcmpu',
    'frsp',
    'fctiw',
    'fctiwz',
    'fdiv',
    'fadd',
    'fsub',
    'fsel',
    'fmul',
    'frsqrte',
    'fmsub',
    'fmadd',
    'fnmsub',
    'fnmadd',
    'fcmpo',
    'mtfsb1',
    'fneg',
    'mcrfs',
    'mtfsb0',
    'fmr',
    'mtfsfi',
    'fnabs',
    'fabs',
    'mffs',
    'mtfsf',
    'fctid',
    'fctidz',
    'fcfid',
    'nop',
    'li',
    'lis',
    'la',
    'mr',
    'not',
    'mtcr',
    'lwsync',
    'hwsync',
    'msync',
    'esync',
    'isellt',
    'iselgt',
    'iseleq',
    'waitrsv',
    'cmpw',
    'cmpd',
    'cmpwi',
    'cmpdi',
    'cmplw',
    'cmpld',
    'cmplwi',
    'cmpldi',
    'bdnzf',
    'bdzf',
    'bf',
    'bdnzt',
    'bdzt',
    'bt',
    'bdnz',
    'bdz',
    'b',
    'bdnzfl',
    'bdzfl',
    'bfl',
    'bdnztl',
    'bdztl',
    'btl',
    'bdnzl',
    'bdzl',
    'bl',
    'bdnzfa',
    'bdzfa',
    'bfa',
    'bdnzta',
    'bdzta',
    'bta',
    'bdnza',
    'bdza',
    'ba',
    'bdnzfla',
    'bdzfla',
    'bfla',
    'bdnztla',
    'bdztla',
    'btla',
    'bdnzla',
    'bdzla',
    'bla',
    'bdnzflr',
    'bdzflr',
    'bflr',
    'bdnztlr',
    'bdztlr',
    'btlr',
    'bdnzlr',
    'bdzlr',
    'blr',
    'bdnzflrl',
    'bdzflrl',
    'bflrl',
    'bdnztlrl',
    'bdztlrl',
    'btlrl',
    'bdnzlrl',
    'bdzlrl',
    'blrl',
    'bdnzflra',
    'bdzflra',
    'bflra',
    'bdnztlra',
    'bdztlra',
    'btlra',
    'bdnzlra',
    'bdzlra',
    'blra',
    'bdnzflrla',
    'bdzflrla',
    'bflrla',
    'bdnztlrla',
    'bdztlrla',
    'btlrla',
    'bdnzlrla',
    'bdzlrla',
    'blrla',
    'bdnzfctr',
    'bdzfctr',
    'bfctr',
    'bdnztctr',
    'bdztctr',
    'btctr',
    'bdnzctr',
    'bdzctr',
    'bctr',
    'bdnzfctrl',
    'bdzfctrl',
    'bfctrl',
    'bdnztctrl',
    'bdztctrl',
    'btctrl',
    'bdnzctrl',
    'bdzctrl',
    'bctrl',
    'bdnzfctra',
    'bdzfctra',
    'bfctra',
    'bdnztctra',
    'bdztctra',
    'btctra',
    'bdnzctra',
    'bdzctra',
    'bctra',
    'bdnzfctrla',
    'bdzfctrla',
    'bfctrla',
    'bdnztctrla',
    'bdztctrla',
    'btctrla',
    'bdnzctrla',
    'bdzctrla',
    'bctrla',
)

inscounter = 0
for mnem in mnems:
    globals()["INS_"+mnem.upper()] = inscounter
    inscounter += 1


IF_NONE = 0
IF_RC = 1<<8
IF_ABS = 1<<9
IF_BRANCH_LIKELY = 1<<10
IF_BRANCH_UNLIKELY = 1<<11
IF_MEM_EA = 1<<12
