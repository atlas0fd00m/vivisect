sys_regs = [
    	("osdtrrx_el1", 64),
        ("dbgbvr0_el1", 64),
        ("dbgbcr0_el1", 64),
        ("dbgwvr0_el1", 64),
        ("dbgwcr0_el1", 64),
        ("dbgbvr1_el1", 64),
        ("dbgbcr1_el1", 64),
        ("dbgwvr1_el1", 64),
        ("dbgwcr1_el1", 64),
        ("mdccint_el1", 64),
        ("mdscr_el1", 64),
        ("dbgbvr2_el1", 64),
        ("dbgbcr2_el1", 64),
        ("dbgwvr2_el1", 64),
        ("dbgwcr2_el1", 64),
        ("osdtrtx_el1", 64),
        ("dbgbvr3_el1", 64),
        ("dbgbcr3_el1", 64),
        ("dbgwvr3_el1", 64),
        ("dbgwcr3_el1", 64),
        ("dbgbvr4_el1", 64),
        ("dbgbcr4_el1", 64),
        ("dbgwvr4_el1", 64),
        ("dbgwcr4_el1", 64),
        ("dbgbvr5_el1", 64),
        ("dbgbcr5_el1", 64),
        ("dbgwvr5_el1", 64),
        ("dbgwcr5_el1", 64),
        ("oseccr_el1", 64),
        ("dbgbvr6_el1", 64),
        ("dbgbcr6_el1", 64),
        ("dbgwvr6_el1", 64),
        ("dbgwcr6_el1", 64),
        ("dbgbvr7_el1", 64),
        ("dbgbcr7_el1", 64),
        ("dbgwvr7_el1", 64),
        ("dbgwcr7_el1", 64),
        ("dbgbvr8_el1", 64),
        ("dbgbcr8_el1", 64),
        ("dbgwvr8_el1", 64),
        ("dbgwcr8_el1", 64),
        ("dbgbvr9_el1", 64),
        ("dbgbcr9_el1", 64),
        ("dbgwvr9_el1", 64),
        ("dbgwcr9_el1", 64),
        ("dbgbvr10_el1", 64),
        ("dbgbcr10_el1", 64),
        ("dbgwvr10_el1", 64),
        ("dbgwcr10_el1", 64),
        ("dbgbvr11_el1", 64),
        ("dbgbcr11_el1", 64),
        ("dbgwvr11_el1", 64),
        ("dbgwcr11_el1", 64),
        ("dbgbvr12_el1", 64),
        ("dbgbcr12_el1", 64),
        ("dbgwvr12_el1", 64),
        ("dbgwcr12_el1", 64),
        ("dbgbvr13_el1", 64),
        ("dbgbcr13_el1", 64),
        ("dbgwvr13_el1", 64),
        ("dbgwcr13_el1", 64),
        ("dbgbvr14_el1", 64),
        ("dbgbcr14_el1", 64),
        ("dbgwvr14_el1", 64),
        ("dbgwcr14_el1", 64),
        ("dbgbvr15_el1", 64),
        ("dbgbcr15_el1", 64),
        ("dbgwvr15_el1", 64),
        ("dbgwcr15_el1", 64),
        ("oslar_el1", 64),
        ("osdlr_el1", 64),
        ("dbgprcr_el1", 64),
        ("dbgclaimset_el1", 64),
        ("dbgclaimclr_el1", 64),
        ("trctraceidr", 64),
        ("trcvictlr", 64),
        ("trcseqevr0", 64),
        ("trccntrldvr0", 64),
        ("trcimspec0", 64),
        ("trcprgctlr", 64),
        ("trcqctlr", 64),
        ("trcviiectlr", 64),
        ("trcseqevr1", 64),
        ("trccntrldvr1", 64),
        ("trcimspec1", 64),
        ("trcprocselr", 64),
        ("trcvissctlr", 64),
        ("trcseqevr2", 64),
        ("trccntrldvr2", 64),
        ("trcimspec2", 64),
        ("trcvipcssctlr", 64),
        ("trccntrldvr3", 64),
        ("trcimspec3", 64),
        ("trcconfigr", 64),
        ("trccntctlr0", 64),
        ("trcimspec4", 64),
        ("trccntctlr1", 64),
        ("trcimspec5", 64),
        ("trcauxctlr", 64),
        ("trcseqrstevr", 64),
        ("trccntctlr2", 64),
        ("trcimspec6", 64),
        ("trcseqstr", 64),
        ("trccntctlr3", 64),
        ("trcimspec7", 64),
        ("trceventctl0r", 64),
        ("trcvdctlr", 64),
        ("trcextinselr", 64),
        ("trccntvr0", 64),
        ("trceventctl1r", 64),
        ("trcvdsacctlr", 64),
        ("trcextinselr1", 64),
        ("trccntvr1", 64),
        ("trcrsr", 64),
        ("trcvdarcctlr", 64),
        ("trcextinselr2", 64),
        ("trccntvr2", 64),
        ("trcstallctlr", 64),
        ("trcextinselr3", 64),
        ("trccntvr3", 64),
        ("trctsctlr", 64),
        ("trcsyncpr", 64),
        ("trcccctlr", 64),
        ("trcbbctlr", 64),
        ("trcrsctlr16", 64),
        ("trcssccr0", 64),
        ("trcsspcicr0", 64),
        ("trcoslar", 64),
        ("trcrsctlr17", 64),
        ("trcssccr1", 64),
        ("trcsspcicr1", 64),
        ("trcrsctlr2", 64),
        ("trcrsctlr18", 64),
        ("trcssccr2", 64),
        ("trcsspcicr2", 64),
        ("trcrsctlr3", 64),
        ("trcrsctlr19", 64),
        ("trcssccr3", 64),
        ("trcsspcicr3", 64),
        ("trcrsctlr4", 64),
        ("trcrsctlr20", 64),
        ("trcssccr4", 64),
        ("trcsspcicr4", 64),
        ("trcpdcr", 64),
        ("trcrsctlr5", 64),
        ("trcrsctlr21", 64),
        ("trcssccr5", 64),
        ("trcsspcicr5", 64),
        ("trcrsctlr6", 64),
        ("trcrsctlr22", 64),
        ("trcssccr6", 64),
        ("trcsspcicr6", 64),
        ("trcrsctlr7", 64),
        ("trcrsctlr23", 64),
        ("trcssccr7", 64),
        ("trcsspcicr7", 64),
        ("trcrsctlr8", 64),
        ("trcrsctlr24", 64),
        ("trcsscsr0", 64),
        ("trcrsctlr9", 64),
        ("trcrsctlr25", 64),
        ("trcsscsr1", 64),
        ("trcrsctlr10", 64),
        ("trcrsctlr26", 64),
        ("trcsscsr2", 64),
        ("trcrsctlr11", 64),
        ("trcrsctlr27", 64),
        ("trcsscsr3", 64),
        ("trcrsctlr12", 64),
        ("trcrsctlr28", 64),
        ("trcsscsr4", 64),
        ("trcrsctlr13", 64),
        ("trcrsctlr29", 64),
        ("trcsscsr5", 64),
        ("trcrsctlr14", 64),
        ("trcrsctlr30", 64),
        ("trcsscsr6", 64),
        ("trcrsctlr15", 64),
        ("trcrsctlr31", 64),
        ("trcsscsr7", 64),
        ("trcacvr0", 64),
        ("trcacvr8", 64),
        ("trcacatr0", 64),
        ("trcacatr8", 64),
        ("trcdvcvr0", 64),
        ("trcdvcvr4", 64),
        ("trcdvcmr0", 64),
        ("trcdvcmr4", 64),
        ("trcacvr1", 64),
        ("trcacvr9", 64),
        ("trcacatr1", 64),
        ("trcacatr9", 64),
        ("trcacvr2", 64),
        ("trcacvr10", 64),
        ("trcacatr2", 64),
        ("trcacatr10", 64),
        ("trcdvcvr1", 64),
        ("trcdvcvr5", 64),
        ("trcdvcmr1", 64),
        ("trcdvcmr5", 64),
        ("trcacvr3", 64),
        ("trcacvr11", 64),
        ("trcacatr3", 64),
        ("trcacatr11", 64),
        ("trcacvr4", 64),
        ("trcacvr12", 64),
        ("trcacatr4", 64),
        ("trcacatr12", 64),
        ("trcdvcvr2", 64),
        ("trcdvcvr6", 64),
        ("trcdvcmr2", 64),
        ("trcdvcmr6", 64),
        ("trcacvr5", 64),
        ("trcacvr13", 64),
        ("trcacatr5", 64),
        ("trcacatr13", 64),
        ("trcacvr6", 64),
        ("trcacvr14", 64),
        ("trcacatr6", 64),
        ("trcacatr14", 64),
        ("trcdvcvr3", 64),
        ("trcdvcvr7", 64),
        ("trcdvcmr3", 64),
        ("trcdvcmr7", 64),
        ("trcacvr7", 64),
        ("trcacvr15", 64),
        ("trcacatr7", 64),
        ("trcacatr15", 64),
        ("trccidcvr0", 64),
        ("trcvmidcvr0", 64),
        ("trccidcctlr0", 64),
        ("trccidcctlr1", 64),
        ("trccidcvr1", 64),
        ("trcvmidcvr1", 64),
        ("trcvmidcctlr0", 64),
        ("trcvmidcctlr1", 64),
        ("trccidcvr2", 64),
        ("trcvmidcvr2", 64),
        ("trccidcvr3", 64),
        ("trcvmidcvr3", 64),
        ("trccidcvr4", 64),
        ("trcvmidcvr4", 64),
        ("trccidcvr5", 64),
        ("trcvmidcvr5", 64),
        ("trccidcvr6", 64),
        ("trcvmidcvr6", 64),
        ("trccidcvr7", 64),
        ("trcvmidcvr7", 64),
        ("trcitctrl", 64),
        ("trcclaimset", 64),
        ("trcclaimclr", 64),
        ("trclar", 64),
        ("teecr32_el1", 64),
        ("teehbr32_el1", 64),
        ("dbgdtr_el0", 64),
        ("dbgdtrtx_el0", 64),
        ("dbgvcr32_el2", 64),
        ("sctlr_el1", 64),
        ("actlr_el1", 64),
        ("cpacr_el1", 64),
        ("rgsr_el1", 64),
        ("gcr_el1", 64),
        ("trfcr_el1", 64),
        ("ttbr0_el1", 64),
        ("ttbr1_el1", 64),
        ("tcr_el1", 64),
        ("apiakeylo_el1", 64),
        ("apiakeyhi_el1", 64),
        ("apibkeylo_el1", 64),
        ("apibkeyhi_el1", 64),
        ("apdakeylo_el1", 64),
        ("apdakeyhi_el1", 64),
        ("apdbkeylo_el1", 64),
        ("apdbkeyhi_el1", 64),
        ("apgakeylo_el1", 64),
        ("apgakeyhi_el1", 64),
        ("spsr_el1", 64),
        ("elr_el1", 64),
        ("sp_el0", 64),
        ("spsel", 64),
        ("currentel", 64),
        ("pan", 64),
        ("uao", 64),
        ("icc_pmr_el1", 64),
        ("afsr0_el1", 64),
        ("afsr1_el1", 64),
        ("esr_el1", 64),
        ("errselr_el1", 64),
        ("erxctlr_el1", 64),
        ("erxstatus_el1", 64),
        ("erxaddr_el1", 64),
        ("erxpfgctl_el1", 64),
        ("erxpfgcdn_el1", 64),
        ("erxmisc0_el1", 64),
        ("erxmisc1_el1", 64),
        ("erxmisc2_el1", 64),
        ("erxmisc3_el1", 64),
        ("erxts_el1", 64),
        ("tfsr_el1", 64),
        ("tfsre0_el1", 64),
        ("far_el1", 64),
        ("par_el1", 64),
        ("pmscr_el1", 64),
        ("pmsicr_el1", 64),
        ("pmsirr_el1", 64),
        ("pmsfcr_el1", 64),
        ("pmsevfr_el1", 64),
        ("pmslatfr_el1", 64),
        ("pmsidr_el1", 64),
        ("pmblimitr_el1", 64),
        ("pmbptr_el1", 64),
        ("pmbsr_el1", 64),
        ("pmbidr_el1", 64),
        ("trblimitr_el1", 64),
        ("trbptr_el1", 64),
        ("trbbaser_el1", 64),
        ("trbsr_el1", 64),
        ("trbmar_el1", 64),
        ("trbtrg_el1", 64),
        ("pmintenset_el1", 64),
        ("pmintenclr_el1", 64),
        ("pmmir_el1", 64),
        ("mair_el1", 64),
        ("amair_el1", 64),
        ("lorsa_el1", 64),
        ("lorea_el1", 64),
        ("lorn_el1", 64),
        ("lorc_el1", 64),
        ("mpam1_el1", 64),
        ("mpam0_el1", 64),
        ("vbar_el1", 64),
        ("rmr_el1", 64),
        ("disr_el1", 64),
        ("icc_eoir0_el1", 64),
        ("icc_bpr0_el1", 64),
        ("icc_ap0r0_el1", 64),
        ("icc_ap0r1_el1", 64),
        ("icc_ap0r2_el1", 64),
        ("icc_ap0r3_el1", 64),
        ("icc_ap1r0_el1", 64),
        ("icc_ap1r1_el1", 64),
        ("icc_ap1r2_el1", 64),
        ("icc_ap1r3_el1", 64),
        ("icc_dir_el1", 64),
        ("icc_sgi1r_el1", 64),
        ("icc_asgi1r_el1", 64),
        ("icc_sgi0r_el1", 64),
        ("icc_eoir1_el1", 64),
        ("icc_bpr1_el1", 64),
        ("icc_ctlr_el1", 64),
        ("icc_sre_el1", 64),
        ("icc_igrpen0_el1", 64),
        ("icc_igrpen1_el1", 64),
        ("icc_seien_el1", 64),
        ("contextidr_el1", 64),
        ("tpidr_el1", 64),
        ("scxtnum_el1", 64),
        ("cntkctl_el1", 64),
        ("csselr_el1", 64),
        ("nzcv", 64),
        ("daifset", 64),
        ("dit", 64),
        ("ssbs", 64),
        ("tco", 64),
        ("fpcr", 64),
        ("fpsr", 64),
        ("dspsr_el0", 64),
        ("dlr_el0", 64),
        ("pmcr_el0", 64),
        ("pmcntenset_el0", 64),
        ("pmcntenclr_el0", 64),
        ("pmovsclr_el0", 64),
        ("pmswinc_el0", 64),
        ("pmselr_el0", 64),
        ("pmccntr_el0", 64),
        ("pmxevtyper_el0", 64),
        ("pmxevcntr_el0", 64),
        ("daifclr", 64),
        ("pmuserenr_el0", 64),
        ("pmovsset_el0", 64),
        ("tpidr_el0", 64),
        ("tpidrro_el0", 64),
        ("scxtnum_el0", 64),
        ("amcr_el0", 64),
        ("amuserenr_el0", 64),
        ("amcntenclr0_el0", 64),
        ("amcntenset0_el0", 64),
        ("amcntenclr1_el0", 64),
        ("amcntenset1_el0", 64),
        ("amevcntr00_el0", 64),
        ("amevcntr01_el0", 64),
        ("amevcntr02_el0", 64),
        ("amevcntr03_el0", 64),
        ("amevcntr10_el0", 64),
        ("amevcntr11_el0", 64),
        ("amevcntr12_el0", 64),
        ("amevcntr13_el0", 64),
        ("amevcntr14_el0", 64),
        ("amevcntr15_el0", 64),
        ("amevcntr16_el0", 64),
        ("amevcntr17_el0", 64),
        ("amevcntr18_el0", 64),
        ("amevcntr19_el0", 64),
        ("amevcntr110_el0", 64),
        ("amevcntr111_el0", 64),
        ("amevcntr112_el0", 64),
        ("amevcntr113_el0", 64),
        ("amevcntr114_el0", 64),
        ("amevcntr115_el0", 64),
        ("amevtyper10_el0", 64),
        ("amevtyper11_el0", 64),
        ("amevtyper12_el0", 64),
        ("amevtyper13_el0", 64),
        ("amevtyper14_el0", 64),
        ("amevtyper15_el0", 64),
        ("amevtyper16_el0", 64),
        ("amevtyper17_el0", 64),
        ("amevtyper18_el0", 64),
        ("amevtyper19_el0", 64),
        ("amevtyper110_el0", 64),
        ("amevtyper111_el0", 64),
        ("amevtyper112_el0", 64),
        ("amevtyper113_el0", 64),
        ("amevtyper114_el0", 64),
        ("amevtyper115_el0", 64),
        ("cntfrq_el0", 64),
        ("cntp_tval_el0", 64),
        ("cntp_ctl_el0", 64),
        ("cntp_cval_el0", 64),
        ("cntv_tval_el0", 64),
        ("cntv_ctl_el0", 64),
        ("cntv_cval_el0", 64),
        ("pmevcntr0_el0", 64),
        ("pmevcntr1_el0", 64),
        ("pmevcntr2_el0", 64),
        ("pmevcntr3_el0", 64),
        ("pmevcntr4_el0", 64),
        ("pmevcntr5_el0", 64),
        ("pmevcntr6_el0", 64),
        ("pmevcntr7_el0", 64),
        ("pmevcntr8_el0", 64),
        ("pmevcntr9_el0", 64),
        ("pmevcntr10_el0", 64),
        ("pmevcntr11_el0", 64),
        ("pmevcntr12_el0", 64),
        ("pmevcntr13_el0", 64),
        ("pmevcntr14_el0", 64),
        ("pmevcntr15_el0", 64),
        ("pmevcntr16_el0", 64),
        ("pmevcntr17_el0", 64),
        ("pmevcntr18_el0", 64),
        ("pmevcntr19_el0", 64),
        ("pmevcntr20_el0", 64),
        ("pmevcntr21_el0", 64),
        ("pmevcntr22_el0", 64),
        ("pmevcntr23_el0", 64),
        ("pmevcntr24_el0", 64),
        ("pmevcntr25_el0", 64),
        ("pmevcntr26_el0", 64),
        ("pmevcntr27_el0", 64),
        ("pmevcntr28_el0", 64),
        ("pmevcntr29_el0", 64),
        ("pmevcntr30_el0", 64),
        ("pmevtyper0_el0", 64),
        ("pmevtyper1_el0", 64),
        ("pmevtyper2_el0", 64),
        ("pmevtyper3_el0", 64),
        ("pmevtyper4_el0", 64),
        ("pmevtyper5_el0", 64),
        ("pmevtyper6_el0", 64),
        ("pmevtyper7_el0", 64),
        ("pmevtyper8_el0", 64),
        ("pmevtyper9_el0", 64),
        ("pmevtyper10_el0", 64),
        ("pmevtyper11_el0", 64),
        ("pmevtyper12_el0", 64),
        ("pmevtyper13_el0", 64),
        ("pmevtyper14_el0", 64),
        ("pmevtyper15_el0", 64),
        ("pmevtyper16_el0", 64),
        ("pmevtyper17_el0", 64),
        ("pmevtyper18_el0", 64),
        ("pmevtyper19_el0", 64),
        ("pmevtyper20_el0", 64),
        ("pmevtyper21_el0", 64),
        ("pmevtyper22_el0", 64),
        ("pmevtyper23_el0", 64),
        ("pmevtyper24_el0", 64),
        ("pmevtyper25_el0", 64),
        ("pmevtyper26_el0", 64),
        ("pmevtyper27_el0", 64),
        ("pmevtyper28_el0", 64),
        ("pmevtyper29_el0", 64),
        ("pmevtyper30_el0", 64),
        ("pmccfiltr_el0", 64),
        ("vpidr_el2", 64),
        ("vmpidr_el2", 64),
        ("sctlr_el2", 64),
        ("actlr_el2", 64),
        ("hcr_el2", 64),
        ("mdcr_el2", 64),
        ("cptr_el2", 64),
        ("hstr_el2", 64),
        ("hacr_el2", 64),
        ("trfcr_el2", 64),
        ("sder32_el2", 64),
        ("ttbr0_el2", 64),
        ("ttbr1_el2", 64),
        ("tcr_el2", 64),
        ("vttbr_el2", 64),
        ("vtcr_el2", 64),
        ("vncr_el2", 64),
        ("vsttbr_el2", 64),
        ("vstcr_el2", 64),
        ("dacr32_el2", 64),
        ("spsr_el2", 64),
        ("elr_el2", 64),
        ("sp_el1", 64),
        ("spsr_irq", 64),
        ("spsr_abt", 64),
        ("spsr_und", 64),
        ("spsr_fiq", 64),
        ("ifsr32_el2", 64),
        ("afsr0_el2", 64),
        ("afsr1_el2", 64),
        ("esr_el2", 64),
        ("vsesr_el2", 64),
        ("fpexc32_el2", 64),
        ("tfsr_el2", 64),
        ("far_el2", 64),
        ("hpfar_el2", 64),
        ("pmscr_el2", 64),
        ("mair_el2", 64),
        ("amair_el2", 64),
        ("mpamhcr_el2", 64),
        ("mpamvpmv_el2", 64),
        ("mpam2_el2", 64),
        ("mpamvpm0_el2", 64),
        ("mpamvpm1_el2", 64),
        ("mpamvpm2_el2", 64),
        ("mpamvpm3_el2", 64),
        ("mpamvpm4_el2", 64),
        ("mpamvpm5_el2", 64),
        ("mpamvpm6_el2", 64),
        ("mpamvpm7_el2", 64),
        ("vbar_el2", 64),
        ("rmr_el2", 64),
        ("vdisr_el2", 64),
        ("ich_ap0r0_el2", 64),
        ("ich_ap0r1_el2", 64),
        ("ich_ap0r2_el2", 64),
        ("ich_ap0r3_el2", 64),
        ("ich_ap1r0_el2", 64),
        ("ich_ap1r1_el2", 64),
        ("ich_ap1r2_el2", 64),
        ("ich_ap1r3_el2", 64),
        ("ich_vseir_el2", 64),
        ("icc_sre_el2", 64),
        ("ich_hcr_el2", 64),
        ("ich_misr_el2", 64),
        ("ich_vmcr_el2", 64),
        ("ich_lr0_el2", 64),
        ("ich_lr1_el2", 64),
        ("ich_lr2_el2", 64),
        ("ich_lr3_el2", 64),
        ("ich_lr4_el2", 64),
        ("ich_lr5_el2", 64),
        ("ich_lr6_el2", 64),
        ("ich_lr7_el2", 64),
        ("ich_lr8_el2", 64),
        ("ich_lr9_el2", 64),
        ("ich_lr10_el2", 64),
        ("ich_lr11_el2", 64),
        ("ich_lr12_el2", 64),
        ("ich_lr13_el2", 64),
        ("ich_lr14_el2", 64),
        ("ich_lr15_el2", 64),
        ("contextidr_el2", 64),
        ("tpidr_el2", 64),
        ("scxtnum_el2", 64),
        ("cntvoff_el2", 64),
        ("cnthctl_el2", 64),
        ("cnthp_tval_el2", 64),
        ("cnthp_ctl_el2", 64),
        ("cnthp_cval_el2", 64),
        ("cnthv_tval_el2", 64),
        ("cnthv_ctl_el2", 64),
        ("cnthv_cval_el2", 64),
        ("cnthvs_tval_el2", 64),
        ("cnthvs_ctl_el2", 64),
        ("cnthvs_cval_el2", 64),
        ("cnthps_tval_el2", 64),
        ("cnthps_ctl_el2", 64),
        ("cnthps_cval_el2", 64),
        ("sctlr_el12", 64),
        ("cpacr_el12", 64),
        ("trfcr_el12", 64),
        ("ttbr0_el12", 64),
        ("ttbr1_el12", 64),
        ("tcr_el12", 64),
        ("spsr_el12", 64),
        ("elr_el12", 64),
        ("afsr0_el12", 64),
        ("afsr1_el12", 64),
        ("esr_el12", 64),
        ("tfsr_el12", 64),
        ("far_el12", 64),
        ("pmscr_el12", 64),
        ("mair_el12", 64),
        ("amair_el12", 64),
        ("mpam1_el12", 64),
        ("vbar_el12", 64),
        ("contextidr_el12", 64),
        ("scxtnum_el12", 64),
        ("cntkctl_el12", 64),
        ("cntp_tval_el02", 64),
        ("cntp_ctl_el02", 64),
        ("cntp_cval_el02", 64),
        ("cntv_tval_el02", 64),
        ("cntv_ctl_el02", 64),
        ("cntv_cval_el02", 64),
        ("sctlr_el3", 64),
        ("actlr_el3", 64),
        ("scr_el3", 64),
        ("sder32_el3", 64),
        ("cptr_el3", 64),
        ("mdcr_el3", 64),
        ("ttbr0_el3", 64),
        ("tcr_el3", 64),
        ("spsr_el3", 64),
        ("elr_el3", 64),
        ("sp_el2", 64),
        ("afsr0_el3", 64),
        ("afsr1_el3", 64),
        ("esr_el3", 64),
        ("tfsr_el3", 64),
        ("far_el3", 64),
        ("mair_el3", 64),
        ("amair_el3", 64),
        ("mpam3_el3", 64),
        ("vbar_el3", 64),
        ("rmr_el3", 64),
        ("icc_ctlr_el3", 64),
        ("icc_sre_el3", 64),
        ("icc_igrpen1_el3", 64),
        ("tpidr_el3", 64),
        ("scxtnum_el3", 64),
        ("cntps_tval_el1", 64),
        ("cntps_ctl_el1", 64),
        ("cntps_cval_el1", 64),
        ("spsel", 64),
]
