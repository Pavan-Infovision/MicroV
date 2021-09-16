/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MV_REG_T_H
#define MV_REG_T_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
    /**
     * <!-- description -->
     *   @brief Defines which register to use for certain hypercalls
     */
    enum mv_reg_t : int32_t
#else
/**
     * <!-- description -->
     *   @brief Defines which register to use for certain hypercalls
     */
enum mv_reg_t
#endif
    {
        /** @brief defines the rax register */
        mv_reg_t_rax = 1,
        /** @brief defines the rbx register */
        mv_reg_t_rbx = 2,
        /** @brief defines the rcx register */
        mv_reg_t_rcx = 3,
        /** @brief defines the rdx register */
        mv_reg_t_rdx = 4,
        /** @brief defines the rbp register */
        mv_reg_t_rbp = 5,
        /** @brief defines the rsi register */
        mv_reg_t_rsi = 6,
        /** @brief defines the rdi register */
        mv_reg_t_rdi = 7,
        /** @brief defines the r8 register */
        mv_reg_t_r8 = 8,
        /** @brief defines the r9 register */
        mv_reg_t_r9 = 9,
        /** @brief defines the r10 register */
        mv_reg_t_r10 = 10,
        /** @brief defines the r11 register */
        mv_reg_t_r11 = 11,
        /** @brief defines the r12 register */
        mv_reg_t_r12 = 12,
        /** @brief defines the r13 register */
        mv_reg_t_r13 = 13,
        /** @brief defines the r14 register */
        mv_reg_t_r14 = 14,
        /** @brief defines the r15 register */
        mv_reg_t_r15 = 15,
        /** @brief defines the rsp register */
        mv_reg_t_rsp = 16,
        /** @brief defines the rip register */
        mv_reg_t_rip = 17,
        /** @brief defines the rflags register */
        mv_reg_t_rflags = 18,
        /** @brief defines the es_selector register */
        mv_reg_t_es_selector = 19,
        /** @brief defines the es_attrib register */
        mv_reg_t_es_attrib = 20,
        /** @brief defines the es_limit register */
        mv_reg_t_es_limit = 21,
        /** @brief defines the es_base register */
        mv_reg_t_es_base = 22,
        /** @brief defines the cs_selector register */
        mv_reg_t_cs_selector = 23,
        /** @brief defines the cs_attrib register */
        mv_reg_t_cs_attrib = 24,
        /** @brief defines the cs_limit register */
        mv_reg_t_cs_limit = 25,
        /** @brief defines the cs_base register */
        mv_reg_t_cs_base = 26,
        /** @brief defines the ss_selector register */
        mv_reg_t_ss_selector = 27,
        /** @brief defines the ss_attrib register */
        mv_reg_t_ss_attrib = 28,
        /** @brief defines the ss_limit register */
        mv_reg_t_ss_limit = 29,
        /** @brief defines the ss_base register */
        mv_reg_t_ss_base = 30,
        /** @brief defines the ds_selector register */
        mv_reg_t_ds_selector = 31,
        /** @brief defines the ds_attrib register */
        mv_reg_t_ds_attrib = 32,
        /** @brief defines the ds_limit register */
        mv_reg_t_ds_limit = 33,
        /** @brief defines the ds_base register */
        mv_reg_t_ds_base = 34,
        /** @brief defines the fs_selector register */
        mv_reg_t_fs_selector = 35,
        /** @brief defines the fs_attrib register */
        mv_reg_t_fs_attrib = 36,
        /** @brief defines the fs_limit register */
        mv_reg_t_fs_limit = 37,
        /** @brief defines the fs_base register */
        mv_reg_t_fs_base = 38,
        /** @brief defines the gs_selector register */
        mv_reg_t_gs_selector = 39,
        /** @brief defines the gs_attrib register */
        mv_reg_t_gs_attrib = 40,
        /** @brief defines the gs_limit register */
        mv_reg_t_gs_limit = 41,
        /** @brief defines the gs_base register */
        mv_reg_t_gs_base = 42,
        /** @brief defines the ldtr_selector register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_ldtr_selector = 43,
        /** @brief defines the ldtr_attrib register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_ldtr_attrib = 44,
        /** @brief defines the ldtr_limit register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_ldtr_limit = 45,
        /** @brief defines the ldtr_base register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_ldtr_base = 46,
        /** @brief defines the tr_selector register */
        mv_reg_t_tr_selector = 47,
        /** @brief defines the tr_attrib register */
        mv_reg_t_tr_attrib = 48,
        /** @brief defines the tr_limit register */
        mv_reg_t_tr_limit = 49,
        /** @brief defines the tr_base register */
        mv_reg_t_tr_base = 50,
        /** @brief defines the gdtr_selector register */
        mv_reg_t_gdtr_selector = 51,
        /** @brief defines the gdtr_attrib register */
        mv_reg_t_gdtr_attrib = 52,
        /** @brief defines the gdtr_limit register */
        mv_reg_t_gdtr_limit = 53,
        /** @brief defines the gdtr_base register */
        mv_reg_t_gdtr_base = 54,
        /** @brief defines the idtr_selector register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_selector = 55,
        /** @brief defines the idtr_attrib register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_attrib = 56,
        /** @brief defines the idtr_limit register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_limit = 57,
        /** @brief defines the idtr_base register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_base = 58,
        /** @brief defines the dr0 register */
        mv_reg_t_dr0 = 59,
        /** @brief defines the dr1 register */
        mv_reg_t_dr1 = 60,
        /** @brief defines the dr2 register */
        mv_reg_t_dr2 = 61,
        /** @brief defines the dr3 register */
        mv_reg_t_dr3 = 62,
        /** @brief defines the dr6 register */
        mv_reg_t_dr6 = 63,
        /** @brief defines the dr7 register */
        mv_reg_t_dr7 = 64,
        /** @brief defines the cr0 register */
        mv_reg_t_cr0 = 65,
        /** @brief defines the cr2 register */
        mv_reg_t_cr2 = 66,
        /** @brief defines the cr3 register */
        mv_reg_t_cr3 = 67,
        /** @brief defines the cr4 register */
        mv_reg_t_cr4 = 68,
        /** @brief defines the cr8 register */
        mv_reg_t_cr8 = 69,
        /** @brief defines the xcr0 register (Intel Only) */
        mv_reg_t_xcr0 = 70,
        /** @brief defines the es_type register */
        mv_reg_t_es_type = 71,
        /** @brief defines the es_present register */
        mv_reg_t_es_present = 72,
        /** @brief defines the es_dpl register */
        mv_reg_t_es_dpl = 73,
        /** @brief defines the es_db register */
        mv_reg_t_es_db = 74,
        /** @brief defines the es_s register */
        mv_reg_t_es_s = 75,
        /** @brief defines the es_l register */
        mv_reg_t_es_l = 76,
        /** @brief defines the es_g register */
        mv_reg_t_es_g = 77,
        /** @brief defines the es_avl register */
        mv_reg_t_es_avl = 78,
        /** @brief defines the es_unusable register */
        mv_reg_t_es_unusable = 79,
        /** @brief defines the es_padding register */
        mv_reg_t_es_padding = 80,
        /** @brief defines the cs_type register */
        mv_reg_t_cs_type = 81,
        /** @brief defines the cs_present register */
        mv_reg_t_cs_present = 82,
        /** @brief defines the cs_dpl register */
        mv_reg_t_cs_dpl = 83,
        /** @brief defines the cs_db register */
        mv_reg_t_cs_db = 84,
        /** @brief defines the cs_s register */
        mv_reg_t_cs_s = 85,
        /** @brief defines the cs_l register */
        mv_reg_t_cs_l = 86,
        /** @brief defines the cs_g register */
        mv_reg_t_cs_g = 87,
        /** @brief defines the cs_avl register */
        mv_reg_t_cs_avl = 88,
        /** @brief defines the cs_unusable register */
        mv_reg_t_cs_unusable = 89,
        /** @brief defines the cs_padding register */
        mv_reg_t_cs_padding = 90,
        /** @brief defines the ds_type register */
        mv_reg_t_ds_type = 91,
        /** @brief defines the ds_present register */
        mv_reg_t_ds_present = 92,
        /** @brief defines the ds_dpl register */
        mv_reg_t_ds_dpl = 93,
        /** @brief defines the ds_db register */
        mv_reg_t_ds_db = 94,
        /** @brief defines the ds_s register */
        mv_reg_t_ds_s = 95,
        /** @brief defines the ds_l register */
        mv_reg_t_ds_l = 96,
        /** @brief defines the ds_g register */
        mv_reg_t_ds_g = 97,
        /** @brief defines the ds_avl register */
        mv_reg_t_ds_avl = 98,
        /** @brief defines the ds_unusable register */
        mv_reg_t_ds_unusable = 99,
        /** @brief defines the ds_padding register */
        mv_reg_t_ds_padding = 100,
        /** @brief defines the fs_type register */
        mv_reg_t_fs_type = 101,
        /** @brief defines the fs_present register */
        mv_reg_t_fs_present = 102,
        /** @brief defines the fs_dpl register */
        mv_reg_t_fs_dpl = 103,
        /** @brief defines the fs_db register */
        mv_reg_t_fs_db = 104,
        /** @brief defines the fs_s register */
        mv_reg_t_fs_s = 105,
        /** @brief defines the fs_l register */
        mv_reg_t_fs_l = 106,
        /** @brief defines the fs_g register */
        mv_reg_t_fs_g = 107,
        /** @brief defines the fs_avl register */
        mv_reg_t_fs_avl = 108,
        /** @brief defines the fs_unusable register */
        mv_reg_t_fs_unusable = 109,
        /** @brief defines the fs_padding register */
        mv_reg_t_fs_padding = 110,
        /** @brief defines the gs_type register */
        mv_reg_t_gs_type = 111,
        /** @brief defines the gs_present register */
        mv_reg_t_gs_present = 112,
        /** @brief defines the gs_dpl register */
        mv_reg_t_gs_dpl = 113,
        /** @brief defines the gs_db register */
        mv_reg_t_gs_db = 114,
        /** @brief defines the gs_s register */
        mv_reg_t_gs_s = 115,
        /** @brief defines the gs_l register */
        mv_reg_t_gs_l = 116,
        /** @brief defines the gs_g register */
        mv_reg_t_gs_g = 117,
        /** @brief defines the gs_avl register */
        mv_reg_t_gs_avl = 118,
        /** @brief defines the gs_unusable register */
        mv_reg_t_gs_unusable = 119,
        /** @brief defines the gs_padding register */
        mv_reg_t_gs_padding = 120,
        /** @brief defines the ss_type register */
        mv_reg_t_ss_type = 121,
        /** @brief defines the ss_present register */
        mv_reg_t_ss_present = 122,
        /** @brief defines the ss_dpl register */
        mv_reg_t_ss_dpl = 123,
        /** @brief defines the ss_db register */
        mv_reg_t_ss_db = 124,
        /** @brief defines the ss_s register */
        mv_reg_t_ss_s = 125,
        /** @brief defines the ss_l register */
        mv_reg_t_ss_l = 126,
        /** @brief defines the ss_g register */
        mv_reg_t_ss_g = 127,
        /** @brief defines the ss_avl register */
        mv_reg_t_ss_avl = 128,
        /** @brief defines the ss_unusable register */
        mv_reg_t_ss_unusable = 129,
        /** @brief defines the ss_padding register */
        mv_reg_t_ss_padding = 130,
        /** @brief defines the tr_type register */
        mv_reg_t_tr_type = 131,
        /** @brief defines the tr_present register */
        mv_reg_t_tr_present = 132,
        /** @brief defines the tr_dpl register */
        mv_reg_t_tr_dpl = 133,
        /** @brief defines the tr_db register */
        mv_reg_t_tr_db = 134,
        /** @brief defines the tr_s register */
        mv_reg_t_tr_s = 135,
        /** @brief defines the tr_l register */
        mv_reg_t_tr_l = 136,
        /** @brief defines the tr_g register */
        mv_reg_t_tr_g = 137,
        /** @brief defines the tr_avl register */
        mv_reg_t_tr_avl = 138,
        /** @brief defines the tr_unusable register */
        mv_reg_t_tr_unusable = 139,
        /** @brief defines the tr_padding register */
        mv_reg_t_tr_padding = 140,
        /** @brief defines the ldt_base register */
        mv_reg_t_ldt_base = 141,
        /** @brief defines the ldt_limit register */
        mv_reg_t_ldt_limit = 142,
        /** @brief defines the ldt_selector register */
        mv_reg_t_ldt_selector = 143,
        /** @brief defines the ldt_type register */
        mv_reg_t_ldt_type = 144,
        /** @brief defines the ldt_present register */
        mv_reg_t_ldt_present = 145,
        /** @brief defines the ldt_dpl register */
        mv_reg_t_ldt_dpl = 146,
        /** @brief defines the ldt_db register */
        mv_reg_t_ldt_db = 147,
        /** @brief defines the ldt_s register */
        mv_reg_t_ldt_s = 148,
        /** @brief defines the ldt_l register */
        mv_reg_t_ldt_l = 149,
        /** @brief defines the ldt_g register */
        mv_reg_t_ldt_g = 150,
        /** @brief defines the ldt_avl register */
        mv_reg_t_ldt_avl = 150,
        /** @brief defines the ldt_unusable register */
        mv_reg_t_ldt_unusable = 151,
        /** @brief defines the ldt_padding register */
        mv_reg_t_ldt_padding = 152,
        /** @brief defines the gdt_base register */
        mv_reg_t_gdt_base = 153,
        /** @brief defines the gdt_limit register */
        mv_reg_t_gdt_limit = 154,
        /** @brief defines the gdt_padding0 register */
        mv_reg_t_gdt_padding0 = 155,
        /** @brief defines the gdt_padding1 register */
        mv_reg_t_gdt_padding1 = 156,
        /** @brief defines the gdt_padding2 register */
        mv_reg_t_gdt_padding2 = 157,
        /** @brief defines the idt_base register */
        mv_reg_t_idt_base = 158,
        /** @brief defines the idt_limit register */
        mv_reg_t_idt_limit = 159,
        /** @brief defines the idt_padding0 register */
        mv_reg_t_idt_padding0 = 160,
        /** @brief defines the idt_padding1 register */
        mv_reg_t_idt_padding1 = 161,
        /** @brief defines the idt_padding2 register */
        mv_reg_t_idt_padding2 = 162,
        /** @brief defines the mv_msr_t_efer register */
        mv_msr_t_efer = 163,
        /** @brief defines the mv_msr_t_apic_base register */
        mv_msr_t_apic_base = 164,
        /** @brief defines and invalid mv_reg_t */
        mv_reg_t_invalid = 165,
    };

#ifdef __cplusplus
}
#endif

#endif
