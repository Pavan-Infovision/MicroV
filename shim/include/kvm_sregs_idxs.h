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

#ifndef KVM_SREGS_IDXS_H
#define KVM_SREGS_IDXS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief index for ES TYPE register in kvm segment */
#define ES_TYPE_IDX ((uint8_t)0)
/** @brief index for ES SELECTOR register in kvm segment */
#define ES_SELECTOR_IDX ((uint16_t)1)
/** @brief index for ES BASE register in kvm segment */
#define ES_BASE_IDX ((uint64_t)2)
/** @brief index for ES LIMIT register in kvm segment */
#define ES_LIMIT_IDX ((uint32_t)3)
/** @brief index for ES PRESENT register in kvm segment */
#define ES_PRESENT_IDX ((uint8_t)4)
/** @brief index for ES DPL register in kvm segment */
#define ES_DPL_IDX ((uint8_t)5)
/** @brief index for ES DB register in kvm segment */
#define ES_DB_IDX ((uint8_t)6)
/** @brief index for ES S register in kvm segment */
#define ES_S_IDX ((uint8_t)7)
/** @brief index for ES L register in kvm segment */
#define ES_L_IDX ((uint8_t)8)
/** @brief index for ES G register in kvm segment */
#define ES_G_IDX ((uint8_t)9)
/** @brief index for ES AVL register in kvm segment */
#define ES_AVL_IDX ((uint8_t)10)
/** @brief index for ES UNUSABLE register in kvm segment */
#define ES_UNUSABLE_IDX ((uint8_t)11)
/** @brief index for ES PADDING register in kvm segment */
#define ES_PADDING_IDX ((uint8_t)12)
/** @brief index for CS TYPE register in kvm segment */
#define CS_TYPE_IDX ((uint8_t)13)
/** @brief index for CS SELECTOR register in kvm segment */
#define CS_SELECTOR_IDX ((uint16_t)14)
/** @brief index for CS BASE register in kvm segment */
#define CS_BASE_IDX ((uint64_t)15)
/** @brief index for CS LIMIT register in kvm segment */
#define CS_LIMIT_IDX ((uint32_t)16)
/** @brief index for CS PRESENT register in kvm segment */
#define CS_PRESENT_IDX ((uint8_t)17)
/** @brief index for CS DPL register in kvm segment */
#define CS_DPL_IDX ((uint8_t)18)
/** @brief index for CS DB register in kvm segment */
#define CS_DB_IDX ((uint8_t)19)
/** @brief index for CS S register in kvm segment */
#define CS_S_IDX ((uint8_t)20)
/** @brief index for CS L register in kvm segment */
#define CS_L_IDX ((uint8_t)21)
/** @brief index for CS G register in kvm segment */
#define CS_G_IDX ((uint8_t)22)
/** @brief index for CS AVL register in kvm segment */
#define CS_AVL_IDX ((uint8_t)23)
/** @brief index for CS UNUSABLE register in kvm segment */
#define CS_UNUSABLE_IDX ((uint8_t)24)
/** @brief index for CS PADDING register in kvm segment */
#define CS_PADDING_IDX ((uint8_t)25)
/** @brief index for DS TYPE register in kvm segment */
#define DS_TYPE_IDX ((uint8_t)26)
/** @brief index for DS SELECTOR register in kvm segment */
#define DS_SELECTOR_IDX ((uint16_t)27)
/** @brief index for DS BASE register in kvm segment */
#define DS_BASE_IDX ((uint64_t)28)
/** @brief index for DS LIMIT register in kvm segment */
#define DS_LIMIT_IDX ((uint32_t)29)
/** @brief index for DS PRESENT register in kvm segment */
#define DS_PRESENT_IDX ((uint8_t)30)
/** @brief index for DS DPL register in kvm segment */
#define DS_DPL_IDX ((uint8_t)31)
/** @brief index for DS DB register in kvm segment */
#define DS_DB_IDX ((uint8_t)32)
/** @brief index for DS S register in kvm segment */
#define DS_S_IDX ((uint8_t)33)
/** @brief index for DS L register in kvm segment */
#define DS_L_IDX ((uint8_t)34)
/** @brief index for DS G register in kvm segment */
#define DS_G_IDX ((uint8_t)35)
/** @brief index for DS AVL register in kvm segment */
#define DS_AVL_IDX ((uint8_t)36)
/** @brief index for DS UNUSABLE register in kvm segment */
#define DS_UNUSABLE_IDX ((uint8_t)37)
/** @brief index for DS PADDING register in kvm segment */
#define DS_PADDING_IDX ((uint8_t)38)
/** @brief index for FS TYPE register in kvm segment */
#define FS_TYPE_IDX ((uint8_t)39)
/** @brief index for FS SELECTOR register in kvm segment */
#define FS_SELECTOR_IDX ((uint16_t)40)
/** @brief index for FS BASE register in kvm segment */
#define FS_BASE_IDX ((uint64_t)41)
/** @brief index for FS LIMIT register in kvm segment */
#define FS_LIMIT_IDX ((uint32_t)42)
/** @brief index for FS PRESENT register in kvm segment */
#define FS_PRESENT_IDX ((uint8_t)43)
/** @brief index for FS DPL register in kvm segment */
#define FS_DPL_IDX ((uint8_t)44)
/** @brief index for FS DB register in kvm segment */
#define FS_DB_IDX ((uint8_t)45)
/** @brief index for FS S register in kvm segment */
#define FS_S_IDX ((uint8_t)46)
/** @brief index for FS L register in kvm segment */
#define FS_L_IDX ((uint8_t)47)
/** @brief index for FS G register in kvm segment */
#define FS_G_IDX ((uint8_t)48)
/** @brief index for FS AVL register in kvm segment */
#define FS_AVL_IDX ((uint8_t)49)
/** @brief index for FS UNUSABLE register in kvm segment */
#define FS_UNUSABLE_IDX ((uint8_t)50)
/** @brief index for FS PADDING register in kvm segment */
#define FS_PADDING_IDX ((uint8_t)51)
/** @brief index for GS TYPE register in kvm segment */
#define GS_TYPE_IDX ((uint8_t)52)
/** @brief index for GS SELECTOR register in kvm segment */
#define GS_SELECTOR_IDX ((uint16_t)53)
/** @brief index for GS BASE register in kvm segment */
#define GS_BASE_IDX ((uint64_t)54)
/** @brief index for GS LIMIT register in kvm segment */
#define GS_LIMIT_IDX ((uint32_t)55)
/** @brief index for GS PRESENT register in kvm segment */
#define GS_PRESENT_IDX ((uint8_t)56)
/** @brief index for GS DPL register in kvm segment */
#define GS_DPL_IDX ((uint8_t)57)
/** @brief index for GS DB register in kvm segment */
#define GS_DB_IDX ((uint8_t)58)
/** @brief index for GS S register in kvm segment */
#define GS_S_IDX ((uint8_t)59)
/** @brief index for GS L register in kvm segment */
#define GS_L_IDX ((uint8_t)60)
/** @brief index for GS G register in kvm segment */
#define GS_G_IDX ((uint8_t)61)
/** @brief index for GS AVL register in kvm segment */
#define GS_AVL_IDX ((uint8_t)62)
/** @brief index for GS UNUSABLE register in kvm segment */
#define GS_UNUSABLE_IDX ((uint8_t)63)
/** @brief index for GS PADDING register in kvm segment */
#define GS_PADDING_IDX ((uint8_t)64)
/** @brief index for SS TYPE register in kvm segment */
#define SS_TYPE_IDX ((uint8_t)65)
/** @brief index for SS SELECTOR register in kvm segment */
#define SS_SELECTOR_IDX ((uint16_t)66)
/** @brief index for SS BASE register in kvm segment */
#define SS_BASE_IDX ((uint64_t)67)
/** @brief index for SS LIMIT register in kvm segment */
#define SS_LIMIT_IDX ((uint32_t)68)
/** @brief index for SS PRESENT register in kvm segment */
#define SS_PRESENT_IDX ((uint8_t)69)
/** @brief index for SS DPL register in kvm segment */
#define SS_DPL_IDX ((uint8_t)70)
/** @brief index for SS DB register in kvm segment */
#define SS_DB_IDX ((uint8_t)71)
/** @brief index for SS S register in kvm segment */
#define SS_S_IDX ((uint8_t)72)
/** @brief index for SS L register in kvm segment */
#define SS_L_IDX ((uint8_t)73)
/** @brief index for SS G register in kvm segment */
#define SS_G_IDX ((uint8_t)74)
/** @brief index for SS AVL register in kvm segment */
#define SS_AVL_IDX ((uint8_t)75)
/** @brief index for SS UNUSABLE register in kvm segment */
#define SS_UNUSABLE_IDX ((uint8_t)76)
/** @brief index for SS PADDING register in kvm segment */
#define SS_PADDING_IDX ((uint8_t)77)
/** @brief index for TR TYPE register in kvm segment */
#define TR_TYPE_IDX ((uint8_t)78)
/** @brief index for TR SELECTOR register in kvm segment */
#define TR_SELECTOR_IDX ((uint16_t)79)
/** @brief index for TR BASE register in kvm segment */
#define TR_BASE_IDX ((uint64_t)80)
/** @brief index for TR LIMIT register in kvm segment */
#define TR_LIMIT_IDX ((uint32_t)81)
/** @brief index for TR PRESENT register in kvm segment */
#define TR_PRESENT_IDX ((uint8_t)82)
/** @brief index for TR DPL register in kvm segment */
#define TR_DPL_IDX ((uint8_t)83)
/** @brief index for TR DB register in kvm segment */
#define TR_DB_IDX ((uint8_t)84)
/** @brief index for TR S register in kvm segment */
#define TR_S_IDX ((uint8_t)85)
/** @brief index for TR L register in kvm segment */
#define TR_L_IDX ((uint8_t)86)
/** @brief index for TR G register in kvm segment */
#define TR_G_IDX ((uint8_t)87)
/** @brief index for TR AVL register in kvm segment */
#define TR_AVL_IDX ((uint8_t)88)
/** @brief index for TR UNUSABLE register in kvm segment */
#define TR_UNUSABLE_IDX ((uint8_t)89)
/** @brief index for TR PADDING register in kvm segment */
#define TR_PADDING_IDX ((uint8_t)90)
/** @brief index for LDT TYPE register in kvm segment */
#define LDT_TYPE_IDX ((uint8_t)91)
/** @brief index for LDT SELECTOR register in kvm segment */
#define LDT_SELECTOR_IDX ((uint16_t)92)
/** @brief index for LDT BASE register in kvm segment */
#define LDT_BASE_IDX ((uint64_t)93)
/** @brief index for LDT LIMIT register in kvm segment */
#define LDT_LIMIT_IDX ((uint32_t)94)
/** @brief index for LDT PRESENT register in kvm segment */
#define LDT_PRESENT_IDX ((uint8_t)95)
/** @brief index for LDT DPL register in kvm segment */
#define LDT_DPL_IDX ((uint8_t)96)
/** @brief index for LDT DB register in kvm segment */
#define LDT_DB_IDX ((uint8_t)97)
/** @brief index for LDT S register in kvm segment */
#define LDT_S_IDX ((uint8_t)98)
/** @brief index for LDT L register in kvm segment */
#define LDT_L_IDX ((uint8_t)99)
/** @brief index for LDT G register in kvm segment */
#define LDT_G_IDX ((uint8_t)100)
/** @brief index for LDT AVL register in kvm segment */
#define LDT_AVL_IDX ((uint8_t)101)
/** @brief index for LDT UNUSABLE register in kvm segment */
#define LDT_UNUSABLE_IDX ((uint8_t)102)
/** @brief index for LDT PADDING register in kvm segment */
#define LDT_PADDING_IDX ((uint8_t)103)
/** @brief index for GDT LIMIT register in kvm dtable */
#define GDT_LIMIT_IDX ((uint16_t)104)
/** @brief index for GDT BASE register in kvm dtable */
#define GDT_BASE_IDX ((uint64_t)105)
/** @brief index for GDT PADDING 0 register in kvm dtable */
#define GDT_PADDING0_IDX ((uint16_t)106)
/** @brief index for GDT PADDING 1 register in kvm dtable */
#define GDT_PADDING1_IDX ((uint16_t)107)
/** @brief index for GDT PADDING 2 register in kvm dtable */
#define GDT_PADDING2_IDX ((uint16_t)108)
/** @brief index for IDT LIMIT register in kvm dtable */
#define IDT_LIMIT_IDX ((uint16_t)109)
/** @brief index for IDT BASE register in kvm dtable */
#define IDT_BASE_IDX ((uint64_t)110)
/** @brief index for IDT PADDING 0 register in kvm dtable */
#define IDT_PADDING0_IDX ((uint16_t)111)
/** @brief index for IDT PADDING 1 register in kvm dtable */
#define IDT_PADDING1_IDX ((uint16_t)112)
/** @brief index for IDT PADDING 2 register in kvm dtable */
#define IDT_PADDING2_IDX ((uint16_t)113)
/** @brief index for CR0 register in kvm sregs */
#define CR0_IDX ((uint64_t)114)
/** @brief index for CR2 register in kvm sregs */
#define CR2_IDX ((uint64_t)115)
/** @brief index for CR3 register in kvm sregs */
#define CR3_IDX ((uint64_t)116)
/** @brief index for CR4 register in kvm sregs */
#define CR4_IDX ((uint64_t)117)
/** @brief index for CR8 register in kvm sregs */
#define CR8_IDX ((uint64_t)118)
/** @brief index for EFER register in kvm sregs */
#define MSR_EFER_IDX ((uint64_t)119)
/** @brief index for APIC_BASE register in kvm sregs */
#define MSR_APIC_BASE_IDX ((uint64_t)120)
/** @brief stores the regs total number of entries for rdl */
#define TOTAL_SREGS_NUM_REG_ENTRIES ((uint64_t)119)
/** @brief stores the MSR total number of entries for rdl */
#define TOTAL_SREGS_NUM_MSR_ENTRIES ((uint64_t)2)

#ifdef __cplusplus
}
#endif

#endif
