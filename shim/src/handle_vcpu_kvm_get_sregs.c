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

#include <debug.h>
#include <g_mut_hndl.h>
#include <kvm_sregs.h>
#include <kvm_sregs_idxs.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_sregs(
    struct shim_vcpu_t *const pmut_vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    struct mv_rdl_t *const pmut_reg_rdl = (struct mv_rdl_t *const)shared_page_for_current_pp();
    platform_expects(NULL != pmut_reg_rdl);

    struct mv_rdl_t *const pmut_msr_rdl = (struct mv_rdl_t *const)shared_page_for_current_pp();
    platform_expects(NULL != pmut_msr_rdl);

    pmut_reg_rdl->entries[ES_SELECTOR_IDX].reg = (uint16_t)mv_reg_t_es_selector;
    pmut_reg_rdl->entries[ES_TYPE_IDX].reg = (uint8_t)mv_reg_t_es_type;
    pmut_reg_rdl->entries[ES_LIMIT_IDX].reg = (uint32_t)mv_reg_t_es_limit;
    pmut_reg_rdl->entries[ES_BASE_IDX].reg = (uint64_t)mv_reg_t_es_base;
    pmut_reg_rdl->entries[ES_PRESENT_IDX].reg = (uint8_t)mv_reg_t_es_present;
    pmut_reg_rdl->entries[ES_DPL_IDX].reg = (uint8_t)mv_reg_t_es_dpl;
    pmut_reg_rdl->entries[ES_DB_IDX].reg = (uint8_t)mv_reg_t_es_db;
    pmut_reg_rdl->entries[ES_S_IDX].reg = (uint8_t)mv_reg_t_es_s;
    pmut_reg_rdl->entries[ES_L_IDX].reg = (uint8_t)mv_reg_t_es_l;
    pmut_reg_rdl->entries[ES_G_IDX].reg = (uint8_t)mv_reg_t_es_g;
    pmut_reg_rdl->entries[ES_AVL_IDX].reg = (uint8_t)mv_reg_t_es_avl;
    pmut_reg_rdl->entries[ES_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_es_unusable;
    pmut_reg_rdl->entries[ES_PADDING_IDX].reg = (uint8_t)mv_reg_t_es_padding;
    pmut_reg_rdl->entries[CS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_cs_selector;
    pmut_reg_rdl->entries[CS_TYPE_IDX].reg = (uint8_t)mv_reg_t_cs_type;
    pmut_reg_rdl->entries[CS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_cs_limit;
    pmut_reg_rdl->entries[CS_BASE_IDX].reg = (uint64_t)mv_reg_t_cs_base;
    pmut_reg_rdl->entries[CS_PRESENT_IDX].reg = (uint8_t)mv_reg_t_cs_present;
    pmut_reg_rdl->entries[CS_DPL_IDX].reg = (uint8_t)mv_reg_t_cs_dpl;
    pmut_reg_rdl->entries[CS_DB_IDX].reg = (uint8_t)mv_reg_t_cs_db;
    pmut_reg_rdl->entries[CS_S_IDX].reg = (uint8_t)mv_reg_t_cs_s;
    pmut_reg_rdl->entries[CS_L_IDX].reg = (uint8_t)mv_reg_t_cs_l;
    pmut_reg_rdl->entries[CS_G_IDX].reg = (uint8_t)mv_reg_t_cs_g;
    pmut_reg_rdl->entries[CS_AVL_IDX].reg = (uint8_t)mv_reg_t_cs_avl;
    pmut_reg_rdl->entries[CS_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_cs_unusable;
    pmut_reg_rdl->entries[CS_PADDING_IDX].reg = (uint8_t)mv_reg_t_cs_padding;
    pmut_reg_rdl->entries[DS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ds_selector;
    pmut_reg_rdl->entries[DS_TYPE_IDX].reg = (uint8_t)mv_reg_t_ds_type;
    pmut_reg_rdl->entries[DS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ds_limit;
    pmut_reg_rdl->entries[DS_BASE_IDX].reg = (uint64_t)mv_reg_t_ds_base;
    pmut_reg_rdl->entries[DS_PRESENT_IDX].reg = (uint8_t)mv_reg_t_ds_present;
    pmut_reg_rdl->entries[DS_DPL_IDX].reg = (uint8_t)mv_reg_t_ds_dpl;
    pmut_reg_rdl->entries[DS_DB_IDX].reg = (uint8_t)mv_reg_t_ds_db;
    pmut_reg_rdl->entries[DS_S_IDX].reg = (uint8_t)mv_reg_t_ds_s;
    pmut_reg_rdl->entries[DS_L_IDX].reg = (uint8_t)mv_reg_t_ds_l;
    pmut_reg_rdl->entries[DS_G_IDX].reg = (uint8_t)mv_reg_t_ds_g;
    pmut_reg_rdl->entries[DS_AVL_IDX].reg = (uint8_t)mv_reg_t_ds_avl;
    pmut_reg_rdl->entries[DS_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_ds_unusable;
    pmut_reg_rdl->entries[DS_PADDING_IDX].reg = (uint8_t)mv_reg_t_ds_padding;
    pmut_reg_rdl->entries[FS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_fs_selector;
    pmut_reg_rdl->entries[FS_TYPE_IDX].reg = (uint8_t)mv_reg_t_fs_type;
    pmut_reg_rdl->entries[FS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_fs_limit;
    pmut_reg_rdl->entries[FS_BASE_IDX].reg = (uint64_t)mv_reg_t_fs_base;
    pmut_reg_rdl->entries[FS_PRESENT_IDX].reg = (uint8_t)mv_reg_t_fs_present;
    pmut_reg_rdl->entries[FS_DPL_IDX].reg = (uint8_t)mv_reg_t_fs_dpl;
    pmut_reg_rdl->entries[FS_DB_IDX].reg = (uint8_t)mv_reg_t_fs_db;
    pmut_reg_rdl->entries[FS_S_IDX].reg = (uint8_t)mv_reg_t_fs_s;
    pmut_reg_rdl->entries[FS_L_IDX].reg = (uint8_t)mv_reg_t_fs_l;
    pmut_reg_rdl->entries[FS_G_IDX].reg = (uint8_t)mv_reg_t_fs_g;
    pmut_reg_rdl->entries[FS_AVL_IDX].reg = (uint8_t)mv_reg_t_fs_avl;
    pmut_reg_rdl->entries[FS_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_fs_unusable;
    pmut_reg_rdl->entries[FS_PADDING_IDX].reg = (uint8_t)mv_reg_t_fs_padding;
    pmut_reg_rdl->entries[GS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_gs_selector;
    pmut_reg_rdl->entries[GS_TYPE_IDX].reg = (uint8_t)mv_reg_t_gs_type;
    pmut_reg_rdl->entries[GS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_gs_limit;
    pmut_reg_rdl->entries[GS_BASE_IDX].reg = (uint64_t)mv_reg_t_gs_base;
    pmut_reg_rdl->entries[GS_PRESENT_IDX].reg = (uint8_t)mv_reg_t_gs_present;
    pmut_reg_rdl->entries[GS_DPL_IDX].reg = (uint8_t)mv_reg_t_gs_dpl;
    pmut_reg_rdl->entries[GS_DB_IDX].reg = (uint8_t)mv_reg_t_gs_db;
    pmut_reg_rdl->entries[GS_S_IDX].reg = (uint8_t)mv_reg_t_gs_s;
    pmut_reg_rdl->entries[GS_L_IDX].reg = (uint8_t)mv_reg_t_gs_l;
    pmut_reg_rdl->entries[GS_G_IDX].reg = (uint8_t)mv_reg_t_gs_g;
    pmut_reg_rdl->entries[GS_AVL_IDX].reg = (uint8_t)mv_reg_t_gs_avl;
    pmut_reg_rdl->entries[GS_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_gs_unusable;
    pmut_reg_rdl->entries[GS_PADDING_IDX].reg = (uint8_t)mv_reg_t_gs_padding;
    pmut_reg_rdl->entries[SS_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ss_selector;
    pmut_reg_rdl->entries[SS_TYPE_IDX].reg = (uint8_t)mv_reg_t_ss_type;
    pmut_reg_rdl->entries[SS_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ss_limit;
    pmut_reg_rdl->entries[SS_BASE_IDX].reg = (uint64_t)mv_reg_t_ss_base;
    pmut_reg_rdl->entries[SS_PRESENT_IDX].reg = (uint8_t)mv_reg_t_ss_present;
    pmut_reg_rdl->entries[SS_DPL_IDX].reg = (uint8_t)mv_reg_t_ss_dpl;
    pmut_reg_rdl->entries[SS_DB_IDX].reg = (uint8_t)mv_reg_t_ss_db;
    pmut_reg_rdl->entries[SS_S_IDX].reg = (uint8_t)mv_reg_t_ss_s;
    pmut_reg_rdl->entries[SS_L_IDX].reg = (uint8_t)mv_reg_t_ss_l;
    pmut_reg_rdl->entries[SS_G_IDX].reg = (uint8_t)mv_reg_t_ss_g;
    pmut_reg_rdl->entries[SS_AVL_IDX].reg = (uint8_t)mv_reg_t_ss_avl;
    pmut_reg_rdl->entries[SS_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_ss_unusable;
    pmut_reg_rdl->entries[SS_PADDING_IDX].reg = (uint8_t)mv_reg_t_ss_padding;
    pmut_reg_rdl->entries[LDT_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_ldt_selector;
    pmut_reg_rdl->entries[LDT_TYPE_IDX].reg = (uint64_t)mv_reg_t_ldt_type;
    pmut_reg_rdl->entries[LDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_ldt_limit;
    pmut_reg_rdl->entries[LDT_BASE_IDX].reg = (uint64_t)mv_reg_t_ldt_base;
    pmut_reg_rdl->entries[LDT_PRESENT_IDX].reg = (uint8_t)mv_reg_t_ldt_present;
    pmut_reg_rdl->entries[LDT_DPL_IDX].reg = (uint8_t)mv_reg_t_ldt_dpl;
    pmut_reg_rdl->entries[LDT_DB_IDX].reg = (uint8_t)mv_reg_t_ldt_db;
    pmut_reg_rdl->entries[LDT_S_IDX].reg = (uint8_t)mv_reg_t_ldt_s;
    pmut_reg_rdl->entries[LDT_L_IDX].reg = (uint8_t)mv_reg_t_ldt_l;
    pmut_reg_rdl->entries[LDT_G_IDX].reg = (uint8_t)mv_reg_t_ldt_g;
    pmut_reg_rdl->entries[LDT_AVL_IDX].reg = (uint8_t)mv_reg_t_ldt_avl;
    pmut_reg_rdl->entries[LDT_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_ldt_unusable;
    pmut_reg_rdl->entries[LDT_PADDING_IDX].reg = (uint8_t)mv_reg_t_ldt_padding;
    pmut_reg_rdl->entries[TR_SELECTOR_IDX].reg = (uint64_t)mv_reg_t_tr_selector;
    pmut_reg_rdl->entries[TR_TYPE_IDX].reg = (uint64_t)mv_reg_t_tr_type;
    pmut_reg_rdl->entries[TR_LIMIT_IDX].reg = (uint64_t)mv_reg_t_tr_limit;
    pmut_reg_rdl->entries[TR_BASE_IDX].reg = (uint64_t)mv_reg_t_tr_base;
    pmut_reg_rdl->entries[TR_PRESENT_IDX].reg = (uint8_t)mv_reg_t_tr_present;
    pmut_reg_rdl->entries[TR_DPL_IDX].reg = (uint8_t)mv_reg_t_tr_dpl;
    pmut_reg_rdl->entries[TR_DB_IDX].reg = (uint8_t)mv_reg_t_tr_db;
    pmut_reg_rdl->entries[TR_S_IDX].reg = (uint8_t)mv_reg_t_tr_s;
    pmut_reg_rdl->entries[TR_L_IDX].reg = (uint8_t)mv_reg_t_tr_l;
    pmut_reg_rdl->entries[TR_G_IDX].reg = (uint8_t)mv_reg_t_tr_g;
    pmut_reg_rdl->entries[TR_AVL_IDX].reg = (uint8_t)mv_reg_t_tr_avl;
    pmut_reg_rdl->entries[TR_UNUSABLE_IDX].reg = (uint8_t)mv_reg_t_tr_unusable;
    pmut_reg_rdl->entries[TR_PADDING_IDX].reg = (uint8_t)mv_reg_t_tr_padding;
    pmut_reg_rdl->entries[GDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_gdt_limit;
    pmut_reg_rdl->entries[GDT_BASE_IDX].reg = (uint64_t)mv_reg_t_gdt_base;
    pmut_reg_rdl->entries[GDT_PADDING0_IDX].reg = (uint8_t)mv_reg_t_gdt_padding0;
    pmut_reg_rdl->entries[GDT_PADDING1_IDX].reg = (uint8_t)mv_reg_t_gdt_padding1;
    pmut_reg_rdl->entries[GDT_PADDING2_IDX].reg = (uint8_t)mv_reg_t_gdt_padding2;
    pmut_reg_rdl->entries[IDT_LIMIT_IDX].reg = (uint64_t)mv_reg_t_idt_limit;
    pmut_reg_rdl->entries[IDT_BASE_IDX].reg = (uint64_t)mv_reg_t_idt_base;
    pmut_reg_rdl->entries[IDT_PADDING0_IDX].reg = (uint8_t)mv_reg_t_idt_padding0;
    pmut_reg_rdl->entries[IDT_PADDING1_IDX].reg = (uint8_t)mv_reg_t_idt_padding1;
    pmut_reg_rdl->entries[IDT_PADDING2_IDX].reg = (uint8_t)mv_reg_t_idt_padding2;
    pmut_reg_rdl->entries[CR0_IDX].reg = (uint64_t)mv_reg_t_cr0;
    pmut_reg_rdl->entries[CR2_IDX].reg = (uint64_t)mv_reg_t_cr2;
    pmut_reg_rdl->entries[CR3_IDX].reg = (uint64_t)mv_reg_t_cr3;
    pmut_reg_rdl->entries[CR4_IDX].reg = (uint64_t)mv_reg_t_cr4;
    pmut_reg_rdl->entries[CR8_IDX].reg = (uint64_t)mv_reg_t_cr8;

    pmut_msr_rdl->num_entries = TOTAL_SREGS_NUM_REG_ENTRIES;

    if (mv_vs_op_reg_get_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    pmut_msr_rdl->entries[MSR_EFER_IDX].reg = (uint64_t)mv_msr_t_efer;
    pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].reg = (uint64_t)mv_msr_t_apic_base;
    pmut_msr_rdl->num_entries = TOTAL_SREGS_NUM_MSR_ENTRIES;

    if (mv_vs_op_msr_get_list(g_mut_hndl, pmut_vcpu->vsid)) {
        bferror("ms_vs_op_msr_get_list failed");
        return SHIM_FAILURE;
    }

    pmut_args->es.selector = (uint16_t)pmut_reg_rdl->entries[ES_SELECTOR_IDX].val;
    pmut_args->es.type = (uint8_t)pmut_reg_rdl->entries[ES_TYPE_IDX].val;
    pmut_args->es.limit = (uint32_t)pmut_reg_rdl->entries[ES_LIMIT_IDX].val;
    pmut_args->es.base = pmut_reg_rdl->entries[ES_BASE_IDX].val;
    pmut_args->es.present = (uint8_t)pmut_reg_rdl->entries[ES_PRESENT_IDX].val;
    pmut_args->es.dpl = (uint8_t)pmut_reg_rdl->entries[ES_DPL_IDX].val;
    pmut_args->es.db = (uint8_t)pmut_reg_rdl->entries[ES_DB_IDX].val;
    pmut_args->es.s = (uint8_t)pmut_reg_rdl->entries[ES_S_IDX].val;
    pmut_args->es.l = (uint8_t)pmut_reg_rdl->entries[ES_L_IDX].val;
    pmut_args->es.g = (uint8_t)pmut_reg_rdl->entries[ES_G_IDX].val;
    pmut_args->es.avl = (uint8_t)pmut_reg_rdl->entries[ES_AVL_IDX].val;
    pmut_args->es.unusable = (uint8_t)pmut_reg_rdl->entries[ES_UNUSABLE_IDX].val;
    pmut_args->es.padding = (uint8_t)pmut_reg_rdl->entries[ES_PADDING_IDX].val;

    pmut_args->cs.selector = (uint16_t)pmut_reg_rdl->entries[CS_SELECTOR_IDX].val;
    pmut_args->cs.type = (uint8_t)pmut_reg_rdl->entries[CS_TYPE_IDX].val;
    pmut_args->cs.limit = (uint32_t)pmut_reg_rdl->entries[CS_LIMIT_IDX].val;
    pmut_args->cs.base = pmut_reg_rdl->entries[CS_BASE_IDX].val;
    pmut_args->cs.present = (uint8_t)pmut_reg_rdl->entries[CS_PRESENT_IDX].val;
    pmut_args->cs.dpl = (uint8_t)pmut_reg_rdl->entries[CS_DPL_IDX].val;
    pmut_args->cs.db = (uint8_t)pmut_reg_rdl->entries[CS_DB_IDX].val;
    pmut_args->cs.s = (uint8_t)pmut_reg_rdl->entries[CS_S_IDX].val;
    pmut_args->cs.l = (uint8_t)pmut_reg_rdl->entries[CS_L_IDX].val;
    pmut_args->cs.g = (uint8_t)pmut_reg_rdl->entries[CS_G_IDX].val;
    pmut_args->cs.avl = (uint8_t)pmut_reg_rdl->entries[CS_AVL_IDX].val;
    pmut_args->cs.unusable = (uint8_t)pmut_reg_rdl->entries[CS_UNUSABLE_IDX].val;
    pmut_args->cs.padding = (uint8_t)pmut_reg_rdl->entries[CS_PADDING_IDX].val;

    pmut_args->ds.selector = (uint16_t)pmut_reg_rdl->entries[DS_SELECTOR_IDX].val;
    pmut_args->ds.type = (uint8_t)pmut_reg_rdl->entries[DS_TYPE_IDX].val;
    pmut_args->ds.limit = (uint32_t)pmut_reg_rdl->entries[DS_LIMIT_IDX].val;
    pmut_args->ds.base = pmut_reg_rdl->entries[DS_BASE_IDX].val;
    pmut_args->ds.present = (uint8_t)pmut_reg_rdl->entries[DS_PRESENT_IDX].val;
    pmut_args->ds.dpl = (uint8_t)pmut_reg_rdl->entries[DS_DPL_IDX].val;
    pmut_args->ds.db = (uint8_t)pmut_reg_rdl->entries[DS_DB_IDX].val;
    pmut_args->ds.s = (uint8_t)pmut_reg_rdl->entries[DS_S_IDX].val;
    pmut_args->ds.l = (uint8_t)pmut_reg_rdl->entries[DS_L_IDX].val;
    pmut_args->ds.g = (uint8_t)pmut_reg_rdl->entries[DS_G_IDX].val;
    pmut_args->ds.avl = (uint8_t)pmut_reg_rdl->entries[DS_AVL_IDX].val;
    pmut_args->ds.unusable = (uint8_t)pmut_reg_rdl->entries[DS_UNUSABLE_IDX].val;
    pmut_args->ds.padding = (uint8_t)pmut_reg_rdl->entries[DS_PADDING_IDX].val;

    pmut_args->fs.selector = (uint16_t)pmut_reg_rdl->entries[FS_SELECTOR_IDX].val;
    pmut_args->fs.type = (uint8_t)pmut_reg_rdl->entries[FS_TYPE_IDX].val;
    pmut_args->fs.limit = (uint32_t)pmut_reg_rdl->entries[FS_LIMIT_IDX].val;
    pmut_args->fs.base = pmut_reg_rdl->entries[FS_BASE_IDX].val;
    pmut_args->fs.present = (uint8_t)pmut_reg_rdl->entries[FS_PRESENT_IDX].val;
    pmut_args->fs.dpl = (uint8_t)pmut_reg_rdl->entries[FS_DPL_IDX].val;
    pmut_args->fs.db = (uint8_t)pmut_reg_rdl->entries[FS_DB_IDX].val;
    pmut_args->fs.s = (uint8_t)pmut_reg_rdl->entries[FS_S_IDX].val;
    pmut_args->fs.l = (uint8_t)pmut_reg_rdl->entries[FS_L_IDX].val;
    pmut_args->fs.g = (uint8_t)pmut_reg_rdl->entries[FS_G_IDX].val;
    pmut_args->fs.avl = (uint8_t)pmut_reg_rdl->entries[FS_AVL_IDX].val;
    pmut_args->fs.unusable = (uint8_t)pmut_reg_rdl->entries[FS_UNUSABLE_IDX].val;
    pmut_args->fs.padding = (uint8_t)pmut_reg_rdl->entries[FS_PADDING_IDX].val;

    pmut_args->gs.selector = (uint16_t)pmut_reg_rdl->entries[GS_SELECTOR_IDX].val;
    pmut_args->gs.type = (uint8_t)pmut_reg_rdl->entries[GS_TYPE_IDX].val;
    pmut_args->gs.limit = (uint32_t)pmut_reg_rdl->entries[GS_LIMIT_IDX].val;
    pmut_args->gs.base = pmut_reg_rdl->entries[GS_BASE_IDX].val;
    pmut_args->gs.present = (uint8_t)pmut_reg_rdl->entries[GS_PRESENT_IDX].val;
    pmut_args->gs.dpl = (uint8_t)pmut_reg_rdl->entries[GS_DPL_IDX].val;
    pmut_args->gs.db = (uint8_t)pmut_reg_rdl->entries[GS_DB_IDX].val;
    pmut_args->gs.s = (uint8_t)pmut_reg_rdl->entries[GS_S_IDX].val;
    pmut_args->gs.l = (uint8_t)pmut_reg_rdl->entries[GS_L_IDX].val;
    pmut_args->gs.g = (uint8_t)pmut_reg_rdl->entries[GS_G_IDX].val;
    pmut_args->gs.avl = (uint8_t)pmut_reg_rdl->entries[GS_AVL_IDX].val;
    pmut_args->gs.unusable = (uint8_t)pmut_reg_rdl->entries[GS_UNUSABLE_IDX].val;
    pmut_args->gs.padding = (uint8_t)pmut_reg_rdl->entries[GS_PADDING_IDX].val;

    pmut_args->ss.selector = (uint16_t)pmut_reg_rdl->entries[SS_SELECTOR_IDX].val;
    pmut_args->ss.type = (uint8_t)pmut_reg_rdl->entries[SS_TYPE_IDX].val;
    pmut_args->ss.limit = (uint32_t)pmut_reg_rdl->entries[SS_LIMIT_IDX].val;
    pmut_args->ss.base = pmut_reg_rdl->entries[SS_BASE_IDX].val;
    pmut_args->ss.present = (uint8_t)pmut_reg_rdl->entries[SS_PRESENT_IDX].val;
    pmut_args->ss.dpl = (uint8_t)pmut_reg_rdl->entries[SS_DPL_IDX].val;
    pmut_args->ss.db = (uint8_t)pmut_reg_rdl->entries[SS_DB_IDX].val;
    pmut_args->ss.s = (uint8_t)pmut_reg_rdl->entries[SS_S_IDX].val;
    pmut_args->ss.l = (uint8_t)pmut_reg_rdl->entries[SS_L_IDX].val;
    pmut_args->ss.g = (uint8_t)pmut_reg_rdl->entries[SS_G_IDX].val;
    pmut_args->ss.avl = (uint8_t)pmut_reg_rdl->entries[SS_AVL_IDX].val;
    pmut_args->ss.unusable = (uint8_t)pmut_reg_rdl->entries[SS_UNUSABLE_IDX].val;
    pmut_args->ss.padding = (uint8_t)pmut_reg_rdl->entries[SS_PADDING_IDX].val;
    pmut_args->tr.selector = (uint16_t)pmut_reg_rdl->entries[TR_SELECTOR_IDX].val;
    pmut_args->tr.type = (uint8_t)pmut_reg_rdl->entries[TR_TYPE_IDX].val;
    pmut_args->tr.limit = (uint16_t)pmut_reg_rdl->entries[TR_LIMIT_IDX].val;
    pmut_args->tr.base = pmut_reg_rdl->entries[TR_BASE_IDX].val;
    pmut_args->tr.present = (uint8_t)pmut_reg_rdl->entries[TR_PRESENT_IDX].val;
    pmut_args->tr.dpl = (uint8_t)pmut_reg_rdl->entries[TR_DPL_IDX].val;
    pmut_args->tr.db = (uint8_t)pmut_reg_rdl->entries[TR_DB_IDX].val;
    pmut_args->tr.s = (uint8_t)pmut_reg_rdl->entries[TR_S_IDX].val;
    pmut_args->tr.l = (uint8_t)pmut_reg_rdl->entries[TR_L_IDX].val;
    pmut_args->tr.g = (uint8_t)pmut_reg_rdl->entries[TR_G_IDX].val;
    pmut_args->tr.avl = (uint8_t)pmut_reg_rdl->entries[TR_AVL_IDX].val;
    pmut_args->tr.unusable = (uint8_t)pmut_reg_rdl->entries[TR_UNUSABLE_IDX].val;
    pmut_args->tr.padding = (uint8_t)pmut_reg_rdl->entries[TR_PADDING_IDX].val;
    pmut_args->ldt.selector = (uint16_t)pmut_reg_rdl->entries[LDT_SELECTOR_IDX].val;
    pmut_args->ldt.type = (uint8_t)pmut_reg_rdl->entries[LDT_TYPE_IDX].val;
    pmut_args->ldt.limit = (uint32_t)pmut_reg_rdl->entries[LDT_LIMIT_IDX].val;
    pmut_args->ldt.base = pmut_reg_rdl->entries[LDT_BASE_IDX].val;
    pmut_args->ldt.present = (uint8_t)pmut_reg_rdl->entries[LDT_PRESENT_IDX].val;
    pmut_args->ldt.dpl = (uint8_t)pmut_reg_rdl->entries[LDT_DPL_IDX].val;
    pmut_args->ldt.db = (uint8_t)pmut_reg_rdl->entries[LDT_DB_IDX].val;
    pmut_args->ldt.s = (uint8_t)pmut_reg_rdl->entries[LDT_S_IDX].val;
    pmut_args->ldt.l = (uint8_t)pmut_reg_rdl->entries[LDT_L_IDX].val;
    pmut_args->ldt.g = (uint8_t)pmut_reg_rdl->entries[LDT_G_IDX].val;
    pmut_args->ldt.avl = (uint8_t)pmut_reg_rdl->entries[LDT_AVL_IDX].val;
    pmut_args->ldt.unusable = (uint8_t)pmut_reg_rdl->entries[LDT_UNUSABLE_IDX].val;
    pmut_args->ldt.padding = (uint8_t)pmut_reg_rdl->entries[LDT_PADDING_IDX].val;

    pmut_args->gdt.limit = (uint16_t)pmut_reg_rdl->entries[GDT_LIMIT_IDX].val;
    pmut_args->gdt.base = pmut_reg_rdl->entries[GDT_BASE_IDX].val;
    pmut_args->gdt.padding[0] = (uint16_t)pmut_reg_rdl->entries[GDT_PADDING0_IDX].val;
    pmut_args->gdt.padding[1] = (uint16_t)pmut_reg_rdl->entries[GDT_PADDING1_IDX].val;
    pmut_args->gdt.padding[2] = (uint16_t)pmut_reg_rdl->entries[GDT_PADDING2_IDX].val;

    pmut_args->idt.limit = (uint16_t)pmut_reg_rdl->entries[IDT_LIMIT_IDX].val;
    pmut_args->idt.base = pmut_reg_rdl->entries[IDT_BASE_IDX].val;
    pmut_args->idt.padding[0] = (uint16_t)pmut_reg_rdl->entries[IDT_PADDING0_IDX].val;
    pmut_args->idt.padding[1] = (uint16_t)pmut_reg_rdl->entries[IDT_PADDING1_IDX].val;
    pmut_args->idt.padding[2] = (uint16_t)pmut_reg_rdl->entries[IDT_PADDING2_IDX].val;

    pmut_args->cr0 = pmut_reg_rdl->entries[CR0_IDX].val;
    pmut_args->cr2 = pmut_reg_rdl->entries[CR2_IDX].val;
    pmut_args->cr3 = pmut_reg_rdl->entries[CR3_IDX].val;
    pmut_args->cr4 = pmut_reg_rdl->entries[CR4_IDX].val;
    pmut_args->cr8 = pmut_reg_rdl->entries[CR8_IDX].val;
    pmut_args->efer = pmut_msr_rdl->entries[MSR_EFER_IDX].val;
    pmut_args->apic_base = pmut_msr_rdl->entries[MSR_APIC_BASE_IDX].val;

    return SHIM_SUCCESS;
}
