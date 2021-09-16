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

#ifndef KVM_SREGS_H
#define KVM_SREGS_H

#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @struct kvm_sregs
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_sregs
    {
        /** @brief stores that value of the cs segment register */
        struct kvm_segment cs;
        /** @brief stores that value of the ds segment register */
        struct kvm_segment ds;
        /** @brief stores that value of the es segment register */
        struct kvm_segment es;
        /** @brief stores that value of the fs segment register */
        struct kvm_segment fs;
        /** @brief stores that value of the gs segment register */
        struct kvm_segment gs;
        /** @brief stores that value of the ss segment register */
        struct kvm_segment ss;
        /** @brief stores that value of the tr segment register */
        struct kvm_segment tr;
        /** @brief stores that value of the ldt segment register */
        struct kvm_segment ldt;
        /** @brief stores that value of the gdt dtable register */
        struct kvm_dtable gdt;
        /** @brief stores that value of the gdt dtable register */
        struct kvm_dtable idt;
        /** @brief stores that value of the cr0 register */
        uint64_t cr0;
        /** @brief stores that value of the cr2 register */
        uint64_t cr2;
        /** @brief stores that value of the cr3 register */
        uint64_t cr3;
        /** @brief stores that value of the cr4 register */
        uint64_t cr4;
        /** @brief stores that value of the cr8 register */
        uint64_t cr8;
        /** @brief stores that value of the efer register */
        uint64_t efer;
        /** @brief stores that value of the apic_base register */
        uint64_t apic_base;
        /** @brief stores that value of the interrupt bitmap */
        uint64_t interrupt_bitmap[4];
    };

#ifdef __cplusplus
}
#endif

#endif
