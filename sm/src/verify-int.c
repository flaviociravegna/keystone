//
// Created by flaviociravegna on 29/03/23.
//
#include "verify-int.h"

#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>

#include "crypto.h"
#include "enclave.h"
#include "page.h"
#include "sm-sbi.h"

#define SATP_PPN_MASK 0x00000fffffffffff

/*
static inline uintptr_t satp_to_pa(uintptr_t satp_val) {
  return (satp_val & ((1UL << RISCV_PGLEVEL_BITS) - 1)) << RISCV_PAGE_BITS;
}

void* get_root_page_table_address(struct enclave *enclave) {
        uintptr_t kernel_offset = enclave->params.runtime_entry - enclave->pa_params.runtime_base;
        uintptr_t root_pt_addr = satp_to_pa(enclave->encl_satp_remap) + kernel_offset;
        sbi_printf("\nPtr: 0x%lx\n", root_pt_addr);
        return (void*)root_pt_addr;
        return (void*)0xffffffffc0009000;
}

pte_t *pte_of_va(uintptr_t va, struct enclave *enclave) {
    // satp_new(kernel_va_to_pa(root_page_table))
    pte_t *t = (pte_t *)0xffffffffc0009000;
    sbi_printf("\nRPT: 0x%lx\n", *t);

    uintptr_t load_pa_start = enclave->pa_params.dram_base;
    int i;
    for (i = 1; i < RISCV_PT_LEVELS; i++) {
        size_t idx = RISCV_GET_PT_INDEX(va, i);

        if (!(t[idx] & PTE_V)) return 0;

        t = (pte_t *)__va(pte_ppn(t[idx]) << RISCV_PGSHIFT, load_pa_start);
    }

    return &t[RISCV_GET_PT_INDEX(va, 3)];
}
*/

void *pa_to_kernel_va(uintptr_t pa, uintptr_t kernel_offset) {
    return (void *)(pa + kernel_offset);
}

// The physical page number of the root page table
// is stored in the satp register’s PPN field
// [4.1.11 of the RISCV reference pdf]
// [4.3 of the RISCV reference pdf for Virt-Mem system]
uintptr_t satp_to_pa(uintptr_t satp) {
    uintptr_t ppn = satp & SATP_PPN_MASK;
    return (ppn << RISCV_PGSHIFT);
}
/*
pte_t *calculate_root_page_table(uintptr_t satp, uintptr_t kernel_offset) {
    uintptr_t target_pa = satp_to_pa(satp);
    void *target_va = pa_to_kernel_va(target_pa, kernel_offset);
    sbi_printf("\nKernel offset  : 0x%lx", kernel_offset);
    sbi_printf("\nRoot PT address: 0x%lx", (uintptr_t) target_va);
    return (pte_t *)target_va;
}

void traverse_page_table(pte_t *pt, uintptr_t kernel_offset) {
    for (int i = 0; i < 15; i++) {
        pte_t pte = pt[i];
        sbi_printf("ffff \n");
        uintptr_t pa = (uintptr_t)pt + i * RISCV_PGSIZE;
        sbi_printf("gggg \n");
        if (pte & PTE_V) {
            if (pte & PTE_R) {
                sbi_printf("\nVisiting page at phys addr 0x%lx", pa);
            } else {
                traverse_page_table((pte_t *)pa_to_kernel_va((pte & PTE_PPN_SHIFT) << RISCV_PAGE_BITS, kernel_offset), kernel_offset);
            }
        }
    }
}*/

/*
 * Iterate over PTEs and hash only the pages that are
 * in the eapp address space
 *
 * "runtime_kernel_size" defined in runtime/runtime.ld.S
 */
int walk_pt_and_hash(struct enclave *enclave, hash_ctx *ctx_x_pages, pte_t *tb, uintptr_t vaddr, int contiguous, int level) {
    uintptr_t phys_addr, va_start, vpn;  //, runtime_kernel_size = 8 * RISCV_PGSIZE;
    pte_t *walk, *end = tb + (RISCV_PGSIZE / sizeof(pte_t));
    int i, is_read_only, va_is_not_utm = 1;

    for (walk = tb, i = 0; walk < end; walk += 1, i++) {
        if (*walk == 0) {
            contiguous = 0;
            continue;
        }

        if (level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT)
            vpn = ((-1UL << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));
        else
            vpn = ((vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));

        va_start = vpn << RISCV_PGSHIFT;
        phys_addr = (*walk >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

        // And is not in the untrusted section
        va_is_not_utm &= !(va_start >= enclave->params.untrusted_ptr &&
                           va_start < (enclave->params.untrusted_ptr + enclave->params.untrusted_size));
        is_read_only = (*walk & PTE_R) && !(*walk & PTE_W);

        // if PTE is a leaf, read-only and not in UTM, extend hash for the page
        if (level == 1) {
            if ((va_is_not_utm && is_read_only) || 1) {
                hash_extend_page(ctx_x_pages, (void *)phys_addr);
                sbi_printf("\nPAGE hashed: [pa: 0x%lx, va: 0x%lx]\t", phys_addr, va_start);
                sbi_printf("Permissions: R:%d, W:%d, X:%d",
                           (*walk & PTE_R) > 0,
                           (*walk & PTE_W) > 0,
                           (*walk & PTE_X) > 0);
            }
        } else  // otherwise, recurse on a lower level
            contiguous = walk_pt_and_hash(enclave, ctx_x_pages, (pte_t *)phys_addr, vpn, contiguous, level - 1);
    }

    return 1;
}

void compute_eapp_hash(struct enclave *enclave, int at_runtime) {
    hash_ctx ctx_x_pages;
    int i;

    sbi_printf("[vaddr info]: \r\n\truntime: %lx\r\n\tuser: %lx\r\n\tuntrusted ptr: %lx\r\n\tuntrusted size: %lx\n\n",
            enclave->params.runtime_entry,
            enclave->params.user_entry,
            enclave->params.untrusted_ptr,
            enclave->params.untrusted_size);

    /*
        Supervisor Address Translation and Protection register
        has been updated at eyrie boot
    */
    enclave->encl_satp_remap = csr_read(satp);
    pte_t *new_pt = (pte_t *) satp_to_pa(enclave->encl_satp_remap);
    //uintptr_t kernel_offset = enclave->params.runtime_entry - enclave->pa_params.runtime_base;
    //traverse_page_table(new_pt, kernel_offset);

    hash_init(&ctx_x_pages);
    walk_pt_and_hash(enclave, &ctx_x_pages, new_pt, 0, 0, RISCV_PGLEVEL_TOP);
    hash_finalize(enclave->hash_eapp_actual, &ctx_x_pages);

    if (!at_runtime)
        for (i = 0; i < MDSIZE; i++)
            enclave->hash_eapp_initial[i] = enclave->hash_eapp_actual[i];

    uintptr_t count;
    sbi_printf("\nHash of EAPP pages: 0x");
    for (count = 0; count < sizeof enclave->hash_eapp_actual / sizeof(*enclave->hash_eapp_actual); count++)
        sbi_printf("%02x", enclave->hash_eapp_actual[count]);
    sbi_printf("\n");
}