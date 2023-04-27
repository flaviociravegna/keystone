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

// The physical page number of the root page table
// is stored in the satp register’s PPN field
// [4.1.11 of the RISCV reference pdf]
// [4.3 of the RISCV reference pdf for Virt-Mem system]
uintptr_t satp_to_pa(uintptr_t satp) {
    uintptr_t ppn = satp & SATP_PPN_MASK;
    return (ppn << RISCV_PGSHIFT);
}

/*
 * Iterate over PTEs and hash only the pages that are
 * in the eapp address space
 *
 * "runtime_kernel_size" defined in runtime/runtime.ld.S
 */
int walk_pt_and_hash(struct enclave *enclave, hash_ctx *ctx_x_pages, pte_t *tb, uintptr_t vaddr, int contiguous, int level, int at_runtime) {
    uintptr_t phys_addr, va_start, vpn, runtime_size;
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
            if ((va_is_not_utm && is_read_only)) {
                runtime_size = enclave->pa_params.user_base - enclave->pa_params.runtime_base;
                // The kernel is remapped at Eyrie boot, and then the entire memory is mapped.
                // So, in order to not measure two times the same runtime pages, filter them 
                // and consider only the addresses "remapped" by the Eyrie kernel
                if (!at_runtime || !(va_start >= enclave->params.runtime_entry && va_start < enclave->params.runtime_entry + runtime_size)) {
                    hash_extend_page(ctx_x_pages, (void *)phys_addr);
                    sbi_printf("\nPAGE hashed: [pa: 0x%lx, va: 0x%lx]\t", phys_addr, va_start);
                    sbi_printf("Permissions: R:%d, W:%d, X:%d",
                        (*walk & PTE_R) > 0,
                        (*walk & PTE_W) > 0,
                        (*walk & PTE_X) > 0);
                }
            }
        } else  // otherwise, recurse on a lower level
            contiguous = walk_pt_and_hash(enclave, ctx_x_pages, (pte_t *)phys_addr, vpn, contiguous, level - 1, at_runtime);
    }

    return 1;
}

void compute_eapp_hash(struct enclave *enclave, int at_runtime) {
    hash_ctx ctx_x_pages;
    int i;

    /*
        Supervisor Address Translation and Protection register
        has been updated at eyrie boot
    */
    enclave->encl_satp_remap = csr_read(satp);
    pte_t *new_pt = at_runtime ? (pte_t *) satp_to_pa(enclave->encl_satp_remap) : (pte_t *) satp_to_pa(enclave->encl_satp);

    hash_init(&ctx_x_pages);
    walk_pt_and_hash(enclave, &ctx_x_pages, new_pt, 0, 0, RISCV_PGLEVEL_TOP, at_runtime);
    hash_finalize(enclave->hash_rt_eapp_actual, &ctx_x_pages);

    if (!at_runtime)
        for (i = 0; i < MDSIZE; i++)
            enclave->hash_rt_eapp_initial[i] = enclave->hash_rt_eapp_actual[i];

    uintptr_t count;
    sbi_printf("\nHash of Runtime & EAPP pages: 0x");
    for (count = 0; count < sizeof enclave->hash_rt_eapp_actual / sizeof(*enclave->hash_rt_eapp_actual); count++)
        sbi_printf("%02x", enclave->hash_rt_eapp_actual[count]);
    sbi_printf("\n");
}