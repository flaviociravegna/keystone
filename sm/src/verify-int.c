//
// Created by flaviociravegna on 29/03/23.
//
#include "enclave.h"
#include "crypto.h"
#include "page.h"
#include <sbi/sbi_console.h>
#include <sbi/riscv_asm.h>

typedef uintptr_t pte_t;

int walk_pt_and_hash(struct enclave *enclave, hash_ctx *ctx_x_pages, pte_t *tb, uintptr_t vaddr, int contiguous, int level) {
    uintptr_t phys_addr, va_start, vpn;
    pte_t *walk;
    int i;

    /*
     * Iterate over PTEs and hash only the pages that are
     * in EPM address space
     *
     * NB: the pages has already been validated before
     * i.e. this function will not be executed if the
     * validation in "validate_and_hash_epm" fails
    */
    for (walk = tb, i = 0; walk < tb + (RISCV_PGSIZE/sizeof(pte_t)); walk += 1, i++) {
        if (*walk == 0) {
            contiguous = 0;
            continue;
        }

        if ( level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT )
            vpn = ((-1UL << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));
        else
            vpn = ((vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));

        va_start = vpn << RISCV_PGSHIFT;
        phys_addr = (*walk >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

        int va_not_in_utm = !(va_start >= enclave->params.untrusted_ptr && va_start < (enclave->params.untrusted_ptr + enclave->params.untrusted_size));
        int is_executable = *walk & PTE_X;

        /* if PTE is a leaf, executable and not in UTM, extend hash for the page */
        if (level == 1) {
            if (va_not_in_utm && is_executable) {
                hash_extend_page(ctx_x_pages, (void *) phys_addr);
                //sbi_printf("PAGE hashed: 0x%lx\n", phys_addr);
            }
        } else /* otherwise, recurse on a lower level */
            contiguous = walk_pt_and_hash(enclave, ctx_x_pages, (pte_t*) phys_addr, vpn, contiguous, level - 1);
    }

    return 1;
}

void compute_rt_eapp_hash(struct enclave *enclave) {
    hash_ctx ctx_x_pages;

    hash_init(&ctx_x_pages);
    walk_pt_and_hash(enclave, &ctx_x_pages, (pte_t*) (enclave->encl_satp << RISCV_PGSHIFT), 0, 0, RISCV_PGLEVEL_TOP);
    hash_finalize(enclave->hash_runtime_and_eapp, &ctx_x_pages);

    uintptr_t count;
    sbi_printf("\nHash of 'X' pages: 0x");
    for(count = 0; count < sizeof enclave->hash_runtime_and_eapp/sizeof (*enclave->hash_runtime_and_eapp); count++)
        sbi_printf("%02x", enclave->hash_runtime_and_eapp[count]);
    sbi_printf("\n");

}