#ifndef _MM_H_
#define _MM_H_
#include <stddef.h>
#include <stdint.h>

#include "mm/vm_defs.h"

uintptr_t translate(uintptr_t va);
pte* pte_of_va(uintptr_t va);
#ifdef USE_FREEMEM

#if __riscv_xlen == 64
# define RISCV_PGTABLE_HIGHEST_BIT 0x100
# define RISCV_PGLEVEL_MASK 0x1ff
#elif __riscv_xlen == 32
# define RISCV_PGTABLE_HIGHEST_BIT 0x300
# define RISCV_PGLEVEL_MASK 0x3ff
#endif

#define VA_BITS 39
#define RISCV_PGLEVEL_TOP ((VA_BITS - RISCV_PAGE_BITS)/RISCV_PT_INDEX_BITS)

uintptr_t alloc_page(uintptr_t vpn, int flags);
void free_page(uintptr_t vpn);
size_t alloc_pages(uintptr_t vpn, size_t count, int flags);
void free_pages(uintptr_t vpn, size_t count);
size_t test_va_range(uintptr_t vpn, size_t count);

uintptr_t get_program_break();
void set_program_break(uintptr_t new_break);

void map_with_reserved_page_table(uintptr_t base, uintptr_t size, uintptr_t ptr, pte* l2_pt, pte* l3_pt);
void modify_eapp_pte_permissions();
#endif /* USE_FREEMEM */

#endif /* _MM_H_ */
