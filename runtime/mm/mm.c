#include "util/rt_util.h"
#include "mm/common.h"
#include "call/syscall.h"
#include "mm/mm.h"
#include "mm/freemem.h"
#include "mm/paging.h"
#include "mm/vm.h"

#ifdef USE_FREEMEM

/* Page table utilities */
static pte*
__walk_create(pte* root, uintptr_t addr);

/* Hacky storage of current u-mode break */
static uintptr_t current_program_break;

uintptr_t get_program_break(){
  return current_program_break;
}

void set_program_break(uintptr_t new_break){
  current_program_break = new_break;
}

static pte*
__continue_walk_create(pte* root, uintptr_t addr, pte* pte)
{
  uintptr_t new_page = spa_get_zero();
  assert(new_page);

  unsigned long free_ppn = ppn(__pa(new_page));
  *pte = ptd_create(free_ppn);
  return __walk_create(root, addr);
}

static pte*
__walk_internal(pte* root, uintptr_t addr, int create)
{
  pte* t = root;
  int i;
  for (i = 1; i < RISCV_PT_LEVELS; i++)
  {
    size_t idx = RISCV_GET_PT_INDEX(addr, i);
    if (!(t[idx] & PTE_V)) {
      return create ? __continue_walk_create(root, addr, &t[idx]) : 0;
    }

    t = (pte*) __va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
  }

  //printf("\nT final: %lx", t[RISCV_GET_PT_INDEX(addr, 3)]);
  return &t[RISCV_GET_PT_INDEX(addr, 3)];
}

/* walk the page table and return PTE
 * return 0 if no mapping exists */
static pte*
__walk(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 0);
}

/* walk the page table and return PTE
 * create the mapping if non exists */
static pte*
__walk_create(pte* root, uintptr_t addr)
{
  return __walk_internal(root, addr, 1);
}


/* allocate a new page to a given vpn
 * returns VA of the page, (returns 0 if fails) */
uintptr_t
alloc_page(uintptr_t vpn, int flags)
{
  uintptr_t page;
  pte* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS);

  assert(flags & PTE_U);

  if (!pte)
    return 0;

	/* if the page has been already allocated, return the page */
  if(*pte & PTE_V) {
    return __va(*pte << RISCV_PAGE_BITS);
  }

	/* otherwise, allocate one from the freemem */
  page = spa_get_zero();
  assert(page);

  *pte = pte_create(ppn(__pa(page)), flags | PTE_V);
#ifdef USE_PAGING
  paging_inc_user_page();
#endif

  return page;
}

void
free_page(uintptr_t vpn){

  pte* pte = __walk(root_page_table, vpn << RISCV_PAGE_BITS);

  // No such PTE, or invalid
  if(!pte || !(*pte & PTE_V))
    return;

  assert(*pte & PTE_U);

  uintptr_t ppn = pte_ppn(*pte);
  // Mark invalid
  // TODO maybe do more here
  *pte = 0;

#ifdef USE_PAGING
  paging_dec_user_page();
#endif
  // Return phys page
  spa_put(__va(ppn << RISCV_PAGE_BITS));

  return;

}

/* allocate n new pages from a given vpn
 * returns the number of pages allocated */
size_t
alloc_pages(uintptr_t vpn, size_t count, int flags)
{
  unsigned int i;
  for (i = 0; i < count; i++) {
    if(!alloc_page(vpn + i, flags))
      break;
  }

  return i;
}

void
free_pages(uintptr_t vpn, size_t count){
  unsigned int i;
  for (i = 0; i < count; i++) {
    free_page(vpn + i);
  }

}

/*
 * Check if a range of VAs contains any allocated pages, starting with
 * the given VA. Returns the number of sequential pages that meet the
 * conditions.
 */
size_t
test_va_range(uintptr_t vpn, size_t count){

  unsigned int i;
  /* Validate the region */
  for (i = 0; i < count; i++) {
    pte* pte = __walk_internal(root_page_table, (vpn+i) << RISCV_PAGE_BITS, 0);
    // If the page exists and is valid then we cannot use it
    if(pte && *pte){
      break;
    }
  }
  return i;
}

/* get a mapped physical address for a VA */
uintptr_t
translate(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);

  if(pte && (*pte & PTE_V))
    return (pte_ppn(*pte) << RISCV_PAGE_BITS) | (RISCV_PAGE_OFFSET(va));
  else
    return 0;
}

/* try to retrieve PTE for a VA, return 0 if fail */
pte*
pte_of_va(uintptr_t va)
{
  pte* pte = __walk(root_page_table, va);
  return pte;
}


/*****************************************/

pte* get_old_pte_from_va(uintptr_t va) {
  /*
  uintptr_t vpn[RISCV_PT_LEVELS];
  uintptr_t pte_offset[RISCV_PT_LEVELS];
  uintptr_t pt_base = (uintptr_t)EYRIE_LOAD_START;

  vpn[0] = addr >> RISCV_PAGE_BITS & RISCV_PGLEVEL_MASK;
  vpn[1] = addr >> (RISCV_PAGE_BITS + RISCV_PT_INDEX_BITS) & RISCV_PGLEVEL_MASK;
  if (RISCV_PT_LEVELS == 3)
    vpn[2] = addr >> (RISCV_PAGE_BITS + (2 * RISCV_PT_INDEX_BITS)) & RISCV_PGLEVEL_MASK;  

  // calculate offsets for the page table levels
  pte_offset[0] = (pt_base + vpn[RISCV_PT_LEVELS - 1] * PTESIZE) & 0xfffffffffff00000UL;
  //if (!((uintptr_t)pte_offset[0] & PTE_V)) return 0;
  
  if (RISCV_PT_LEVELS == 3) {
    pte_offset[1] = ((uintptr_t)pte_offset[0] + vpn[1] * PTESIZE);
      //if (!((uintptr_t)pte_offset[0] & PTE_V)) return 0;

    pte_offset[2] = ((uintptr_t)pte_offset[1] + vpn[0] * PTESIZE);
  } else
    pte_offset[1] = ((uintptr_t)pte_offset[0] + vpn[0] * PTESIZE);
  
  // extract the page table entry pointer from the offset
  return (pte *)((uintptr_t)pte_offset[RISCV_PT_LEVELS - 1] + (addr & (RISCV_PAGE_SIZE - 1) >> 2));*/
  pte *pt = (pte *)EYRIE_LOAD_START;
  int level;

  for (level = RISCV_PT_LEVELS - 1; level >= 0; level--) {
    uintptr_t index = (va >> (RISCV_PAGE_BITS + level * RISCV_PT_INDEX_BITS)) & RISCV_PGLEVEL_MASK;
    printf("\nIndex: 0x%lx", index, (uintptr_t)pt + index);
    pte entry = pt[index];
    printf(", entry: 0x%lx", entry);
    //if ((entry & PTE_V) == 0) return 0;
    
    pt = (pte *)(entry & ~(RISCV_PGLEVEL_MASK));
  }

  return &pt[(va >> RISCV_PAGE_BITS) & RISCV_PGLEVEL_MASK];
}

int walk_old_pt_and_update(pte *tb, uintptr_t vaddr, int contiguous, int level) {
    uintptr_t phys_addr, va_start, vpn;
    pte *walk, *end = tb + (RISCV_PAGE_SIZE / sizeof(pte));
    int i;
    
    for (walk = tb, i = 0; walk < end; walk += 1, i++) {
        //The runtime can only access virtual addresses
        uintptr_t *walk_virt = (uintptr_t *)__va((uintptr_t)walk);
        //printf("\nWalk: [v: 0x%lx, p: 0x%lx]", walk_virt, walk);
        if (*walk_virt == 0) {
            contiguous = 0;
            continue;
        }

        if (level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT)
            vpn = ((-1UL << RISCV_PT_INDEX_BITS) | (i & RISCV_PGLEVEL_MASK));
        else
            vpn = ((vaddr << RISCV_PT_INDEX_BITS) | (i & RISCV_PGLEVEL_MASK));

        va_start = vpn << RISCV_PAGE_BITS;
        phys_addr = (*walk_virt >> PTE_PPN_SHIFT) << RISCV_PAGE_BITS;

        if (level == 1) {
          if (phys_addr >= eapp_pa_start && phys_addr < __pa(freemem_va_start)) {
            pte *entry = pte_of_va(va_start);
            if (entry != 0) {
              // Retrieve the permissions of the eapp, defined by the user
              int is_r = (*walk_virt & PTE_R) > 0;
              int is_w = (*walk_virt & PTE_W) > 0;
              int is_x = (*walk_virt & PTE_X) > 0;

              // now set these permissions to the related page table entry
              // defined by the runtime
              *entry &= ~((uintptr_t)(PTE_R | PTE_W | PTE_X));
              if (is_r) *entry |= PTE_R;
              if (is_w) *entry |= PTE_W;
              if (is_x) *entry |= PTE_X;

              /*
              printf("\nAddr: [v: 0x%lx, p: 0x%lx], Permissions: R:%d, W:%d, X:%d, old_pte: [a: 0x%lx, pte: 0x%lx]",
              va_start, phys_addr,
              (*entry & PTE_R) > 0,
              (*entry & PTE_W) > 0,
              (*entry & PTE_X) > 0,
              walk_virt, *walk_virt);*/

              //pte *old_e = get_old_pte_from_va(va_start);
              //printf("\nRetrieved pte: [a: 0x%lx, pte: 0x%lx]]\n****************************************************\n", old_e, *old_e);
            }
          }
        } else  // otherwise, recurse on a lower level
            contiguous = walk_old_pt_and_update((pte *)phys_addr, vpn, contiguous, level - 1);
    }

    return 1;
}

void modify_eapp_pte_permissions() {
  walk_old_pt_and_update((pte *)__pa(EYRIE_LOAD_START), 0, 0, RISCV_PGLEVEL_TOP);
}


/******************************************/

void
set_leaf_level(uintptr_t dram_base,
              uintptr_t dram_size,
              uintptr_t ptr,
              uintptr_t leaf_level,
              pte* leaf_pt)
{
  uintptr_t offset = 0;
  uintptr_t freemem_pa_start = __pa(freemem_va_start);
  
  for (offset = 0; offset < dram_size; offset += RISCV_GET_LVL_PGSIZE(leaf_level)) {
      uintptr_t actual_pa = dram_base + offset;
      uintptr_t actual_va_kernel = actual_pa + kernel_offset;
      int flags = 0;

      // order of physical addresses (low -> high):
      // runtime | eapp | free      
      if (actual_pa < eapp_pa_start) {
        // Runtime addresses
        if (actual_va_kernel >= runtime_va_text_start && actual_va_kernel < runtime_va_text_end)
          flags = PTE_R | PTE_X | PTE_A | PTE_D;
        else if (actual_va_kernel >= runtime_va_rodata_start && actual_va_kernel < runtime_va_rodata_end)
          flags = PTE_R | PTE_A | PTE_D;
        else
          flags = PTE_R | PTE_W | PTE_A | PTE_D;
      } else if (actual_pa < freemem_pa_start) {
          // EAPP addresses
          // TODO: modify the entry correctly here
          /*pte *entry_old_root_pt = get_old_pte_from_va(__va(actual_pa));
          if (entry_old_root_pt == 0)
            printf("\n ZERO");
          else {
            printf("\nEntry found! ");
            printf("\nAddr: [v: 0x%lx, p: 0x%lx], Addr pte: 0x%lx",
              __va(actual_pa), actual_pa, entry_old_root_pt);
            printf(", Permissions: R:%d, W:%d, X:%d",
              (*entry_old_root_pt & PTE_R) > 0,
              (*entry_old_root_pt & PTE_W) > 0,
              (*entry_old_root_pt & PTE_X) > 0);
          }*/
          flags = PTE_R | PTE_W | PTE_A | PTE_D;
      } else
          flags = PTE_R | PTE_W | PTE_A | PTE_D;  // Free memory addresses

      leaf_pt[RISCV_GET_PT_INDEX(ptr + offset, leaf_level)] = pte_create(ppn(actual_pa), flags);
  }
}

void
__map_with_reserved_page_table_32(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt)
{
  uintptr_t leaf_level = 2;
  pte* leaf_pt = l2_pt;
  unsigned long dram_max =  RISCV_GET_LVL_PGSIZE(leaf_level - 1);

  /* use megapage if l2_pt is null */
  if (!l2_pt) {
    leaf_level = 1;
    leaf_pt = root_page_table;
    dram_max = -1UL; 
  }

  assert(dram_size <= dram_max);
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  if(l2_pt) {
       /* set root page table entry */
       root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] =
       ptd_create(ppn(kernel_va_to_pa(l2_pt)));
  }

  /* set leaf level */
  set_leaf_level(dram_base, dram_size, ptr, leaf_level, leaf_pt);

}

void
__map_with_reserved_page_table_64(uintptr_t dram_base,
                               uintptr_t dram_size,
                               uintptr_t ptr,
                               pte* l2_pt,
                               pte* l3_pt)
{
  uintptr_t leaf_level = 3;
  pte* leaf_pt = l3_pt;
  /* use megapage if l3_pt is null */
  if (!l3_pt) {
    leaf_level = 2;
    leaf_pt = l2_pt;
  }
  assert(dram_size <= RISCV_GET_LVL_PGSIZE(leaf_level - 1));
  assert(IS_ALIGNED(dram_base, RISCV_GET_LVL_PGSIZE_BITS(leaf_level)));
  assert(IS_ALIGNED(ptr, RISCV_GET_LVL_PGSIZE_BITS(leaf_level - 1)));

  /* set root page table entry */
  root_page_table[RISCV_GET_PT_INDEX(ptr, 1)] = ptd_create(ppn(kernel_va_to_pa(l2_pt)));

  /* set L2 if it's not leaf */
  if (leaf_pt != l2_pt) {
    l2_pt[RISCV_GET_PT_INDEX(ptr, 2)] =
      ptd_create(ppn(kernel_va_to_pa(l3_pt)));
  }

  /* set leaf level */
  set_leaf_level(dram_base, dram_size, ptr, leaf_level, leaf_pt);
}

void
map_with_reserved_page_table(uintptr_t dram_base,
                             uintptr_t dram_size,
                             uintptr_t ptr,
                             pte* l2_pt,
                             pte* l3_pt)
{
  #if __riscv_xlen == 64
  if (dram_size > RISCV_GET_LVL_PGSIZE(2))
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, 0);
  else
    __map_with_reserved_page_table_64(dram_base, dram_size, ptr, l2_pt, l3_pt);
  #elif __riscv_xlen == 32
  if (dram_size > RISCV_GET_LVL_PGSIZE(1))
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, 0);
  else
    __map_with_reserved_page_table_32(dram_base, dram_size, ptr, l2_pt);
  #endif
}

#endif /* USE_FREEMEM */
