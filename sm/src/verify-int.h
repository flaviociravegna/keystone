#include "page.h"
#include "enclave.h"

#if __riscv_xlen == 64
#define EYRIE_LOAD_START 0xffffffff00000000
#define RISCV_PT_INDEX_BITS 9
#define RISCV_PT_LEVELS 3
#define SATP_PPN_MASK 0x00000fffffffffff
#elif __riscv_xlen == 32
#define EYRIE_LOAD_START 0xf0000000
#define RISCV_PT_INDEX_BITS 10
#define RISCV_PT_LEVELS 2
#define SATP_PPN_MASK 0x003FFFFF
#endif

uintptr_t satp_to_pa(uintptr_t satp);