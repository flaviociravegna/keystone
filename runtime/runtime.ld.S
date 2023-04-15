#include "mm/vm_defs.h"

OUTPUT_ARCH( "riscv" )

SECTIONS
{
  . = 0xffffffffc0000000;
  PROVIDE(rt_base = .);
  .text : {
    PROVIDE(rt_text_start = .);
    *(.text._start)
    *(.text.encl_trap_handler)
    *(.text)
    PROVIDE(rt_text_end = .);
  }
  . = ALIGN(RISCV_PAGE_SIZE);
  .rodata :
  {
    PROVIDE(rt_rodata_start = .);
    *(.rdata)
    *(.rodata)
    PROVIDE(rt_rodata_end = .);
  }
  . = ALIGN(RISCV_PAGE_SIZE);
  .data : { *(.data) }
  .bss : { *(.bss) }
  . = ALIGN(RISCV_PAGE_SIZE);
  .kernel_stack : {
    . += 8 * RISCV_PAGE_SIZE;
    PROVIDE(kernel_stack_end = .);
  }

  _end = .;
}
