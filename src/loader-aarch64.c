#include "loader.h"

LOADER_SECTION(entry)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader() {
  // System V AArch64 ABI:
  //   (x0, x1) <- function(x0, x1, x2, x3, x4, x5, x6, x7)
  // Loader Register ABI
  //   x19: loader base for munmap, set by loader_loader()
  //   x20: loader size for munmap
  //   x21: at_execfn for restoring
  //   x22: total mmap range for PIE elf, 0 for non PIE elf
  //   x23: loader_reg_flags_t
  __asm__ volatile(
      "mov x0, sp;"   // param
      "mov x1, x22;"  // total_memsz for PIE elf
      "mov x2, x23;"  // loader_reg_flags_t
      "bl loader_main;"
      "tbnz x0, #63, restore;"  // fail with -errno in rax

      // Move [rsp, rsp + sz) to [new_sp, new_sp + sz), assume new_sp < sp
      "mov x3, sp;"                  // src
      "ldr x2, [x3, #%c[reg_off]];"  // dst
      "mov sp, x2;"

      "add x0, x0, #15;"  // move 16 bytes each time
      "bic x0, x0, #15;"
      "1:;"
      "ldp x4, x5, [x3], #16;"
      "stp x4, x5, [x2], #16;"
      "subs x0, x0, #16;"
      "b.gt 1b;"

      "mov x0, sp;"  // x1 is still ld_dir
      "bl loader_fix_stack;"

      "mov x8, %[munmap];"
      "mov x0, x19;"  // loader base
      "mov x1, x20;"  // loader size

      ".global trap_ok_marker;"
      "trap_ok_marker:"
      "brk #0x3039; svc #0; udf #0x3039;"

      "restore:"
      "brk #0x3065; svc #0; udf #0x3065;"
      :
      : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP))
      : "memory");
}
