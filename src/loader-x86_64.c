#include "loader.h"

LOADER_SECTION(entry)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader() {
  // System V X64 ABI:
  //   (rax, rdx) <- function(rdi, rsi, rdx, rcx, r8, r9)
  //  Loader Register ABI:
  //    rbx: loader base for munmap, set by loader_loader()
  //    rbp: loader size for munmap
  //    r12: at_execfn for restoring
  //    r13: total mmap range for PIE elf, 0 for non PIE elf
  //    r14: loader_reg_flags_t
  __asm__ volatile(
      "mov %%rsp, %%rdi;"  // param
      "mov %%r13, %%rsi;"  // total_memsz for PIE elf
      "mov %%r14, %%rdx;"  // loader_reg_flags_t
      "call loader_main;"  // now r13, r14 can be dropped
      "test %%rax, %%rax;"
      "js restore;"  // fail with -errno in rax

      // Move [rsp, rsp + sz) to [new_sp, new_sp + sz), assume new_sp < sp
      // On the return of execve, the DF must be 0.
      "mov %%rax, %%rcx;"
      "mov %%rsp, %%rsi;"
      "movq %c[reg_off](%%rsp), %%rdi;"
      "movq %c[reg_off](%%rsp), %%rsp;"
      "rep movsb;"  // move with ERMS

      "mov %%rsp, %%rdi;"  // ld_dir is already in rdx
      "call loader_fix_stack;"

      "mov %[munmap], %%rax;"
      "mov %%rbx, %%rdi;"  // loader base
      "mov %%rbp, %%rsi;"  // loader filesz

      "int3;"
      ".global trap_ok_marker;"
      "trap_ok_marker:"
      "syscall; ud2; ud2; .2byte 0x3039;"  // munmap, and no return

      "restore:"
      "int3;"
      "syscall; ud2; ud2; .2byte 0x3065;"  // mark of restoring via execve()
      :
      : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP))
      : "memory");
}
