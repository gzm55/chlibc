#include "loader.h"

// syscall:   rax       <- rax(rdi, rsi, rdx, r10, r8, r9)
// function:  rax       <- rax(rdi, rsi, rdx, rcx, r8, r9)
//           (rax, rdx) <- rax(rdi, rsi, rdx, rcx, r8, r9)
// callee-saved: rbx, rbp, r12, r13, r14, r15

// Prepares registers and load segments for loader().
// On EVENT_EXEC, the tracer pokes this function into tracees' memory directly, and let tracees run from
// loader_loader_entry. Before waking tracees up, the kernel finishes `execve' syscall, and set the return
// register to 0.
LOADER_SECTION(text)
[[gnu::naked]] [[gnu::noinline]]
#ifdef __clang__
[[gnu::nocf_check]]
#endif
void loader_loader() {
  //  loader_loader() Register ABI:
  //    rax:  0 (execve result) -> loader_base?
  //    rdi:  chlibc_path
  //    rsi:  O_RDONLY(0) -> filesz
  //    rdx:  R-X
  //    r10:  priv
  //    r8:   mmap -> fd?
  //    r9:   filesz -> O_RDONLY(0)
  //    rbx:  open -> 0
  //    rbp:  loader_offset -> loader
  __asm__ volatile(
      ".global loader_loader_entry, loader_loader_end;"
      "quick_exit:"
      // rax=? rdi=? rbx=0
      "mov %[exit], %%bl;"
      // rax=? rdi=? rbx=exit
      "mov %%ebx, %%edi;"

      "loader_loader_entry:"
      // entry: rax=0 rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=open rbp=loader_offset
      // exit: rax=? rdi=exit rbx=exit
      "xchg %%ebx, %%eax;"
      // entry: [rax=open rdi=chlibc_path rsi=O_RDONLY(0)] rdx=R-X r10=priv r8=mmap r9=filesz rbx=0 rbp=loader_offset
      // exit: [rax=exit rdi=exit] rbx=?
      "syscall;"

      // rax=fd? rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=0 rbp=loader_offset
      "xchg %%rax, %%r8;"
      // rax=mmap rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=fd? r9=filesz rbx=0 rbp=loader_offset
      "xchg %%rsi, %%r9;"
      // [rax=mmap rdi=chlibc_path(hint) rsi=filesz rdx=R-X r10=priv r8=fd? r9=0] rbx=0 rbp=loader_offset
      "syscall;"

      // rax=addr? r8=fd? rbx=0 rbp=loader_offset
      "addq %%rax, %%rbp;"

      // mmap err is guaranteed overflow(CF=1) the previous addq, since:
      // loader_offset >= 4K (by linker script)
      // -errno in (-4K,0) (by syscall ABI)
      "jc quick_exit;"

      // rax=addr r8=fd rbx=0 [rbp=&loader]
      "jmp *%%rbp;"
      "loader_loader_end:"
      :
      : [exit] "i"(SYS_exit)  // quick_exit
  );
}

static_assert(0 <= SYS_exit && SYS_exit < 256);

LOADER_SECTION(entry)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader() {
  // System V X64 ABI:
  //   (rax, rdx) <- function(rdi, rsi, rdx, rcx, r8, r9)
  //  loader() Register ABI:
  //    r8:  fd of chlibc elf
  //    rbx: 0, quick_exit used, set by loader_loader()
  //    rbp: loader base for munmap, saved from rax
  //    r12: loader size for munmap
  //    r13: total mmap range for PIE elf, 0 for non PIE elf
  //    r14: loader_reg_flags_t
  __asm__ volatile(
      ".global trap_ok_marker, trap_munmap_fail_marker, loader_end;"
      "mov %%rax, %%rbp;"  // save loader base

      "mov %%rsp, %%rdi;"  // param
      "mov %%r13, %%rsi;"  // total_memsz for PIE elf
      "mov %%r14, %%rdx;"  // loader_reg_flags_t
      "call loader_main;"  // now r13, r14 can be dropped, r8 is already set to fd
      "test %%rax, %%rax;"
      "js quick_exit;"  // fail with -errno in rax

      // Move [rsp, rsp + sz) to [new_sp, new_sp + sz), assume new_sp < sp
      // On the return of execve, the DF must be 0.
      "movq %c[reg_off](%%rsp), %%rdi;"  // arg1
      "mov %%rsp, %%rsi;"                // arg2
      "mov %%rax, %%rcx;"                // arg4, reuse ld_dir in rdx (arg3)
      "movq %%rdi, %%rsp;"               // allocate space

      "call loader_fix_stack;"

      "mov %[munmap], %%rax;"
      "mov %%rbp, %%rdi;"  // loader base
      "mov %%r12, %%rsi;"  // loader filesz

      "int3;"
      "trap_ok_marker:"
      "syscall;"
      "trap_munmap_fail_marker:"
      "ud2; ud2; .2byte 0x3039; ud2;"  // munmap, and no return
      "loader_end:"
      :
      : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP))
      : "memory");
}
