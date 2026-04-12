#include "loader.h"

// syscall:   x0      <- x8(x0, x1, x2, x3, x4, x5)
// function:  x0      <- x8(x0, x1, x2, x3, x4, x5)
//           (x0, x1) <- x8(x0, x1, x2, x3, x4, x5)
// callee-saved: x19--x28

// Prepares registers and load segments for loader().
// On EVENT_EXEC, the tracer pokes this function into tracees' memory directly, and let tracees run from
// loader_loader_entry. Before waking tracees up, the kernel finishes `execve' syscall, and set the return
// register to 0.
LOADER_SECTION(text)
[[gnu::naked]] [[gnu::noinline]] [[gnu::target("branch-protection=none")]]
void loader_loader() {
  //  loader_loader() Register ABI:
  //    x8: openat
  //    x0: 0 (set by kernel as execve result)
  //    x1: chlibc_path
  //    x2: O_RDONLY(0)
  //    x3: priv
  //    x4: filesz
  //    x5: 0
  //    x20: loader_offset
  //    [rsp] = [mmap, R-X]
  __asm__ volatile(
      ".global loader_loader_entry, loader_loader_end;"

      "quick_exit:"
      "mov x0, %[exit];"
      "mov x8, %[exit];"

      "loader_loader_entry:"
      // entry: [x8=openat x0=0 x1=chlibc_path x2=O_RDONLY(0)] x3=priv x4=filesz x5=0 x19=&loader_loader
      //        [rsp] = [mmap, R-X]
      // exit: [x0=exit x0=exit]
      "svc #0;"

      // x8=openat x0=fd? x1=chlibc_path x2=&loader_loader x3=priv x4=filesz x5=0
      //    [rsp] = [mmap, R-X]
      "ldp x8, x2, [sp], #16;"
      // x8=mmap x0=fd? x1=chlibc_path x2=R-X x3=priv x4=filesz x5=0
      "mov x1, x4;"
      // x8=mmap x0=fd? x1=filesz x2=R-X x3=priv x4=filesz x5=0
      "mov x4, x0;"
      // [x8=mmap x0=fd?(hint) x1=filesz x2=R-X x3=priv x4=fd? x5=0]
      "svc #0;"

      // x8=mmap x0=addr? x4=fd? x20=loader_offset
      "adds x20, x20, x0;"

      // mmap err is guaranteed overflow the previous adds, since:
      // loader_offset >= 4K (by linker script)
      // -errno in (-4K,0) (by syscall ABI)
      "b.cs quick_exit;"

      // x8=mmap x0=addr x4=fd [x20=&loader]
      "br x20;"

      "loader_loader_end:"
      :
      : [exit] "i"(SYS_exit)  // quick_exit
  );
}

LOADER_SECTION(entry)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader() {
  // System V AArch64 ABI:
  //   (x0, x1) <- function(x0, x1, x2, x3, x4, x5, x6, x7)
  // loader() Register ABI
  //   x4:  fd of chlibc elf
  //   x20: loader base for munmap, saved from rax
  //   x21: loader size for munmap
  //   x22: total mmap range for PIE elf, 0 for non PIE elf
  //   x23: loader_reg_flags_t
  __asm__ volatile(
      ".global trap_ok_marker, trap_munmap_fail_marker, loader_end;"
      "mov x20, x0;"  // save loader base

      "mov x0, sp;"                // param
      "mov x1, x22;"               // total_memsz for PIE elf
      "mov x2, x23;"               // loader_reg_flags_t
      "bl loader_main;"            // now x22, x23 can be dropped, x4 is already set to fd
      "tbnz x0, #63, quick_exit;"  // fail with -errno in rax

      "mov x3, sp;"                  // src, reuse x0 and x1
      "ldr x2, [x3, #%c[reg_off]];"  // dst
      "mov sp, x2;"

      "bl loader_fix_stack;"

      "mov x8, %[munmap];"
      "mov x0, x20;"  // loader base
      "mov x1, x21;"  // loader size

      "trap_ok_marker:"
      "brk #0x3039; svc #0;"
      "trap_munmap_fail_marker:"
      "udf #0x3039; udf #0x3039;"
      "loader_end:"
      :
      : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP))
      : "memory");
}
