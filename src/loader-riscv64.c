#include "loader.h"

// syscall:   a0      <- a7(a0, a1, a2, a3, a4, a5)
// function:  a0      <- function(a0, a1, a2, a3, a4, a5, a6, a7)
//           (a0, a1) <- function(a0, a1, a2, a3, a4, a5, a6, a7)
// callee-saved: s0--s11 (x8, x9, x18-x27)

// Prepares registers and load segments for loader().
// On EVENT_EXEC, the tracer pokes this function into tracees' memory directly, and let tracees run from
// loader_loader_entry. Before waking tracees up, the kernel finishes `execve' syscall, and set the return
// register to 0.
LOADER_SECTION(text)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader_loader() {
  //  loader_loader() Register ABI:
  //    a7: openat
  //    a0: 0 (set by kernel as execve result)
  //    a1: chlibc_path
  //    a2: O_RDONLY(0)
  //    a3: priv
  //    a4: filesz
  //    a5: 0
  //    s0: exit
  //    s1: loader_offset
  //    s10: R-X
  //    s11: mmap
  __asm__ volatile(
      ".option push;"
      ".option rvc;"
      ".global loader_loader_entry, loader_loader_end;"

      "quick_exit:"
      // a7=? a0=? s0=exit
      "c.mv a7, s0;"
      // a7=exit a0=? s0=exit
      "c.mv a0, s0;"

      "loader_loader_entry:"
      // entry: [a7=openat a0=0 a1=chlibc_path a2=O_RDONLY(0)] a3=priv a4=filesz a5=0 s1=loader_offset s10=R-X s11=mmap
      // exit: [a7=exit a0=exit]
      "ecall;"

      // a7=openat a0=fd? a1=chlibc_path a2=O_RDONLY(0) a3=priv a4=filesz a5=0 s1=loader_offset s10=R-X s11=mmap
      "c.mv a7, s11;"
      // a7=mmap a0=fd? a1=chlibc_path a2=O_RDONLY(0) a3=priv a4=filesz a5=0 s1=loader_offset s10=R-X
      "c.mv a2, s10;"
      // a7=mmap a0=fd? a1=chlibc_path a2=R-X a3=priv a4=filesz a5=0 s1=&loader_loader
      "c.mv a1, a4;"
      // a7=mmap a0=fd? a1=filesz a2=R-X a3=priv a4=filesz a5=0 s1=&loader_loader
      "c.mv a4, a0;"
      // [a7=mmap a0=fd?(hint) a1=filesz a2=R-X a3=priv a4=fd? a5=0] s1=&loader_loader
      "ecall;"

      // a0=addr? a4=fd? s1=loader_offset
      "c.add s1, a0;"

      // mmap err is guaranteed overflow the previous adds, since:
      // loader_offset >= 4K (by linker script)
      // -errno in (-4K,0) (by syscall ABI)
      "bltu s1, a0, quick_exit;"  // if (s1 < a0) goto quick_exit

      // a0=addr a4=fd [s1=&loader]
      "c.jr s1;"

      "loader_loader_end:"
      ".option pop;" ::);
}

LOADER_SECTION(entry)
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader() {
  // System V RISC-V ABI:
  //   (a0, a1) <- function(a0, a1, a2, a3, a4, a5, a6, a7)
  // loader() Register ABI
  //   a4:  fd of chlibc elf
  //   s1:  loader base for munmap, saved from a0
  //   s2:  loader size for munmap
  //   s3:  total mmap range for PIE elf, 0 for non PIE elf
  //   s4:  loader_reg_flags_t
  __asm__ volatile(
      ".option push;"
      ".option rvc;"
      ".global trap_ok_marker, trap_munmap_fail_marker, loader_end;"
      "c.mv s1, a0;"  // save loader base

      "c.mv a0, sp;"          // param
      "c.mv a1, s3;"          // total_memsz for PIE elf
      "c.mv a2, s4;"          // loader_reg_flags_t
      "call loader_main;"     // now s3, s4 can be dropped, a4 is already set to fd
      "bltz a0, quick_exit;"  // fail with -errno in a0

      "ld a2, %c[reg_off](sp);"  // arg2, dst, reuse a0 and a1
      "c.mv a3, sp;"             // arg1, src
      "c.mv sp, a2;"             // allocate space

      "call loader_fix_stack;"

      "li a7, %[munmap];"
      "c.mv a0, s1;"  // loader base
      "c.mv a1, s2;"  // loader size

      "trap_ok_marker:"
      "c.ebreak; ecall;"
      "trap_munmap_fail_marker:"
      ".2byte 0x3039;"
      "c.unimp; .2byte 0x3039; c.unimp;"
      "loader_end:"
      ".option pop;"
      :
      : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP))
      : "memory");
}
