#include "loader.h"

// syscall:   r3 + cr0.so <- r0(r3, r4, r5, r6, r7, r8)
// function:  r3          <- function(r3, r4, r5, r6, r7, r8, r9, r10)
//           (r3, r4)     <- function(r3, r4, r5, r6, r7, r8, r9, r10)
// callee-saved: r1, r2, r14-r31

// Prepares registers and load segments for loader().
// On EVENT_EXEC, the tracer pokes this function into tracees' memory directly, and let tracees run from
// loader_loader_entry. Before waking tracees up, the kernel finishes `execve' syscall, and set the return
// register to 0.
//
// loader_loader() Register ABI:
//   r0: openat
//   r3: 0 (set by kernel as execve result)
//   r4: chlibc_path
//   r5: O_RDONLY(0)
//   r6: priv
//   r7: filesz
//   r8: 0
//   r15: loader_offset
//   r30: R-X
//   r31: mmap
__asm__(
    ".section \".loader.text\";"
    ".align 2;"
    ".global loader_loader, loader_loader_entry, loader_loader_end;"
    ".type loader_loader, @function;"

    "loader_loader:"
    "quick_exit:"
    "li %%r0, %[exit];"
    "li %%r3, %[exit];"

    "loader_loader_entry:"
    // entry: [r0=openat r3=0 r4=chlibc_path r5=O_RDONLY(0)] r6=priv r7=filesz r8=0 r15=loader_offset r30=R-X r31=mmap
    // exit: [r0=exit r3=exit]
    "sc;"

    // r0=openat r3=fd? r4=chlibc_path r5=O_RDONLY(0) r6=priv r7=filesz r8=0 r15=loader_offset r30=R-X r31=mmap
    "mr %%r0, %%r31;"
    // r0=mmap r3=fd? r4=chlibc_path r5=O_RDONLY(0) r6=priv r7=filesz r8=0 r15=loader_offset r30=R-X
    "mr %%r5, %%r30;"
    // r0=mmap r3=fd? r4=chlibc_path r5=R-X r6=priv r7=filesz r8=0 r15=loader_offset
    "mr %%r4, %%r7;"
    // r0=mmap r3=fd r4=filesz r5=R-X r6=priv r7=filesz r8=0 r15=loader_offset
    "mr %%r7, %%r3;"
    // [r0=mmap r3=fd?(hint) r4=filesz r5=R-X r6=priv r7=fd? r8=0] r15=loader_offset
    "sc;"

    // Check if mmap failed, PPC64 `sc` sets cr0.so on syscall error
    "bso quick_exit;"

    // r3=addr r7=fd r15=loader_offset
    "add %%r15, %%r15, %%r3;"

    // r3=addr r7=fd [r15=&loader]
    "mtctr %%r15;"
    "bctr;"  // Move target address to ctr and branch

    "loader_loader_end:"
    :
    : [exit] "i"(SYS_exit)  // quick_exit
);

// PPC64LE ELFv2 ABI:
//   (r3, r4) <- function(r3, r4, r5, r6, r7, r8, r9, r10)
// loader() Register ABI (Mapped to PPC64LE)
//   r7:  fd of chlibc elf
//   r15: loader base for munmap, saved from r3
//   r16: loader size for munmap
//   r17: total mmap range for PIE elf, 0 for non PIE elf
//   r18: loader_reg_flags_t
__asm__(
    ".section \".loader.entry\";"
    ".align 2;"
    ".global loader, trap_ok_marker, trap_munmap_fail_marker, loader_end;"
    ".type loader, @function;"

    "loader:"
    "mr %%r15, %%r3;"  // save loader base

    "mr %%r3, %%r1;"   // loader_param on stack
    "mr %%r4, %%r17;"  // total_memsz for PIE elf
    "mr %%r5, %%r18;"  // loader_reg_flags_t
    "bl loader_main;"  // now r17, r18 can be dropped, r7 is already set to fd.
    "cmpdi %%r3, 0;"
    "blt quick_exit;"  // fail with -errno in r3

    "ld %%r5, %[reg_off](%%r1);"  // dst, reuse r3 and r4
    "mr %%r6, %%r1;"              // src
    "mr %%r1, %%r5;"              // allocate space

    "bl loader_fix_stack;"

    "li %%r0, %[munmap];"
    "mr %%r3, %%r15;"  // loader base
    "mr %%r4, %%r16;"  // loader size

    "trap_ok_marker:"
    "tnei %%r0, 0x3039;"  // ebreak equivalent (SIGTRAP)
    "sc;"                 // ecall equivalent (System call)

    "trap_munmap_fail_marker:"
    ".long 0x00000000;"  // unimp equivalent (0x0 is guaranteed SIGILL on PPC)
    ".long 0x30393039;"  // 4-byte Magic marker (Tracer needs to match this)
    "loader_end:"
    :
    : [munmap] "i"(SYS_munmap), [reg_off] "i"(offsetof(loader_param_t, regs._M_SP)));
