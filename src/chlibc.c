#if defined(__linux__)
#  if !defined(__gnu_linux__)
#    error "Requires Glibc on normal linux. Compilation aborted."
#  endif
// Runtime kernel requirement:
//   X64:     Linux >= 2.6.18
//   AMD64:   Linux >= 3.19
//   RISCV64: Linux >= 5.4
#else
#  error "Requires Linux. Compilation aborted."
#endif

#if defined(__x86_64__)
#  define ARCH_X64
#elif defined(__aarch64__)
#  define ARCH_ARM64
#elif define(__riscv) && __riscv_xlen == 64
#  define ARCH_RISCV64
#else
#  error "Requires x86_64/aarch64/riscv64 architecture. Compilation aborted."
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#  error "Requires Little-endian. Compilation aborted."
#endif

#if !defined(__GNUC__)
#  error "This project is strictly optimized for GCC/Clang compilers."
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#  error "This project is strictly optimized for C23."
#endif

#if !defined(_GNU_SOURCE)
#  error "This project requires Glibc and its extension features."
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <linux/binfmts.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#ifndef PTRACE_O_EXITKILL
#  include <linux/ptrace.h>
#endif


int main() { return 0; }
