#if defined(__linux__)
#if !defined(__gnu_linux__)
#error "Requires Glibc on normal linux. Compilation aborted."
#endif
#else
#error "Requires Linux. Compilation aborted."
// Runtime kernel requirement:
//   X64:     Linux >= 2.6.18
//   AMD64:   Linux >= 3.19
//   RISCV64: Linux >= 5.4
#endif

#if defined(__x86_64__)
#define ARCH_X64
#elif defined(__aarch64__)
#define ARCH_ARM64
#elif define(__riscv) && __riscv_xlen == 64
#define ARCH_RISCV64
#else
#error "Requires x86_64/aarch64/riscv64 architecture. Compilation aborted."
#endif

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Requires Little-endian. Compilation aborted."
#endif

#if !defined(__GNUC__)
#error "This project is strictly optimized for GCC/Clang compilers."
#endif

int main() { return 0; }
