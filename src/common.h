#ifndef __CHLIBC_COMMON_H__
#define __CHLIBC_COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__x86_64__)
#define ARCH_X64
#elif defined(__aarch64__)
#define ARCH_ARM64
#elif defined(__riscv)
#if __riscv_xlen == 64 && defined(__riscv_c)
#define ARCH_RISCV64
#else
#error "Requires riscv 64bit with C-extension (Compressed Instructions). Compilation aborted."
#endif
#else
#error "Requires x86_64/aarch64/riscv64 architecture. Compilation aborted."
#endif

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)

#define ARRAY_SIZE(x) (sizeof(int[_Generic(&(x), typeof(&(x)[0])*: -1, default: 1)]) * 0 + sizeof(x) / sizeof(*(x)))
#define sizeof_member(t, m) (sizeof(((t*)nullptr)->m))
#define end_offsetof(t, m) (offsetof(t, m) + sizeof_member(t, m))
#define is_power_2(x) (0 == ((x) & ((x) - 1)))

////////// Align Macros ////////////
#define __ALIGNAS_TYPE(fallback, as, ...)                                                       \
  typeof(__extension__({                                                                        \
    [[maybe_unused]] uint64_t _ = 0;                                                            \
    ({                                                                                          \
      _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wunused-value\"")       \
          _Pragma("GCC diagnostic ignored \"-Wshadow\"") as* _;                                 \
      _Pragma("GCC diagnostic pop") _Generic(_, uint64_t: (fallback) + UINT64_MAX, default: _); \
    });                                                                                         \
  }))
#define __ALIGNAS_OF(as, ...)             \
  sizeof(*__extension__({                 \
    alignas(as) char __c = 0;             \
    (char (*)[__alignof__(__c)]) nullptr; \
  }))

#define __ALIGNAS_OF_DEF(p) typeof(*_Generic(__extension__((p) + UINT64_MAX), uint64_t: (uint64_t*)0, default: p))
#define __ALIGN_Z_EXT(p)                                                                                             \
  ((uint64_t)(unsigned _BitInt(                                                                                      \
      _Generic(__extension__((p) + UINT64_MAX), uint64_t: sizeof(p), default: sizeof(__extension__((p) + 0))) * 8))( \
      p))

#define ALIGN_D_IMP(p, a, t) ((t)((p) & ~((a) - 1)))
#define ALIGN_U_IMP(p, a, t) ((t)(((p) + (a) - 1) & ~((a) - 1)))
#define ALIGN_D_DIST_IMP(p, a) ((p) & ((a) - 1))
#define ALIGN_U_DIST_IMP(p, a) (-(p) & ((a) - 1))
#define ALIGN_U_INVALID_IMP(a) ((uint64_t)(int64_t)(-(signed _BitInt(sizeof(a) * 8))(a)))

// align_*(p, [alignas])
// align_*_dist(p, [alignas])
// p: can be integer type, T*ptr or T array[]
// alignas: can be integer const or a type T.
#define align_d(p, ...)                                                                       \
  ALIGN_D_IMP(__ALIGN_Z_EXT(p), __ALIGNAS_OF(__VA_ARGS__ __VA_OPT__(, ) __ALIGNAS_OF_DEF(p)), \
              __ALIGNAS_TYPE(p __VA_OPT__(, ) __VA_ARGS__, 0))
#define align_u(p, ...)                                                                       \
  ALIGN_U_IMP(__ALIGN_Z_EXT(p), __ALIGNAS_OF(__VA_ARGS__ __VA_OPT__(, ) __ALIGNAS_OF_DEF(p)), \
              __ALIGNAS_TYPE(p __VA_OPT__(, ) __VA_ARGS__, 0))
#define align_d_dist(p, ...) \
  ALIGN_D_DIST_IMP(__ALIGN_Z_EXT(p), __ALIGNAS_OF(__VA_ARGS__ __VA_OPT__(, ) __ALIGNAS_OF_DEF(p)))
#define align_u_dist(p, ...) \
  ALIGN_U_DIST_IMP(__ALIGN_Z_EXT(p), __ALIGNAS_OF(__VA_ARGS__ __VA_OPT__(, ) __ALIGNAS_OF_DEF(p)))

// when p >= align_u_invalid(as), [align_u(), align_u() + a] should not be used to avoid overflow
// (align_u() + a) should be valid to check the pointer range
#define align_u_invalid(as) ALIGN_U_INVALID_IMP(__ALIGNAS_OF(as))

#define STACK_ALIGNAS 16

/// Types
typedef struct {
  uint64_t offset;  // -1 --> MAP_ANONYMOUS
  uint64_t vaddr;   // without bias
  struct {
    size_t length : 61;  // page-aligned size - padzero() size
    uint8_t prot : 3;
  };
} mmap_param_t;
static_assert(alignof(mmap_param_t) == 8);
static_assert(sizeof(mmap_param_t) % 8 == 0);

typedef struct {
  uintptr_t vaddr;  // without bias
  size_t length;    // page-aligned size
} munmap_param_t;

////////// API check Functions ////////////
#define _OK_CALL(exp, ok_, ...)                                                        \
  __extension__({                                                                      \
    typeof(exp) _OK_CALL_RESULT = (exp); /* typeof() here supports exp = WSTOPSIG() */ \
    auto const _ = _OK_CALL_RESULT;                                                    \
    if (!(ok_)) {                                                                      \
      ERR(#exp);                                                                       \
      __VA_ARGS__;                                                                     \
    }                                                                                  \
    _OK_CALL_RESULT;                                                                   \
  })
#define _OK_CALL_DEF(exp, ok_, def) _OK_CALL(exp, ok_, _OK_CALL_RESULT = (def))

#endif  // __CHLIBC_COMMON_H__
