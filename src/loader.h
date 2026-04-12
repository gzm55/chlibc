// clang-format Language: C

#ifndef __CHLIBC_LOADER_H__
#define __CHLIBC_LOADER_H__

#include <elf.h>
#include <sys/syscall.h>
#include <sys/user.h>

#include "common.h"

#define LOADER_SECTION(type) [[gnu::section(".loader." #type)]]

#if defined(ARCH_X64)
typedef struct user_regs_struct common_regs_t;
#  define _M_PC rip
#  define _M_SP rsp
#  define _M_SYS_NR rax
#  define _M_SYS_ARG1 rdi
#  define _M_SYS_ARG2 rsi
#  define _M_SYS_ARG3 rdx
#  define _M_SYS_ARG4 r10
#  define _M_SYS_ARG5 r8
#  define _M_SYS_ARG6 r9
#  define _M_SYS_RET rax
#  define _M_S0 rbx
#  define _M_S1 rbp
#  define _M_S2 r12
#  define _M_S3 r13
#  define _M_S4 r14
#  define TRAP_OP_NEXT 0
#  define LOADER_LOADER_SP (0 * 8)

#elif defined(ARCH_ARM64)
typedef struct user_pt_regs common_regs_t;
#  define _M_PC pc
#  define _M_SP sp
#  define _M_SYS_NR regs[8]
#  define _M_SYS_ARG1 regs[0]
#  define _M_SYS_ARG2 regs[1]
#  define _M_SYS_ARG3 regs[2]
#  define _M_SYS_ARG4 regs[3]
#  define _M_SYS_ARG5 regs[4]
#  define _M_SYS_ARG6 regs[5]
#  define _M_SYS_RET regs[0]
#  define _M_S1 regs[20]
#  define _M_S2 regs[21]
#  define _M_S3 regs[22]
#  define _M_S4 regs[23]
#  define TRAP_OP_NEXT 4
#  define LOADER_LOADER_SP (2 * 8)

#else  // ARCH_RISCV64
typedef struct user_regs_struct common_regs_t;
#  define _M_PC pc
#  define _M_SP sp
#  define _M_SYS_NR a7
#  define _M_SYS_ARG1 a0
#  define _M_SYS_ARG2 a1
#  define _M_SYS_ARG3 a2
#  define _M_SYS_ARG4 a3
#  define _M_SYS_ARG5 a4
#  define _M_SYS_ARG6 a5
#  define _M_SYS_RET a0
#  define _M_S1 s1
#  define _M_S2 s2
#  define _M_S3 s3
#  define _M_S4 s4
#  define TRAP_OP_NEXT 2
#  define LOADER_LOADER_SP (0 * 8)

#endif

static_assert(sizeof(uintptr_t) == sizeof_member(common_regs_t, _M_PC));
static_assert(sizeof(uintptr_t) == sizeof_member(common_regs_t, _M_SP));

#define __RELO_TYPE(n) typeof(((loader_relo_types *)nullptr)->n)
#define __RELO_TYPE_UQ(n) typeof_unqual(*((loader_relo_types *)nullptr)->n) *
#define __RELO_ALIGNOF(n) alignof(typeof(*((loader_relo_types *)nullptr)->n))
#define __RELO_OFS(p, n)                           \
  (offsetof(loader_relo_types, n) < sizeof(void *) \
       ? UINT32_C(0)                               \
       : (p)->relo_offsets[offsetof(loader_relo_types, n) / sizeof(void *) - 1])
#define __RELO_PTR(p, n) ((__RELO_TYPE(n)) & (p)->data[__RELO_OFS(p, n)])
#define RELO_PTR(p, n) __RELO_PTR(_Generic(p, loader_param_t: &(p), default: p), n)
#define RELO_OFS_INC(p, n, x)                                                        \
  do {                                                                               \
    if (sizeof(void *) <= offsetof(loader_relo_types, n))                            \
      (p)->relo_offsets[offsetof(loader_relo_types, n) / sizeof(void *) - 1] += (x); \
  } while (0);
#define RELO_WRITTEN(p) \
  _Generic(p, loader_param_t: &(p), default: p)->relo_offsets[offsetof(loader_relo_types, end) / sizeof(void *) - 1]

// calc remote abs addr via a downloaded local parameter
#define RELO_PTR_REMOTE(rb, lp, n) \
  ((rb) + sizeof(loader_param_t) + __RELO_OFS(_Generic(lp, loader_param_t: &(lp), default: lp), n))

// only for building loader_param_t.data
#define RELO_SET_OFFSET(p, n)                                                                           \
  __extension__({                                                                                       \
    auto const _param = _Generic(p, loader_param_t: &(p), default: p);                                  \
    static_assert(alignof(typeof(*_param)) % __RELO_ALIGNOF(n) == 0);                                   \
    if (offsetof(loader_relo_types, n) < sizeof(void *))                                                \
      RELO_WRITTEN(_param) = 0;                                                                         \
    else {                                                                                              \
      RELO_WRITTEN(_param) = align_u(RELO_WRITTEN(_param), __RELO_ALIGNOF(n));                          \
      _param->relo_offsets[offsetof(loader_relo_types, n) / sizeof(void *) - 1] = RELO_WRITTEN(_param); \
    }                                                                                                   \
    (__RELO_TYPE_UQ(n)) & _param->data[RELO_WRITTEN(_param)];                                           \
  })

typedef uint64_t argc_t [[gnu::aligned(STACK_ALIGNAS)]];
static_assert(alignof(argc_t) == 16 && sizeof(argc_t) == 8);

typedef struct {
  const mmap_param_t *mmap_params;  // bias = mmap result
  union {
    const mmap_param_t *mmap_params_end;
    const munmap_param_t *munmap_params;  // bias = at_base
  };
  union {
    const munmap_param_t *munmap_params_end;
    const char *interp_path;
  };
  const char *libc_dir;
  const char *chlibc_path;

  const argc_t *argc;  // entry stack
  char *const *envp;
  char **envp_null;  // envp end marker, used to insert envp pointer of LD_LIBRARY_PATH
  const Elf64_auxv_t *auxv;
  union {
    char *lib_paths;  // string of LD_LIBRARY_PATH
    const void *end;
  };
} loader_relo_types;
static_assert(sizeof(loader_relo_types) % sizeof(void *) == 0);
static_assert(offsetof(loader_relo_types, end) > sizeof(void *));
#define LOADER_RELO_OFFSETS_COUNT (sizeof(loader_relo_types) / sizeof(void *) - 1)
#define LOADER_PARAM_SZ_BEFORE_STACK(p) (sizeof(loader_param_t) + __RELO_OFS(p, argc))
#define LOADER_PARAM_CHLIBC_PATH_OFS_FROM_ARGC(p) (__RELO_OFS(p, chlibc_path) - __RELO_OFS(p, argc))

typedef struct {
  alignas(STACK_ALIGNAS) struct {
    common_regs_t regs;
    uint32_t relo_offsets[LOADER_RELO_OFFSETS_COUNT];
  };

  alignas(STACK_ALIGNAS) uint8_t data[];
} loader_param_t;
static_assert(alignof(loader_param_t) == STACK_ALIGNAS);
static_assert(offsetof(loader_param_t, data) % STACK_ALIGNAS == 0);
static_assert(sizeof(loader_param_t) == offsetof(loader_param_t, data));

typedef union {
  uint64_t raw;
  struct {
    uint8_t at_base_idx;
    uint8_t at_pagesz_idx;
#ifdef ARCH_ARM64
    bool support_bti;  // enable BTI on all supported kernels, skip checking gnu properties
#endif
  };
} loader_reg_flags_t;
static_assert(sizeof(loader_reg_flags_t) == sizeof(uint64_t));

#if defined(__clang__) && defined(ARCH_X64)
[[gnu::nocf_check]]
#endif
void loader_loader();
void loader_loader_end();
void loader_loader_entry();
extern const uint8_t trap_ok_marker[];
extern const uint8_t trap_munmap_fail_marker[];

#ifdef ARCH_X64
void loader_fix_stack(void *, const void *, char **, size_t);
#else
void loader_fix_stack(size_t, char **, void *, const void *);
#endif

void loader();

typedef struct {
  int64_t stacksz;
  char **ld_dir;
} stack_move_info_t;

// when fail return {-errno, nullptr}
// success return {stacksz for moving, the elem in envp for LD_LIBRARY_PATH}
stack_move_info_t loader_main(loader_param_t *, uint64_t, loader_reg_flags_t, uint64_t, int);

#endif  // __CHLIBC_LOADER_H__
