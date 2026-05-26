#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "loader.h"

/// tiny libc

#ifdef ARCH_ARM64
#  ifndef PROT_BTI
#    define PROT_BTI 0x10
#  endif
#endif

#define SYSCALL_FAIL(r) ((uint64_t)-4096 < (uint64_t)(uintptr_t)(r))

LOADER_SECTION(text)
static inline int _tlc_strncmp(const char *const restrict s1, const char *const restrict s2, const size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (s1[i] - s2[i])
      return (int)((uint8_t)s1[i] - (uint8_t)s2[i]);
    if (!s2[i])
      break;
  }
  return 0;
}

LOADER_SECTION(text)
static inline size_t _tlc_strlen(const char *const restrict s) {
  auto p = s;
  while (*p++)
    ;
  return p - s - 1;
}

LOADER_SECTION(text)
static inline char *_tlc_stpcpy(char *restrict dest, const char *restrict src) {
  while ((*dest++ = *src++))
    ;
  return --dest;  // dest points to '\0'
}

LOADER_SECTION(text)
static inline void *_tlc_memclr(void *const s, size_t n) {
  auto p = (uint8_t *)s;
#if defined(ARCH_X64)
  if (n)
    __asm__ volatile("rep stosb" : "+D"(p), "+c"(n) : "a"(0) : "memory");
#else
  while (n-- > 0)
    *p++ = 0;
#endif
  return s;
}

LOADER_SECTION(text)
static inline void *_tlc_memmove16(void *dest, const void *src, size_t count) {
  auto const rst = dest;
#ifdef ARCH_X64
  __asm__ volatile("rep movsb" : "+D"(dest), "+S"(src), "+c"(count) : : "memory", "cc");  // ERMS
#else
  auto const d = (uint128_t *)__builtin_assume_aligned(dest, 16);
  auto const s = (const uint128_t *)__builtin_assume_aligned(src, 16);
  auto const n = align_u(count, alignof(uint128_t)) / sizeof(uint128_t);  // extend to full 16 bytes

  // ensure s[n-1] exists and will not be overlapped in moving loop body
  __ASSUME(n > 0);
  __ASSUME((uintptr_t)s - (uintptr_t)d > 16);

#  if defined(__clang__)
  _Pragma("unroll 2")
#  else
  _Pragma("GCC unroll 2")
#  endif
  for (size_t i = 0; i < (n & ~UINT64_C(1)); i++)
    d[i] = s[i];
  d[n - 1] = s[n - 1];
#endif
  return rst;
}

#define EVAL8(...) EVAL4(EVAL4(__VA_ARGS__))
#define EVAL4(...) EVAL2(EVAL2(__VA_ARGS__))
#define EVAL2(...) __VA_ARGS__
#define EVAL(...) __VA_ARGS__
#define NEXT_EXPAND_ROUND()
#define LOOP8I(op, ...) __VA_OPT__(EVAL8(LOOP8I_DO(op, 7, 6, 5, 4, 3, 2, 1, 0, __VA_ARGS__)))
#define LOOP8I_DO(op, _7, _6, _5, _4, _3, _2, _1, idx, v, ...) \
  op(idx, v) __VA_OPT__(LOOP8I_DO_DELAY_TO NEXT_EXPAND_ROUND()()(op, -1, _7, _6, _5, _4, _3, _2, _1, __VA_ARGS__))
#define LOOP8I_DO_DELAY_TO() LOOP8I_DO
#define SYSCALL_BIND(i, exp) register uint64_t a##i __asm__(_STR(_N_SYS_A_I##i)) = (uintptr_t)(exp);
#define SYSCALL_R_REG(i, exp) , "r"(a##i)
#define SYSCALL_RW_REG(i, exp) , "+r"(a##i)
#define LIST_TAILS(_, ...) __VA_OPT__(, __VA_ARGS__)
#define LIST_TTAILS(_1, _2, ...) __VA_OPT__(, __VA_ARGS__)
#define LIST_TAILS2(_, ...) __VA_ARGS__

#define LIST_DROP_FIRST_EMPTY(L) L
#define LIST_DROP_FIRST_NOT_EMPTY(L, _1, ...) LIST_DROP_FIRST_DO_01 L __VA_OPT__(, ) __VA_ARGS__
#define LIST_DROP_FIRST_DO_01(_1, ...) (__VA_ARGS__)
#define LIST_DROP_FIRST_01(L, ...) LIST_DROP_FIRST##__VA_OPT__(_NOT)##_EMPTY(L __VA_OPT__(, ) __VA_ARGS__)
#define LIST_DROP_FIRST_01_DELAY(...) LIST_DROP_FIRST_01 NEXT_EXPAND_ROUND()(__VA_ARGS__)
#define LIST_DROP_FIRST_6(...)                                  \
  EVAL4(EVAL LIST_DROP_FIRST_01_DELAY(LIST_DROP_FIRST_01_DELAY( \
      LIST_DROP_FIRST_01_DELAY(LIST_DROP_FIRST_01_DELAY(LIST_DROP_FIRST_01_DELAY(LIST_DROP_FIRST_01(__VA_ARGS__)))))))

#if defined(ARCH_X64)
#  define _N_SYS_INST "syscall"
#  define _N_SYS_CLOBBERS , "cc", "rcx", "r11"
#  define ASM_SYSCALL_DO ASM_SYSCALL_DO_NR
#elif defined(ARCH_ARM64)
#  define _N_SYS_INST "svc #0"
#  define _N_SYS_CLOBBERS
#  define ASM_SYSCALL_DO ASM_SYSCALL_DO_A0
#elif defined(ARCH_RISCV64)
#  define _N_SYS_INST "ecall"
#  define _N_SYS_CLOBBERS
#  define ASM_SYSCALL_DO ASM_SYSCALL_DO_A0
#elif defined(ARCH_PPC64LE)
#  define _N_SYS_INST "sc; bns+ 1f; neg %%r3, %%r3; 1:"
#  define _N_SYS_CLOBBERS "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "cr0", "ctr"
#  define ASM_SYSCALL_DO ASM_SYSCALL_DO_A0V
#endif

#define ASM_SYSCALL(name, ...)                                \
  register uint64_t nr __asm__(_STR(_N_SYS_NR)) = SYS_##name; \
  LOOP8I(SYSCALL_BIND __VA_OPT__(, ) __VA_ARGS__)             \
  ASM_SYSCALL_DO(name, __VA_ARGS__)

#define ASM_SYSCALL_DO_NR(name, ...)                                                                         \
  __asm__ volatile(_N_SYS_INST                                                                               \
                   : "+r"(nr)                                                                                \
                   : EVAL(LIST_TAILS2 NEXT_EXPAND_ROUND()(LOOP8I(SYSCALL_R_REG __VA_OPT__(, ) __VA_ARGS__))) \
                   : "memory" _N_SYS_CLOBBERS);                                                              \
  return (typeof(_tlc_##name(__VA_ARGS__)))nr

#define ASM_SYSCALL_DO_A0(name, ...)                                            \
  ASM_SYSCALL_DO_A0##__VA_OPT__(_NOT)##_EMPTY(name __VA_OPT__(, ) __VA_ARGS__); \
  return (typeof(_tlc_##name(__VA_ARGS__)))a0
#define ASM_SYSCALL_DO_A0_EMPTY(name)              \
  register uint64_t a0 __asm__(_STR(_N_SYS_A_I0)); \
  __asm__ volatile(_N_SYS_INST : "=r"(a0) : "r"(nr) : "memory" _N_SYS_CLOBBERS)
#define ASM_SYSCALL_DO_A0_NOT_EMPTY(name, ...)                                                         \
  __asm__ volatile(_N_SYS_INST                                                                         \
                   : "+r"(a0)                                                                          \
                   : "r"(nr)EVAL2(LIST_TTAILS NEXT_EXPAND_ROUND()(LOOP8I(SYSCALL_R_REG, __VA_ARGS__))) \
                   : "memory" _N_SYS_CLOBBERS)

#define ASM_SYSCALL_DO_A0V(name, ...)                                            \
  ASM_SYSCALL_DO_A0V##__VA_OPT__(_NOT)##_EMPTY(name __VA_OPT__(, ) __VA_ARGS__); \
  return (typeof(_tlc_##name(__VA_ARGS__)))a0
#define ASM_SYSCALL_DO_A0V_EMPTY(name)             \
  register uint64_t a0 __asm__(_STR(_N_SYS_A_I0)); \
  __asm__ volatile(_N_SYS_INST : "=r"(a0) : "r"(nr) : "memory" EVAL(LIST_TAILS NEXT_EXPAND_ROUND()(_N_SYS_CLOBBERS)))
#define ASM_SYSCALL_DO_A0V_NOT_EMPTY(name, ...)                                                 \
  __asm__ volatile(_N_SYS_INST                                                                  \
                   : EVAL(LIST_TAILS2 NEXT_EXPAND_ROUND()(LOOP8I(SYSCALL_RW_REG, __VA_ARGS__))) \
                   : "r"(nr)                                                                    \
                   : "memory", LIST_DROP_FIRST_6((_N_SYS_CLOBBERS), __VA_ARGS__))

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline uint8_t *_tlc_mmap(void *const addr, const size_t length, const int prot, const int flags, const int fd,
                                 const off_t offset) {
  ASM_SYSCALL(mmap, addr, length, prot, flags, fd, offset);
}
LOADER_SECTION(text)
[[gnu::always_inline]]
static inline uint64_t _tlc_munmap(void *const addr, const size_t length) {
  ASM_SYSCALL(munmap, addr, length);
}

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline int _tlc_openat(const int dirfd, const char *const path, const int flags) {
  ASM_SYSCALL(openat, dirfd, path, flags);
}
// in _tlc_open(),  path must be a absolute path, so dirfd is ignored
#define _tlc_open(...) _tlc_openat(0, __VA_ARGS__)

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline uint64_t _tlc_close(const int fd) {
  ASM_SYSCALL(close, fd);
}

constexpr auto LD_DIR_KEY_LEN = 16;
LOADER_SECTION(rodata)
static const union {
  char cstr[LD_DIR_KEY_LEN + 1];
  uint128_t d128;
} LD_DIR_KEY = {.cstr = "LD_LIBRARY_PATH="};
static_assert(sizeof(LD_DIR_KEY.cstr) == LD_DIR_KEY_LEN + 1);
typedef uint128_t unaligned_uint128_t [[gnu::aligned(STACK_ALIGNAS)]];

LOADER_SECTION(text)
static inline bool is_ld_dir_env(const char *const p) {
  if (LIKELY(align_u_dist(p, 0x1000) >= 16)) {
    auto const p128 = (const unaligned_uint128_t *)p;
    return *p128 == LD_DIR_KEY.d128;
  }
  return UNLIKELY(_tlc_strncmp(p, LD_DIR_KEY.cstr, LD_DIR_KEY_LEN) == 0);
}

/// Loader functions

LOADER_SECTION(text)
#ifdef ARCH_X64
void loader_fix_stack(void *const new_sp, const void *const old_sp, const char **p_ld_dir, const size_t count) {
#else
void loader_fix_stack(const size_t count, const char **p_ld_dir, void *const new_sp, const void *const old_sp) {
#endif
  auto const old_end = (char *)old_sp + count;
  // Move [rsp, rsp + sz) to [new_sp, new_sp + sz), assume new_sp < sp
  // On the return of execve, the DF must be 0.
  auto const param = (loader_param_t *)_tlc_memmove16(new_sp, old_sp, count);
#ifdef ARCH_PPC64LE
  // use local LD_DIR_KEY on stack to avoid depending on TOC
  union {
    char cstr[LD_DIR_KEY_LEN + 1];
    uint128_t d128;
  } LD_DIR_KEY = {.d128 = ((uint128_t)0x3D485441505F5952 << 64) | 0x415242494C5F444C};
  LD_DIR_KEY.cstr[LD_DIR_KEY_LEN] = '\0';
#endif
  if (p_ld_dir) {
    // fix LD_LIBRARY_PATH
    auto prev = (const char *)LD_DIR_KEY.cstr + LD_DIR_KEY_LEN;  // empty string

    if (!*p_ld_dir) {
      auto auxv = (__RELO_TYPE_UQ(auxv))RELO_PTR(param, auxv);
      static_assert(sizeof(*auxv) == 16);
      static_assert(alignof(typeof(*auxv)) == 8);
      auto const end = (__RELO_TYPE_UQ(auxv))RELO_PTR(param, end);
      auto n = end - auxv;  // auxv as at least 3 elems, since AT_ENTRY, AT_EXECFN and etc. are required
      auxv += n;
      while (n--) {
        auto const tmp = *--auxv;  // avoid overlap UB
        *(typeof(auxv))((uintptr_t)auxv + 8) = tmp;
      }

      RELO_OFS_INC(param, envp_null, 8);
      RELO_OFS_INC(param, auxv, 8);
      RELO_OFS_INC(param, lib_paths, 8);
      *RELO_PTR(param, envp_null) = nullptr;
    } else
      prev = *p_ld_dir + LD_DIR_KEY_LEN;

    auto p = RELO_PTR(param, lib_paths);
    *p_ld_dir = p;
    p = _tlc_stpcpy(p, LD_DIR_KEY.cstr);
    p = _tlc_stpcpy(p, RELO_PTR(param, libc_dir));
    if (*prev) {
      *p++ = ':';
      _tlc_stpcpy(p, prev);
    }
  }

  // append the interp path
  auto const interp_path = RELO_PTR(param, interp_path);
  auto const interp_path_sz = _tlc_strlen(interp_path) + 1;
  _tlc_stpcpy(old_end - interp_path_sz, interp_path);

  param->regs._M_SP = (uintptr_t)RELO_PTR(param, argc);  // restore stack for interp

  // cleaning stack except regs, this will destroy the loader parameter
  auto const after_regs = ((uint8_t *)param) + end_offsetof(typeof(*param), regs);
  _tlc_memclr(after_regs, param->regs._M_SP - (uintptr_t)after_regs);
}

// for align to system page
#define align_page_u(p) ALIGN_U_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz, typeof((p) + UINT64_MAX))
#define align_page_u_dist(p) ALIGN_U_DIST_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz)

typedef struct {
#ifdef ARCH_ARM64
  size_t pagesz : 63;
  bool support_bti : 1;
#else
  size_t pagesz;
#endif
} loader_sys_conf_t;
static_assert(sizeof(loader_sys_conf_t) == sizeof(uint64_t));

LOADER_SECTION(text)
static inline uint8_t *loader_mmap(uint8_t *const base, const mmap_param_t *const m, const size_t placeholder,
                                   const int fd, const loader_sys_conf_t g_sc) {
  auto const nofd = m->offset + 1 == 0;
  const int prot = m->prot
#ifdef ARCH_ARM64
                   | (g_sc.support_bti && 0 != (m->prot & PROT_EXEC) ? PROT_BTI : 0)
#endif
      ;
  auto const segsz = align_page_u((size_t)m->length);
  auto const flags = MAP_PRIVATE | (nofd ? MAP_ANONYMOUS : 0) | (placeholder ? 0 : MAP_FIXED);
  auto const _fd = nofd ? -1 : fd;
  auto const ofs = nofd ? 0 : m->offset;
  auto const length = placeholder ? placeholder : segsz;

  auto rst = _tlc_mmap(base + m->vaddr, length, prot, flags, _fd, ofs);
  if (SYSCALL_FAIL(rst))
    return rst;  // mmap() fail

  // clear the writable tail half page, see the ref
  // ref: https://github.com/torvalds/linux/blob/v6.19/fs/binfmt_elf.c#L435
  if (prot & PROT_WRITE) {
    auto const zerosz = align_page_u_dist((size_t)m->length);
    _tlc_memclr(rst + m->length, zerosz);
  }

  // try munmap() placeholder pages
  if (segsz < placeholder)
    _tlc_munmap(rst + segsz, placeholder - segsz);  // ignore munmap error for placeholder tail

  return rst;
}

// when fail return {-errno, nullptr}
// success return {stacksz for moving, the elem in envp for LD_LIBRARY_PATH}
LOADER_SECTION(text)
stack_move_info_t loader_main(loader_param_t *const param, const uint64_t dyn_total_memsz,
                              const loader_reg_flags_t rflags, uint64_t, const int fd_chlibc) {
  _tlc_close(fd_chlibc);  // try close the fd of chlibc

  stack_move_info_t info;
  info.ld_dir = nullptr;

  auto const auxv = (__RELO_TYPE_UQ(auxv))RELO_PTR(param, auxv);
  auto const old_base = (uint8_t *)auxv[rflags.at_base_idx].a_un.a_val;

  // unmap old interp
  auto const munmap_params_end = RELO_PTR(param, munmap_params_end);
  for (auto un = RELO_PTR(param, munmap_params); un < munmap_params_end; ++un)
    _tlc_munmap(old_base + un->vaddr, un->length);  // ignore mnumap errors

  // prepare new interp
  const loader_sys_conf_t sys_conf = {
      .pagesz = auxv[rflags.at_pagesz_idx].a_un.a_val,
#ifdef ARCH_ARM64
      .support_bti = rflags.support_bti,
#endif
  };

  auto const interp_path = RELO_PTR(param, interp_path);
  auto const fd = _tlc_open(interp_path, O_RDONLY);
  if (SYSCALL_FAIL(fd)) {
    info.stacksz = fd;
    goto FAIL;
  }

  // map new interp
  uint8_t *base = 0;  // non PIE use 0 base
  auto const mmap_params_end = RELO_PTR(param, mmap_params_end);
  auto m = RELO_PTR(param, mmap_params);

  if (dyn_total_memsz) {
    // PIE elf, use placeholder to find a random base (try reuse old_base)
    auto const rst = loader_mmap(old_base, m, dyn_total_memsz, fd, sys_conf);
    if (SYSCALL_FAIL(rst)) {
      info.stacksz = (typeof(info.stacksz))rst;
      goto FAIL;
    }

    base = rst - m->vaddr;

    ++m;
  }

  auxv[rflags.at_base_idx].a_un.a_val = (uintptr_t)base;  // save new base

  for (; m < mmap_params_end; ++m) {
    auto const rst = loader_mmap(base, m, 0, fd, sys_conf);
    if (SYSCALL_FAIL(rst)) {
      info.stacksz = (typeof(info.stacksz))rst;
      goto FAIL;
    }
  }

  // prepare stack info for updating LD_LIBRARY_PATH
  auto const libc_dir = RELO_PTR(param, libc_dir);
  auto const libc_dir_len = _tlc_strlen(libc_dir);
  auto const old_sp = (const uint8_t *)param;
  auto const end = (const uint8_t *)RELO_PTR(param, end);
  auto const interp_path_sz = _tlc_strlen(interp_path) + 1;
  auto alloc_sz = sizeof(char *) + LD_DIR_KEY_LEN + libc_dir_len + 1;  // insert new env elem
  alloc_sz += interp_path_sz;                                          // insert interp path

  info.ld_dir = RELO_PTR(param, envp_null);
  for (auto p = RELO_PTR(param, envp); *p; ++p)
    if (is_ld_dir_env(*p)) {
      auto const ld_dir = *p + LD_DIR_KEY_LEN;

      if (_tlc_strncmp(ld_dir, libc_dir, libc_dir_len) == 0 &&
          (ld_dir[libc_dir_len] == '\0' || ld_dir[libc_dir_len] == ':')) {
        info.ld_dir = nullptr;      // reuse current LD_LIBRARY_PATH
        alloc_sz = interp_path_sz;  // only insert interp path
        break;
      }

      info.ld_dir = p;
      alloc_sz -= sizeof(char *);  // reuse previous elem

      auto const ld_dir_len = _tlc_strlen(ld_dir);
      if (ld_dir_len)
        alloc_sz += ld_dir_len + 1;  // libc_dir:<old_ld_dir>\0
      break;
    }

  param->regs._M_PC += (uintptr_t)base;  // update new interp entry in the backup regs
  param->regs._M_SP = (uintptr_t)align_d(old_sp - alloc_sz, STACK_ALIGNAS);  // save new sp in the backup regs
#ifdef ARCH_PPC64LE
  param->regs.gpr[12] = param->regs._M_PC;  // PPC64 ELFv2 ABI
#endif

  info.stacksz = end - old_sp;

  if (info.ld_dir)
    info.ld_dir -= ((uintptr_t)old_sp - param->regs._M_SP) / sizeof(*info.ld_dir);  // fix for stack moving

FAIL:
  if (0 <= fd)
    _tlc_close(fd);  // ignore close() error
  return info;
}
