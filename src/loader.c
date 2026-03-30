#include <fcntl.h>
#include <sys/mman.h>

#include "loader.h"

/// tiny libc

#ifdef ARCH_ARM64
#  ifndef PROT_BTI
#    define PROT_BTI 0x10
#  endif
#endif

#define SYSCALL_FAIL(r) ((uint64_t)-4096 < (uint64_t)(r))

LOADER_SECTION(text)
static inline int _tlc_strncmp(const void *const vs1, const void *const vs2, const size_t n) {
  const uint8_t *s1 = vs1, *s2 = vs2;
  for (size_t i = 0; i < n; ++i) {
    if (s1[i] - s2[i])
      return (int)(s1[i] - s2[i]);
    if (!s2[i])
      break;
  }
  return 0;
}

LOADER_SECTION(text)
static inline size_t _tlc_strlen(const char *const s) {
  if (!s)
    return 0;
  auto p = s;
  while (*p++)
    ;
  return p - s - 1;
}

LOADER_SECTION(text)
static inline char *_tlc_stpcpy(char *dest, const char *src) {
  while ((*dest = *src)) {
    ++dest;
    ++src;
  }
  return dest;  // dest points to '\0'
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
[[gnu::always_inline]]
static inline uintptr_t _tlc_mmap(void *addr, const size_t length, const int prot, const int flags, const int fd,
                                  const off_t offset) {
  uintptr_t ret;
#ifdef ARCH_X64
  ret = SYS_mmap;
  register const uint64_t r10 __asm__("r10") = (long)flags;
  register const uint64_t r8 __asm__("r8") = (uint64_t)fd;
  register const uint64_t r9 __asm__("r9") = (uint64_t)offset;
  __asm__ volatile("syscall"
                   : "+a"(ret)
                   : "D"(addr), "S"(length), "d"(prot), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
#elif defined(ARCH_ARM64)
  register auto x0 __asm__("x0") = addr;
  register const uint64_t x1 __asm__("x1") = length;
  register const uint64_t x2 __asm__("x2") = prot;
  register const uint64_t x3 __asm__("x3") = flags;
  register const uint64_t x4 __asm__("x4") = fd;
  register const uint64_t x5 __asm__("x5") = offset;
  register const uint64_t nr __asm__("x8") = SYS_mmap;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(nr), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  ret = (typeof(ret))x0;
#else  // ARCH_RISCV64
  register auto x0 __asm__("a0") = addr;
  register const uint64_t x1 __asm__("a1") = length;
  register const uint64_t x2 __asm__("a2") = prot;
  register const uint64_t x3 __asm__("a3") = flags;
  register const uint64_t x4 __asm__("a4") = fd;
  register const uint64_t x5 __asm__("a5") = offset;
  register const uint64_t nr __asm__("a7") = SYS_mmap;
  __asm__ volatile("ecall" : "+r"(x0) : "r"(nr), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  ret = (typeof(ret))x0;
#endif
  return ret;
}

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline uint64_t _tlc_munmap(void *const addr, const size_t length) {
  uintptr_t ret;
#ifdef ARCH_X64
  ret = SYS_munmap;
  __asm__ volatile("syscall" : "+a"(ret) : "D"(addr), "S"(length) : "rcx", "r11", "memory");
#elif defined(ARCH_ARM64)
  register auto x0 __asm__("x0") = addr;
  register const uint64_t x1 __asm__("x1") = length;
  register const uint64_t nr __asm__("x8") = SYS_munmap;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(nr), "r"(x1) : "memory");
  ret = (typeof(ret))x0;
#else  // ARCH_RISCV64
  register auto x0 __asm__("a0") = addr;
  register const uint64_t x1 __asm__("a1") = length;
  register const uint64_t nr __asm__("a7") = SYS_munmap;
  __asm__ volatile("ecall" : "+r"(x0) : "r"(nr), "r"(x1) : "memory");
  ret = (typeof(ret))x0;
#endif
  return ret;
}

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline int _tlc_open(const char *path, int flags) {
  uintptr_t ret;
#ifdef ARCH_X64
  ret = SYS_open;
  __asm__ volatile("syscall" : "+a"(ret) : "D"(path), "S"(flags) : "rcx", "r11", "memory");
#elif defined(ARCH_ARM64)
  register uintptr_t x0 __asm__("x0") = 0;
  register const auto x1 __asm__("x1") = path;
  register const uint64_t x2 __asm__("x2") = flags;
  register const uint64_t nr __asm__("x8") = SYS_openat;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(nr), "r"(x1), "r"(x2) : "memory");
  ret = x0;
#else  // ARCH_RISCV64
  register uintptr_t x0 __asm__("a0") = 0;
  register const auto x1 __asm__("a1") = path;
  register const uint64_t x2 __asm__("a2") = flags;
  register const uint64_t nr __asm__("a7") = SYS_openat;
  __asm__ volatile("ecall" : "+r"(x0) : "r"(nr), "r"(x1), "r"(x2) : "memory");
  ret = x0;
#endif
  return ret;
}

LOADER_SECTION(text)
[[gnu::always_inline]]
static inline uint64_t _tlc_close(const int fd) {
  uintptr_t ret;
#ifdef ARCH_X64
  ret = SYS_close;
  __asm__ volatile("syscall" : "+a"(ret) : "D"(fd) : "rcx", "r11", "memory");
#elif defined(ARCH_ARM64)
  register uint64_t x0 __asm__("x0") = fd;
  register const uint64_t nr __asm__("x8") = SYS_close;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(nr) : "memory");
  ret = x0;
#else  // ARCH_RISCV64
  register uint64_t x0 __asm__("a0") = fd;
  register const uint64_t nr __asm__("a7") = SYS_close;
  __asm__ volatile("ecall" : "+r"(x0) : "r"(nr) : "memory");
  ret = x0;
#endif
  return ret;
}

#define LD_DIR_KEY "LD_LIBRARY_PATH="
constexpr auto ld_dir_key_len = 16;
static_assert(sizeof(LD_DIR_KEY) == ld_dir_key_len + 1);
__asm__(
    ".pushsection .loader.rodata,\"a\",@progbits;"
    ".align 16;"
    "asm_ld_lib_key:"
    ".string \"" LD_DIR_KEY "\";");
[[gnu::visibility("hidden")]]
extern const char asm_ld_lib_key[];

/// Loader functions

LOADER_SECTION(text)
#ifdef ARCH_X64
void loader_fix_stack(loader_param_t *const param, long, char **p_ld_dir) {
#else
void loader_fix_stack(loader_param_t *const param, char **p_ld_dir) {
#endif
  auto prev = asm_ld_lib_key + ld_dir_key_len;  // empty string
  if (!p_ld_dir) {
    auto auxv = (__RELO_TYPE_UQ(auxv))RELO_PTR(param, auxv);
    auto const end = (__RELO_TYPE_UQ(auxv))RELO_PTR(param, end);
    auto n = end - auxv;  // auxv as at least 3 elems, since AT_ENTRY, AT_EXECFN and etc. are required
    auxv += n;
    while (n--) {
      static_assert(sizeof(*auxv) == 16);
      static_assert(alignof(typeof(*auxv)) == 8);
      auto const tmp = *--auxv;  // avoid overlap UB
      *(typeof(auxv))((uintptr_t)auxv + 8) = tmp;
    }

    p_ld_dir = RELO_PTR(param, envp_null);
    RELO_OFS_INC(param, envp_null, 8);
    RELO_OFS_INC(param, auxv, 8);
    RELO_OFS_INC(param, lib_paths, 8);
    *RELO_PTR(param, envp_null) = nullptr;
  } else
    prev = *p_ld_dir + ld_dir_key_len;

  auto p = *p_ld_dir = RELO_PTR(param, lib_paths);
  p = _tlc_stpcpy(p, asm_ld_lib_key);
  p = _tlc_stpcpy(p, RELO_PTR(param, libc_dir));
  if (*prev) {
    *p++ = ':';
    _tlc_stpcpy(p, prev);
  }
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
static inline void *loader_mmap(void *const base, const mmap_param_t *const m, const size_t placeholder, const int fd,
                                const loader_sys_conf_t g_sc) {
  auto const nofd = m->offset + 1 == UINT64_MAX;
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

  auto rst = (uint8_t *)_tlc_mmap((uint8_t *)base + m->vaddr, length, prot, flags, _fd, ofs);
  if (SYSCALL_FAIL(rst))
    return rst;  // mmap() fail

  // clear tail half page
  auto const zerosz = align_page_u_dist((size_t)m->length);
  _tlc_memclr(rst + m->length, zerosz);

  // try munmap() placeholder pages
  if (segsz < placeholder)
    _tlc_munmap(rst + segsz, placeholder - segsz);  // ignore munmap error for placeholder tail

  return rst;
}

// when fail return {-errno, nullptr}
// success return {stacksz for moving, the elem in envp for LD_LIBRARY_PATH}
LOADER_SECTION(text)
stack_move_info_t loader_main(loader_param_t *const param, const uint64_t dyn_total_memsz,
                              const loader_reg_flags_t rflags) {
  stack_move_info_t info = {
      .stacksz = -22,
      .ld_dir = nullptr,
  };  // EINVAL=22

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
    auto const rst = loader_mmap(old_base + m->vaddr, m, dyn_total_memsz, fd, sys_conf);
    if (SYSCALL_FAIL(rst)) {
      info.stacksz = (typeof(info.stacksz))rst;
      goto FAIL;
    }

    base = (uint8_t *)rst - m->vaddr;
    if (base != old_base)
      auxv[rflags.at_base_idx].a_un.a_val = (uintptr_t)base;  // save new base

    ++m;
  }

  for (; m < mmap_params_end; ++m) {
    auto const rst = (uintptr_t)loader_mmap(base, m, 0, fd, sys_conf);
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
  auto alloc_sz = sizeof(char *) + ld_dir_key_len + libc_dir_len + 1;  // insert new

  for (auto p = (__RELO_TYPE_UQ(envp))RELO_PTR(param, envp); *p; ++p)
    if (_tlc_strncmp(*p, LD_DIR_KEY, ld_dir_key_len) == 0) {
      info.ld_dir = p;
      alloc_sz -= sizeof(char *);  // reuse previous elem

      auto const ld_dir = *p + ld_dir_key_len;
      auto const ld_dir_len = _tlc_strlen(ld_dir);
      if (ld_dir_len)
        alloc_sz += ld_dir_len + 1;  // libc_dir:<old_ld_dir>\0
      break;
    }

  param->regs._M_PC += (uintptr_t)base;  // update new interp entry in the backup regs
  param->regs._M_SP = (uintptr_t)align_d(old_sp - alloc_sz, STACK_ALIGNAS);  // save new sp in the backup regs
  info.stacksz = end - old_sp;

FAIL:
  if (0 <= fd)
    _tlc_close(fd);  // ignore close() error
  return info;
}
