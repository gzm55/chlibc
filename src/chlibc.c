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

// #include "common.h"
#include "loader.h"

#if defined(ARCH_X64)
__asm__(".symver memcpy, memcpy@GLIBC_2.2.5");
#endif

////////// System Config/Feature ////////////
typedef struct {
  size_t pagesz;
  size_t max_arg_strlen;
  int o_cloexec;
  int f_dupfd_cloexec;
#ifdef ARCH_ARM64
  int prot_bti;
#endif
#ifdef ARCH_X64
  bool has_ptrace_exitkill;
  bool has_ptrace_getregset;
  bool has_vm_rwv;
#endif
} sys_config_t;
static sys_config_t g_sc;
static bool init_sys_config();
#ifdef ARCH_X64
#  define __FORCE_CLOEXEC(fd, cond)                      \
    do                                                   \
      if (cond) {                                        \
        auto const __fd = (fd);                          \
        auto const __fd_flags = fcntl(__fd, F_GETFD);    \
        if (__fd_flags != -1)                            \
          fcntl(__fd, F_SETFD, __fd_flags | FD_CLOEXEC); \
      }                                                  \
    while (0)
#  define OPENFD_CLOEXEC(fd) __FORCE_CLOEXEC(fd, O_CLOEXEC != g_sc.o_cloexec)
#  define DUPFD_CLOEXEC(fd) __FORCE_CLOEXEC(fd, F_DUPFD_CLOEXEC != g_sc.f_dupfd_cloexec)
static bool init_sys_config_ptrace(pid_t, bool);
#else
#  define OPENFD_CLOEXEC(fd)
#  define DUPFD_CLOEXEC(fd)
#endif

// for align to system page
#define align_page_d(p) ALIGN_D_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz, typeof((p) + UINT64_MAX))
#define align_page_u(p) ALIGN_U_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz, typeof((p) + UINT64_MAX))
#define align_page_d_dist(p) ALIGN_D_DIST_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz)
#define align_page_u_dist(p) ALIGN_U_DIST_IMP(__ALIGN_Z_EXT(p), g_sc.pagesz)
#define align_page_u_invalid ALIGN_U_INVALID_IMP(g_sc.pagesz)

// [r_ofs, r_ofs+r_sz) is contained in [0, totalsz)
static inline bool range_validate(const uint64_t r_ofs, const uint64_t r_sz, const uint64_t totalsz) {
  return LIKELY(r_sz <= totalsz && r_ofs <= totalsz - r_sz);  // avoid overflow
}

////////// LOG Functions ////////////
static void _log_write_syslogv(struct iovec *iov, int iovcnt) {
  openlog("chlibc", LOG_PID | LOG_CONS, LOG_USER);
#define _SYSMSG(i) (i < iovcnt ? (char *)iov[i].iov_base : "")
  syslog(LOG_CRIT, "LOG FAIL - %s%s%s%s", _SYSMSG(0), _SYSMSG(1), _SYSMSG(2), _SYSMSG(3));
#undef _SYSMSG
  closelog();
}
static bool _log_fd_ok(const int fd) {
  if (fd < 0 || fcntl(fd, F_GETFD) < 0)
    return false;
  if (isatty(fd)) {
    auto const ttygp = tcgetpgrp(fd);
    if (ttygp < 0 || ttygp != getpgrp())
      return false;
  }
  return write(fd, "", 0) == 0;
}
static int _log_fd() {
  static int fd = -2;
  if (-1 == fd)
    return fd;
  if (0 <= fd) {
    // check tty
    if (isatty(fd)) {
      auto const ttygp = tcgetpgrp(fd);
      return (ttygp < 0 || ttygp != getpgrp()) ? -1 : fd;
    }
    return fd;
  }

  // from env
  auto const env_path = getenv("CHLIBC_LOGGER_FILE");
  if (env_path && 0 != *env_path) {
    fd = open(env_path, O_WRONLY | O_APPEND | O_CREAT | O_NOCTTY | g_sc.o_cloexec | O_NOFOLLOW | O_NONBLOCK, 0644);
    OPENFD_CLOEXEC(fd);
    if (_log_fd_ok(fd))
      return fd;
    close(fd);
  }

  // from stderr
  if (isatty(STDERR_FILENO)) {
    fd = fcntl(STDERR_FILENO, g_sc.f_dupfd_cloexec, 3);
    DUPFD_CLOEXEC(fd);
    auto const flags = fcntl(fd, F_GETFL, 0);
    if (fd >= 3 && flags != -1 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1 && _log_fd_ok(fd))
      return fd;
    close(fd);
  }

#define FAIL_MSG "_log_fd() cannot find a valid fd"
  struct iovec iov = {.iov_base = FAIL_MSG, .iov_len = strlen(FAIL_MSG)};
  _log_write_syslogv(&iov, 1);
#undef FAIL_MSG

  fd = -1;
  return fd;
}
static void _log_writev(struct iovec *iov, int iovcnt) {
  static int fail_cnt = 0;
  int fd = _log_fd();
  if (-1 == fd || fail_cnt >= 10)
    return;
  if (iov) {
    const size_t fallback_n = (size_t)iovcnt <= 4 ? (size_t)iovcnt : 4;
    struct iovec fallback_v[4] = {
        0,
    };
    for (size_t i = 0; i < fallback_n; ++i)
      fallback_v[i] = iov[i];
    while (0 < iovcnt) {
      auto written = writev(fd, iov, iovcnt);
      if (-1 == written) {
        if (errno == EINTR)  // treat buffer full (EAGAIN or EWOULDBLOCK), etc. as errors
          continue;          // only continue on signals, which are handled after writing
        write(fd, "\n", 1);
        _log_write_syslogv(fallback_v, fallback_n);
        ++fail_cnt;
        return;
      }
      while (iovcnt > 0 && written >= (ssize_t)iov->iov_len) {
        written -= iov->iov_len;
        ++iov;
        --iovcnt;
      }
      if (written > 0) {
        iov->iov_base = (char *)iov->iov_base + written;
        iov->iov_len -= written;
      }
    }
  } else if (isatty(fd))
    tcflush(fd, TCOFLUSH);  // flush tty
  else {
    struct stat st;
    if (fstat(fd, &st) >= 0 && S_ISREG(st.st_mode))
      fdatasync(fd);
  }
}
static void _log_error(char *const file, const int flen, char *const fmt, ...) {
  auto const old_errno = errno;
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  auto n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  auto const len = n < 0 ? strlen(fmt) : ((size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1);
  auto const errmsg = old_errno ? strerror(old_errno) : "";
  struct iovec iov[] = {
      {.iov_base = file, .iov_len = flen},
      {.iov_base = n < 0 ? fmt : buf, .iov_len = len},
      {.iov_base = (old_errno ? ": " : ""), .iov_len = (old_errno ? 2 : 0)},
      {.iov_base = errmsg, .iov_len = strlen(errmsg)},
      {.iov_base = "\n", .iov_len = 1},
  };
  _log_writev(iov, ARRAY_SIZE(iov));
  errno = old_errno;
}
#define ERR(fmt, ...) _log_error(__FILE__, strlen(__FILE__), ":%d " fmt, __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#define FATAL(err, ...)      \
  do {                       \
    ERR(__VA_ARGS__);        \
    _log_writev(nullptr, 0); \
    _Exit(err);              \
  } while (0)

#ifdef ENABLE_DEBUG_LOG
#  define DEBUG(pid, event, sig, msg)                                                                         \
    do {                                                                                                      \
      errno = 0;                                                                                              \
      _log_error(__FILE__, strlen(__FILE__), ":%d [c=%d][ev=%d][sig=%d] %s", __LINE__, pid, event, sig, msg); \
    } while (0)
#else  // ENABLE_DEBUG_LOG
#  define DEBUG(...) ((void)0)
#endif  // ENABLE_DEBUG_LOG

////////// Signals handlers ////////////
static sigset_t sig_mask_all, sig_mask_init;
static atomic_uint_fast32_t pending_signal;
static sigjmp_buf sig_jump_env;
static atomic_uintptr_t sig_crash_ip;
static_assert(ATOMIC_INT_LOCK_FREE == 2);
static_assert(ATOMIC_LONG_LOCK_FREE == 2);
static_assert(ATOMIC_LLONG_LOCK_FREE == 2);
static_assert(ATOMIC_POINTER_LOCK_FREE == 2);

#define _SIGBIT1(x) (UINT64_C(1) << (x))
#define _SIGBIT2(x, y) (_SIGBIT1(x) | _SIGBIT1(y))
#define _SIGBIT3(x, y, z) (_SIGBIT1(x) | _SIGBIT1(y) | _SIGBIT1(z))
#define _SIGBIT4(a, b, c, d) (_SIGBIT2(a, b) | _SIGBIT2(c, d))
#define _SIGBIT5(a, b, c, d, e) (_SIGBIT3(a, b, c) | _SIGBIT2(d, e))

// bit 0: kill all tracees
// bit SIGKILL: if set, kill all tracees with SIGKILL
// bit SIGSTOP: stop/continue tracees
static const uint_fast32_t signal_or_bits[32] = {
    // must not register handler:
    // - control bits
    // - for waitpid()
    [0] = 0,
    [SIGKILL] = 0,
    [SIGSTOP] = 0,
    [SIGCHLD] = 0,  // to cooperate with waitpid()
    [SIGTRAP] = 0,
    [SIGWINCH] = 0,  // default SIG_IGN

    [SIGPIPE] = UINT_FAST32_MAX,  // let write() api handle
    [SIGXFSZ] = UINT_FAST32_MAX,  // let write() api handle
    [SIGIO] = UINT_FAST32_MAX,    // do not use SIGIO mode IO
    [SIGPWR] = UINT_FAST32_MAX,

    // dencent exit
    [SIGINT] = _SIGBIT2(SIGINT, 0),
    [SIGQUIT] = _SIGBIT2(SIGQUIT, 0),
    [SIGTERM] = _SIGBIT2(SIGTERM, 0),
    [SIGALRM] = _SIGBIT2(SIGALRM, 0),      // tracer does not use timer
    [SIGURG] = _SIGBIT2(SIGURG, 0),        // tracer does not use network
    [SIGVTALRM] = _SIGBIT2(SIGVTALRM, 0),  // tracer does not use virtual timer
    [SIGPROF] = _SIGBIT2(SIGPROF, 0),      // tracer does not use prof timer

    // force exit
    [SIGILL] = _SIGBIT3(SIGILL, 0, SIGKILL),
    [SIGABRT] = _SIGBIT3(SIGABRT, 0, SIGKILL),
    [SIGBUS] = _SIGBIT3(SIGBUS, 0, SIGKILL),
    [SIGFPE] = _SIGBIT3(SIGFPE, 0, SIGKILL),
    [SIGSEGV] = _SIGBIT3(SIGSEGV, 0, SIGKILL),
    [SIGSTKFLT] = _SIGBIT3(SIGSTKFLT, 0, SIGKILL),
    [SIGXCPU] = _SIGBIT3(SIGXCPU, 0, SIGKILL),
    [SIGSYS] = _SIGBIT3(SIGSYS, 0, SIGKILL),

    // stop/continue all tracees
    [SIGCONT] = _SIGBIT2(SIGCONT, SIGSTOP),
    [SIGTSTP] = _SIGBIT2(SIGTSTP, SIGSTOP),
    [SIGTTIN] = _SIGBIT2(SIGTTIN, SIGSTOP),  // handle group-stop
    [SIGTTOU] = _SIGBIT2(SIGTTOU, SIGSTOP),

    // from kernel: ignore
    // from user: forward with dedup
    [SIGUSR1] = _SIGBIT1(SIGUSR1),
    [SIGUSR2] = _SIGBIT1(SIGUSR2),

    // from kernel (tty closes or network brokes): self ignore, do not forward
    // from shell (shell exit): self ignore, forward with dedup
    // from user (kill pid or kill -pid): self ignore, forward with dedup
    [SIGHUP] = _SIGBIT1(SIGHUP),
};

static inline const char *sig_core_name(const int s) {
#define _CORE(s) \
  case s:        \
    return #s
  switch (s) {
    _CORE(SIGABRT);
    _CORE(SIGBUS);
    _CORE(SIGFPE);
    _CORE(SIGILL);
    _CORE(SIGSEGV);
    _CORE(SIGSYS);
  }
#undef _CORE
  return nullptr;
}

#define _SIG_IS_VALID(a) (0 != (uint_fast32_t)(((a) + 1) >> 1))
// #define _SIG_IS_CONTROL(a) (0 != ((a) & _SIGBIT2(0, SIGSTOP)))
#define _SIG_FROM_USER(p) (LIKELY(p) && ((p)->si_code == SI_USER || (p)->si_code == SI_TKILL))

static void tracer_sigaction_handler(const int sig, siginfo_t *const info, void *const ctx) {
  if (sig_core_name(sig) && info->si_code > 0) {
    // self blocking signal, exit immediately
    auto const instruction_pointer =
#if defined(ARCH_X64)
        (uintptr_t)(((const ucontext_t *)ctx)->uc_mcontext.gregs[REG_RIP]);
#elif defined(ARCH_ARM64)
        (uintptr_t)(((const ucontext_t *)ctx)->uc_mcontext.pc);
#else  // ARCH_RISCV64
        (uintptr_t)(((const ucontext_t *)ctx)->uc_mcontext.__gregs[REG_PC]);
#endif
    atomic_store_explicit(&sig_crash_ip, instruction_pointer, memory_order_relaxed);
    siglongjmp(sig_jump_env, sig);
    _Exit(128 + sig);  // should never come here
  }

  auto const action = signal_or_bits[sig];  // handler is reg by going through signal_or_bits array
  if ((action & _SIGBIT1(0)) || _SIG_FROM_USER(info) || sig == SIGCONT) {
    // hand signals in main():
    //  - all kill signals
    //  - from kill() or tgkill()
    // ignore all non-exit handlers from kernel, including group-stop/cont signals
    if (action & _SIGBIT1(SIGSTOP)) {
      atomic_fetch_and_explicit(&pending_signal, ~_SIGBIT5(SIGTTIN, SIGTTOU, SIGTSTP, SIGCONT, SIGSTOP),
                                memory_order_relaxed);
    }
    atomic_fetch_or_explicit(&pending_signal, action, memory_order_relaxed);
  }
}

static int min_exit_signal(const uint_fast32_t signals, const bool kill) {
  if (signals & _SIGBIT1(0)) {
    for (size_t s = 1; s < ARRAY_SIZE(signal_or_bits); ++s) {
      auto const bits = signal_or_bits[s];
      auto const group = kill ? _SIGBIT1(SIGKILL) : _SIGBIT1(0);
      if (_SIG_IS_VALID(bits) && (bits & group) && bits == (signals & bits)) {
        return s;
      }
    }
  }
  return 0;
}

static bool needs_sentinel() {
  auto const fd = open(ctermid(nullptr), O_RDONLY | O_NOCTTY | g_sc.o_cloexec);
  OPENFD_CLOEXEC(fd);
  if (fd < 0)
    return false;
  const pid_t fg_pgrp = tcgetpgrp(fd);
  close(fd);
  return fg_pgrp != -1;
}

static pid_t tracer_in_sentinel = -1;
static void sentinel_sigaction_handler(const int sig, siginfo_t *const info, void *) {
  auto const from_user = _SIG_FROM_USER(info);
  switch (sig) {
  case SIGHUP:
    [[fallthrough]];
  case SIGUSR1:
    [[fallthrough]];
  case SIGUSR2:
    if (from_user)
      kill(tracer_in_sentinel, sig);
    break;

  case SIGINT:
    [[fallthrough]];
  case SIGQUIT:
    [[fallthrough]];
  case SIGTERM:
    [[fallthrough]];
  case SIGALRM:
    [[fallthrough]];
  case SIGURG:
    [[fallthrough]];
  case SIGVTALRM:
    [[fallthrough]];
  case SIGPROF:
    kill(tracer_in_sentinel, sig);
    break;

  case SIGILL:
    [[fallthrough]];
  case SIGABRT:
    [[fallthrough]];
  case SIGBUS:
    [[fallthrough]];
  case SIGFPE:
    [[fallthrough]];
  case SIGSEGV:
    [[fallthrough]];
  case SIGSTKFLT:
    [[fallthrough]];
  case SIGXCPU:
    [[fallthrough]];
  case SIGSYS:
    kill(tracer_in_sentinel, SIGABRT);
    if (!from_user)
      _Exit(128 + sig);
    break;

  default:
    _Exit(128 + sig);
  }
}

static void setup_sentinel_if_need_or_die() {
  if (!needs_sentinel())
    return;

  auto const tracer = _OK_CALL(fork(), _ >= 0, _Exit(64));

  if (tracer == 0)
    return;  // tracer as child

  // sentinel as parent
  tracer_in_sentinel = tracer;
  struct sigaction sa = {
      .sa_flags = SA_SIGINFO | SA_RESTART,
      .sa_sigaction = sentinel_sigaction_handler,
  };
  _OK_CALL(sigaction(SIGHUP, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGUSR1, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGUSR2, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGINT, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGQUIT, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGTERM, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGALRM, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGURG, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGVTALRM, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGPROF, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGILL, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGABRT, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGBUS, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGFPE, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGSEGV, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGSTKFLT, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGXCPU, &sa, nullptr), _ == 0, _Exit(64));
  _OK_CALL(sigaction(SIGSYS, &sa, nullptr), _ == 0, _Exit(64));

  // restore signal masks
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), 0 == _, _Exit(65));

  while (true) {
    siginfo_t info = {.si_pid = 0};  // clear si_pid
    if (waitid(P_PID, tracer, &info, WEXITED) == 0 && info.si_pid == tracer) {
      if (info.si_code == CLD_EXITED)
        _Exit(info.si_status);
      else
        _Exit(128 + info.si_status);
    }
  }
}

static void setup_signal_handlers_or_die() {
  auto const die_fd = _log_fd();  // init log fd
  auto const die_sig = sigsetjmp(sig_jump_env, 1);
  if (die_sig) {
    // async signal safe urging exit
    if (die_fd != -1) {
      auto const signame = sig_core_name(die_sig);
      auto const crash_ip = atomic_load_explicit(&sig_crash_ip, memory_order_relaxed);
      static char crash_ip_str[] = "0x0123456789abcdef !!!\n", map[] = "0123456789abcdef";
      char *p = crash_ip_str + 2;
      for (int shift = 15 * 4; 0 <= shift; shift -= 4)
        *p++ = map[(crash_ip >> shift) & 0x0F];
#define M0 "!!! CRASH SIGNAL = "
#define M1 (signame ? signame : "?")
#define M2 " RIP = "
      write(die_fd, M0, strlen(M0));
      write(die_fd, M1, strlen(M1));
      write(die_fd, M2, strlen(M2));
      write(die_fd, crash_ip_str, strlen(crash_ip_str));
#undef M0
#undef M1
#undef M2
    }
    _Exit(128 + die_sig);
  }

  struct sigaction sa = {
      .sa_flags = SA_SIGINFO,  // DO *NOT* SET SA_RESTART
      .sa_sigaction = tracer_sigaction_handler,
  };
  struct sigaction sa_tstp = {
      .sa_flags = SA_SIGINFO,  // DO *NOT* SET SA_RESTART
      .sa_sigaction = tracer_sigaction_handler,
  };
  struct sigaction sa_cont = {
      .sa_flags = SA_SIGINFO,  // DO *NOT* SET SA_RESTART
      .sa_sigaction = tracer_sigaction_handler,
  };

  _OK_CALL(sigemptyset(&sa.sa_mask), _ == 0, _Exit(66));
  _OK_CALL(sigemptyset(&sa_tstp.sa_mask), _ == 0, _Exit(67));
  _OK_CALL(sigemptyset(&sa_cont.sa_mask), _ == 0, _Exit(68));

  // avoid overlap between SIGCONT and SIGSTOP
  _OK_CALL(sigaddset(&sa_tstp.sa_mask, SIGCONT), _ == 0, _Exit(69));
  _OK_CALL(sigaddset(&sa_cont.sa_mask, SIGTSTP), _ == 0, _Exit(70));

  // setup normal signals
  for (size_t s = 1; s < ARRAY_SIZE(signal_or_bits); ++s) {
    auto const action = signal_or_bits[s];
    if (action == UINT_FAST32_MAX)
      _OK_CALL(signal(s, SIG_IGN), _ != SIG_ERR, _Exit(128 + s));
    else if (action) {
      auto const psa = s == SIGTSTP ? &sa_tstp : (s == SIGCONT ? &sa_cont : &sa);
      _OK_CALL(sigaction(s, psa, nullptr), _ == 0, _Exit(128 + s));
    }
  }

  // ignore all rt signals, and donot forward to the tracee root
  for (int rt = SIGRTMIN; rt <= SIGRTMAX; ++rt)
    _OK_CALL(signal(rt, SIG_IGN), _ != SIG_ERR, _Exit(128 + rt));

  // restore signal masks
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), _ == 0, _Exit(66));
}

////////// PIDs table ////////////
typedef union {
  uint64_t raw;
  struct {
    uint32_t bits;
    uint32_t next;
  };
} pids_slot;
static_assert(sizeof(pids_slot) == 8);
constexpr auto pids_slot_bits_nr = sizeof_member(pids_slot, bits) * 8;

static pids_slot *pids;
static uint32_t pids_base_offset;
static uint32_t pids_base_mask;
static bool pids_init(const pid_t child) {
  // get pid max
  uint32_t pid_max = UINT32_C(1 << 22);
  auto const fd = _OK_CALL(open("/proc/sys/kernel/pid_max", O_RDONLY | g_sc.o_cloexec), _ != -1);
  OPENFD_CLOEXEC(fd);

  if (fd != -1) {
    char buf[32];
    ssize_t total_read = 0;
    while (total_read < (ssize_t)sizeof(buf) - 1) {
      ssize_t rb = read(fd, buf + total_read, sizeof(buf) - 1 - total_read);
      if (rb == 0)
        break;  // EOF
      if (rb == -1) {
        if (errno == EINTR)
          continue;  // stopped by signal
        close(fd);
        goto PID_MAX_DEFAULT;
      }
      total_read += rb;
    }
    close(fd);
    buf[total_read] = '\0';

    // parse pid max
    char *endptr = nullptr;
    static_assert(sizeof(long) >= sizeof(pid_max) && sizeof(pid_max) >= sizeof(pid_t));
    static_assert(sizeof(long) == sizeof(int64_t));
    errno = 0;
    auto pid_max_long =
        _OK_CALL_DEF(strtol(buf, &endptr, 10),
                     endptr != buf && INT64_C(4096) <= _ && _ < (INT64_C(1) << 31) && errno == 0, INT64_C(1 << 22));
    pid_max = (uint32_t)pid_max_long;
  PID_MAX_DEFAULT:
  }
  pid_max = (uint32_t)(UINT64_C(1) << (sizeof(pid_max) * 8 - __builtin_clz(pid_max - 1)));  // round to the next 2 power
  pids_base_offset = pid_max - (uint32_t)child;  // pid_max is a exclusive limit, so child in [1, pid_max-1]
  pids_base_mask = pid_max - 1;

  auto const page_size = _OK_CALL(getpagesize(), _ >= 1024, return false);
  auto const pid_slots_nr = (pid_max + pids_slot_bits_nr - 1) / pids_slot_bits_nr;
  auto const pid_page_nr = ((pid_slots_nr * sizeof(pids_slot)) + page_size - 1) / page_size;
  auto const pid_mmap_size = pid_page_nr * page_size;

  pids = _OK_CALL(mmap(NULL, pid_mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                  _ != MAP_FAILED, return false);

  return true;
}
static inline pid_t pids_tracee0() { return (pid_t)(pids_base_mask - pids_base_offset + 1); }
static pids_slot *pids_slot_search(const uint32_t slot, const bool add) {
  auto const curr = pids + slot;
  if (slot && 0 == curr->raw) {  // link head (slot 0) is always active
    // a free slot
    if (add) {
      curr->next = pids->next;
      pids->next = slot;
    } else {
      return nullptr;  // found a free slot
    }
  }

  if (0 != curr->next) {
    auto const next = pids + curr->next;
    if (next->bits == 0) {  // remove the dangling next slot
      curr->next = next->next;
      next->raw = 0;  // clear
    }
  }

  return curr;
}
static inline void pids_add(const pid_t pid) {
  auto const p = ((uint32_t)pid + pids_base_offset) & pids_base_mask;
  pids_slot_search(p >> 5, true)->bits |= _SIGBIT1(p & 31);
}
static inline void pids_del(const pid_t pid) {
  auto const p = ((uint32_t)pid + pids_base_offset) & pids_base_mask;
  auto const curr = pids_slot_search(p >> 5, false);
  if (curr)
    curr->bits &= ~_SIGBIT1(p & 31);
}
static void pids_kill_all(const int sig) {
  for (uint32_t curr = 0, prev = 0; curr + 1; curr = 0 == pids[curr].next ? UINT32_C(-1) : pids[curr].next) {
    auto const slot = pids + curr;
    for (auto bits = slot->bits; bits; bits &= bits - 1) {
      auto const ctz = __builtin_ctz(bits);
      const pid_t child = ((curr << 5) + ctz - pids_base_offset) & pids_base_mask;
      if (-1 == kill(child, sig)) {  // use kill to support centos 5 or 6
        switch (errno) {
        case ESRCH:
          slot->bits &= ~_SIGBIT1(ctz);  // remove non existing child quickly
        case EPERM:
          break;  // ignore permission error
        default:
          FATAL(128 + sig, "BUG");  // bug if EINVAL or other unknown errors
        }
      }
    }
    if (slot != pids && 0 == slot->bits) {  // remove from the list
      pids[prev].next = slot->next;
      slot->raw = 0;  // clear
      curr = prev;
    } else
      prev = curr;
  }
}
static bool pt_cont(const pid_t pid, const int sig);
static void pids_pt_cont_all() {
  for (uint32_t curr = 0, prev = 0; curr + 1; curr = 0 == pids[curr].next ? UINT32_C(-1) : pids[curr].next) {
    auto const slot = pids + curr;
    for (auto bits = slot->bits; bits; bits &= bits - 1) {
      auto const ctz = __builtin_ctz(bits);
      const pid_t child = ((curr << 5) + ctz - pids_base_offset) & pids_base_mask;
      pt_cont(child, 0);
    }
    if (slot != pids && 0 == slot->bits) {  // remove from the list
      pids[prev].next = slot->next;
      slot->raw = 0;  // clear
      curr = prev;
    } else
      prev = curr;
  }
}
static void pids_kill_tracee0(const int sig) {
  auto const tracee0 = pids_tracee0();
  if (-1 == kill(tracee0, sig)) {
    switch (errno) {
    case ESRCH:
      pids->bits &= ~_SIGBIT1(0);  // tracee0 is on slot 0 bit 0
    case EPERM:
      break;  // ignore permission error
    default:
      FATAL(128 + sig, "BUG");  // bug if EINVAL or other unknown errors
    }
  }
}

////////// Init System Config/Feature ////////////
static bool init_sys_config() {
  g_sc.pagesz = _OK_CALL(sysconf(_SC_PAGESIZE), _ >= 4096 && is_power_2(_), return false);
  g_sc.max_arg_strlen = 32 * g_sc.pagesz;

#ifdef ARCH_X64
  {
    auto const null_fd = _OK_CALL(open("/dev/null", O_RDONLY | O_CLOEXEC), _ >= 0, return false);
    auto const null_fd_flags = _OK_CALL(fcntl(null_fd, F_GETFD), _ != -1, return false);
    auto const null_dupfd = fcntl(null_fd, F_DUPFD_CLOEXEC);

    g_sc.o_cloexec = (null_fd_flags & FD_CLOEXEC) != 0 ? O_CLOEXEC : 0;
    g_sc.f_dupfd_cloexec = 0 <= null_dupfd ? F_DUPFD_CLOEXEC : F_DUPFD;
    close(null_dupfd);
    close(null_fd);
  }
#else
  g_sc.o_cloexec = O_CLOEXEC;
  g_sc.f_dupfd_cloexec = F_DUPFD_CLOEXEC;
#endif

#ifdef ARCH_ARM64
#  ifndef PROT_BTI
#    define PROT_BTI 0x10
#  endif
  {
    auto const p = mmap(NULL, g_sc.pagesz, PROT_READ | PROT_EXEC | PROT_BTI, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_sc.prot_bti = p != MAP_FAILED ? PROT_BTI : 0;
    if (g_sc.prot_bti)
      munmap(p, g_sc.pagesz);
  }
#endif

  // test process_vm_readv and process_vm_writev
  {
#ifdef ARCH_X64
    char buf;
    const struct iovec local = {&buf, 1};
    const struct iovec remote = {&buf, 1};
    auto const ret = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    g_sc.has_vm_rwv = ret == -1 && errno == ENOSYS;
#endif
  }
  return true;
}
#ifdef ARCH_X64
static bool init_sys_config_ptrace(const pid_t pid, bool exitkill) {
  g_sc.has_ptrace_exitkill = exitkill;

  struct iovec iov = {.iov_base = NULL, .iov_len = 0};
  if (0 == ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))
    g_sc.has_ptrace_getregset = true;
  return true;
}
#endif

////////// Global Buffer ////////////
// Global static buffer to copy the tracee data or as an temp buffer.
// The pointer and the size must be align to the system pagesize.
// Automatically unmapped when the tracer is terminated.
static int8_t *g_buffer;
static size_t calc_g_buffer_sz(size_t);
static bool alloc_g_buffer() {
  auto const arg_max = _OK_CALL(sysconf(_SC_ARG_MAX), _POSIX_ARG_MAX <= _ && _ <= INT64_C(4194304), return false);
  auto const aligned_size = align_page_u(calc_g_buffer_sz(arg_max));  // align up to page size
  if (UNLIKELY(aligned_size >= (UINT64_C(1) << 32)))
    return false;  // less then 4G

  g_buffer = _OK_CALL(mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                      _ != MAP_FAILED, return false);
  return true;
}

////////// INTERP ////////////
#if defined(ARCH_X64)
#  define SYS_INTERP_PATH "/lib64/ld-linux-x86-64.so.2"
#  define INTERP_NAME "/ld-linux-x86-64.so.2"
#  define CONDA_ARCH_TRIPLE "x86_64-conda-linux-gnu"
#  define ELF_ARCH EM_X86_64
#elif defined(ARCH_ARM64)
#  define SYS_INTERP_PATH "/lib/ld-linux-aarch64.so.1"
#  define INTERP_NAME "/ld-linux-aarch64.so.1"
#  define CONDA_ARCH_TRIPLE "aarch64-conda-linux-gnu"
#  define ELF_ARCH EM_AARCH64
#else  // riscv64 with lp64d ABI
#  define SYS_INTERP_PATH "/lib/ld-linux-riscv64-lp64d.so.1"
#  define CONDA_ARCH_TRIPLE "riscv64-conda-linux-gnu"
#  define INTERP_NAME "/ld-linux-riscv64-lp64d.so.1"
#  define ELF_ARCH EM_RISCV
#endif
#define SYS_INTERP_PATH_WORD_NR ((sizeof(SYS_INTERP_PATH) + sizeof(uint64_t) - 1) / sizeof(uint64_t))
#define CONDA_INTERP_PATH "/" CONDA_ARCH_TRIPLE "/sysroot" SYS_INTERP_PATH
#define MAX_MMAP_CNT 128

typedef struct {
  char path[PATH_MAX];  // set to empty string when initialized incorrectly
  char libc_dir[PATH_MAX];
  uint64_t filesz;
  uintptr_t entry_vaddr;
  bool is_dyn;
  uint16_t pt_mmap_cnt;
  size_t total_memsz;
  mmap_param_t pt_mmap_params[MAX_MMAP_CNT];
} elf_info_t;

static_assert((unsigned)(PROT_READ | PROT_WRITE | PROT_EXEC) < 8);

static elf_info_t target_interp;
static elf_info_t system_interp;
static elf_info_t chlibc_info;
static elf_info_t loader_info;
static size_t chlibc_root_len = 0;
static char chlibc_root[PATH_MAX + 1];

#define GETENV_SAFE(var) ((env = getenv(var)) && env[0] != '\0')
static const char *find_target_interp_path() {
  static char resolved_path[PATH_MAX];
  char tmp[PATH_MAX * 2];
  const char *env;

  // $CHLIBC_INTERP
  if (GETENV_SAFE("CHLIBC_INTERP") && realpath(env, resolved_path))
    return resolved_path;
  // $CHLIBC_GLIBC_HOME/{interp-basename}
  if (GETENV_SAFE("CHLIBC_GLIBC_HOME") && realpath(env, tmp) && strcat(tmp, INTERP_NAME)) {
    if (realpath(tmp, resolved_path))
      return resolved_path;
  }
  // $CONDA_PREFIX/<arch>/sysroot/{lib64,lib}/{interp-basename}
  if (GETENV_SAFE("CONDA_PREFIX") && realpath(env, tmp) && strcat(tmp, CONDA_INTERP_PATH)) {
    if (realpath(tmp, resolved_path))
      return resolved_path;
  }
  // dirname($0)/../<arch>/sysroot/{lib64,lib}/{interp-basename}
  if (strcat(dirname(dirname(strcpy(tmp, chlibc_info.path))), CONDA_INTERP_PATH)) {
    if (realpath(tmp, resolved_path))
      return resolved_path;
  }
  ERR("no valid interp found");
  return nullptr;
}
static const char *find_target_libc_dir() {
  static char resolved_path[PATH_MAX];
  char tmp[PATH_MAX * 2];
  const char *env;

  // $CHLIBC_GLIBC_HOME
  if (GETENV_SAFE("CHLIBC_GLIBC_HOME") && realpath(env, resolved_path))
    return resolved_path;
  // $CONDA_PREFIX/<arch>/sysroot/{lib64,lib}
  if (GETENV_SAFE("CONDA_PREFIX") && realpath(env, tmp) && strcat(tmp, CONDA_INTERP_PATH)) {
    if (realpath(tmp, resolved_path))
      return dirname(resolved_path);
  }
  // dirname($CHLIBC_INTERP)
  if (GETENV_SAFE("CHLIBC_INTERP") && realpath(env, resolved_path))
    return dirname(resolved_path);
  // dirname($0)/../<arch>/sysroot/{lib64,lib}
  if (strcat(dirname(dirname(strcpy(tmp, chlibc_info.path))), CONDA_INTERP_PATH)) {
    if (realpath(tmp, resolved_path))
      return dirname(resolved_path);
  }
  ERR("no valid glibc dir found");
  return nullptr;
}
static bool init_chlibc_root() {
  const char *env;
  bool rst = false;

  if (GETENV_SAFE("CHLIBC_PREFIX") && realpath(env, chlibc_root))
    rst = true;  // CHLIBC_PREFIX
  else if (GETENV_SAFE("CONDA_PREFIX") && realpath(env, chlibc_root))
    rst = true;  // CONDA_PREFIX
  else if (dirname(strcpy(chlibc_root, chlibc_info.path)))
    rst = true;  // dirname($0)/..

  if (rst) {
    chlibc_root_len = strlen(chlibc_root);
    chlibc_root[chlibc_root_len++] = '/';
    chlibc_root[chlibc_root_len] = '\0';
  } else
    ERR("no valid chlibc prefix found");

  return rst;
}
#undef GETENV_SAFE

static inline int make_prot(const int p_flags) {
  int prot = 0;
  prot |= (p_flags & PF_R) ? PROT_READ : 0;
  prot |= (p_flags & PF_W) ? PROT_WRITE : 0;
  prot |= (p_flags & PF_X) ? PROT_EXEC : 0;
  return prot;
}

// parse and generate the mmap() plan of an interp elf
// ref: load_elf_interp() in https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c
static bool init_elf_info(const char *const path, const char *const libc_dir, elf_info_t *const info,
                          const bool must_static) {
  bool rst = false;
  if (!path)
    goto DONE;

  _OK_CALL(realpath(path, info->path), _ != nullptr, goto DONE);
  if (libc_dir)
    _OK_CALL(realpath(libc_dir, info->libc_dir), _ != nullptr, goto DONE);
  else
    info->libc_dir[0] = '\0';

  auto fd = _OK_CALL(open(info->path, O_RDONLY | O_NOCTTY | O_NOFOLLOW), _ >= 0, goto DONE);
  struct stat st;

  _OK_CALL(fstat(fd, &st), _ >= 0, goto CLEAN_FD_DONE);
  _OK_CALL(S_ISREG(st.st_mode), _ != 0, goto CLEAN_FD_DONE);
  _OK_CALL(st.st_size, (off_t)sizeof(Elf64_Ehdr) < _, goto CLEAN_FD_DONE);

  info->filesz = (uint64_t)st.st_size;
  auto const elf = _OK_CALL((const uint8_t *)mmap(NULL, info->filesz, PROT_READ, MAP_PRIVATE, fd, 0), _ != MAP_FAILED,
                            goto CLEAN_FD_DONE);
  close(fd);
  fd = -1;

  auto const ehdr = (const Elf64_Ehdr *)elf;
  if (!range_validate(0, sizeof(Elf64_Ehdr), info->filesz) ||
      !range_validate(ehdr->e_phoff, ehdr->e_phnum * sizeof(Elf64_Phdr), info->filesz))
    goto UNMAP_DONE;  // invalid elf

  _OK_CALL(memcmp(ehdr->e_ident, ELFMAG, SELFMAG), _ == 0, goto UNMAP_DONE);  // must elf
  _OK_CALL(ehdr->e_ident[EI_CLASS], _ == ELFCLASS64, goto UNMAP_DONE);        // must elf64
  _OK_CALL(ehdr->e_machine, _ == ELF_ARCH, goto UNMAP_DONE);                  // check arch
  _OK_CALL(ehdr->e_type, _ == ET_EXEC || _ == ET_DYN, goto UNMAP_DONE);       // check type

  info->entry_vaddr = ehdr->e_entry;
  info->is_dyn = ehdr->e_type == ET_DYN;
  info->pt_mmap_cnt = 0;
  info->total_memsz = 0;

  auto const phdr = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
  typeof_unqual(phdr->p_vaddr) prev_vaddr = 0;

  // parse all loadable segments
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    if (PT_INTERP == phdr[i].p_type && must_static)
      goto UNMAP_DONE;  // interp must be static linked

    if (PT_LOAD != phdr[i].p_type)
      continue;

    if (phdr[i].p_memsz < phdr[i].p_filesz || phdr[i].p_vaddr < prev_vaddr)
      // The file size may not be larger than the memory size. Loadable segment entries in the program header table
      // appear in ascending order, sorted on the p_vaddr member.
      goto UNMAP_DONE;
    if (!range_validate(phdr[i].p_vaddr, phdr[i].p_memsz, align_page_u_invalid))
      goto UNMAP_DONE;  // ensure total mapped memory, after aligned, is not overflow: sz + pgsz + vaddr <= 2^64
    if (phdr[i].p_filesz) {
      if (!range_validate(phdr[i].p_offset, phdr[i].p_filesz, info->filesz))
        goto UNMAP_DONE;  // file range overflow
      if (LIKELY(align_page_d_dist(phdr[i].p_offset) != align_page_d_dist(phdr[i].p_vaddr)))
        // Loadable process segments must have congruent values for p_vaddr and p_offset, modulo the page size.
        goto UNMAP_DONE;
    }

    prev_vaddr = phdr[i].p_vaddr;

    if (0 == phdr[i].p_memsz)  // skip empty segment
      continue;

    if (info->total_memsz < phdr[i].p_vaddr + phdr[i].p_memsz)
      info->total_memsz = phdr[i].p_vaddr + phdr[i].p_memsz;

    // Map "p_filesz" bytes from offset "p_offset" into memory at bias + "p_vaddr". Memory from "p_filesz" through
    // "p_memsz" rounded up to the next page is zeroed.
    // ref: elf_load()
    uint64_t zero_start, zero_end;  // start and end of full zero pages
    auto const prot = make_prot(phdr[i].p_flags);

    zero_end = align_page_u(phdr[i].p_vaddr + phdr[i].p_memsz);

    if (phdr[i].p_filesz) {
      if (MAX_MMAP_CNT <= info->pt_mmap_cnt)
        goto UNMAP_DONE;  // too many loadable segments
      info->pt_mmap_params[info->pt_mmap_cnt].prot = prot & 7;
      info->pt_mmap_params[info->pt_mmap_cnt].offset = align_page_d(phdr[i].p_offset);
      info->pt_mmap_params[info->pt_mmap_cnt].vaddr = align_page_d(phdr[i].p_vaddr);

      // length is designed not to align to the page boundary, then we known the tailing size for padzero()
      if (UNLIKELY((UINT64_C(1) << 61) <= align_page_d_dist(phdr[i].p_vaddr) + phdr[i].p_filesz)) {
        DEBUG(0, 0, 0, "segment is too large");
        goto UNMAP_DONE;
      }
      info->pt_mmap_params[info->pt_mmap_cnt].length = align_page_d_dist(phdr[i].p_vaddr) + phdr[i].p_filesz;

      info->pt_mmap_cnt++;

      zero_start = align_page_u(phdr[i].p_vaddr + phdr[i].p_filesz);
    } else
      zero_start = align_page_d(phdr[i].p_vaddr);

    if (zero_end > zero_start) {
      if (MAX_MMAP_CNT == info->pt_mmap_cnt)
        goto UNMAP_DONE;  // too many loadable segments
      info->pt_mmap_params[info->pt_mmap_cnt].prot = prot;
      info->pt_mmap_params[info->pt_mmap_cnt].offset = UINT64_C(-1);  // zero pages
      info->pt_mmap_params[info->pt_mmap_cnt].vaddr = zero_start;
      info->pt_mmap_params[info->pt_mmap_cnt].length = zero_end - zero_start;
      info->pt_mmap_cnt++;
    }
  }

  if (!info->pt_mmap_cnt || info->total_memsz == info->pt_mmap_params[0].vaddr)
    goto UNMAP_DONE;  // no loadable segments

  info->total_memsz = align_page_u(info->total_memsz - info->pt_mmap_params[0].vaddr);

  rst = true;

UNMAP_DONE:
  munmap((void *)elf, st.st_size);
CLEAN_FD_DONE:
  if (fd >= 0)
    close(fd);
DONE:
  info->path[0] &= -rst;
  return rst;
}

// convert chlibc to loader
static bool init_loader_info() {
  strcpy(loader_info.path, chlibc_info.path);
  loader_info.libc_dir[0] = 0;
  loader_info.filesz = loader_info.total_memsz = loader_info.pt_mmap_params[0].length = chlibc_info.filesz;
  loader_info.is_dyn = chlibc_info.is_dyn;
  loader_info.pt_mmap_cnt = 1;
  loader_info.pt_mmap_params[0].offset = 0;
  loader_info.pt_mmap_params[0].vaddr = 0;
  loader_info.pt_mmap_params[0].prot = PROT_READ | PROT_EXEC;

  extern void _start();                                                    // runtime entry
  auto const bias = (uintptr_t)&_start - chlibc_info.entry_vaddr;          // chlibc runtime bias
  auto const vaddr = (uint64_t)((typeof(bias))(uintptr_t)&loader - bias);  // loader linktime vaddr
  auto found = false;
  for (int i = 0; i < chlibc_info.pt_mmap_cnt; ++i) {
    auto const m = chlibc_info.pt_mmap_params + i;
    if (m->offset != UINT32_C(-1) && m->vaddr <= vaddr && vaddr < m->vaddr + m->length) {
      found = true;
      loader_info.entry_vaddr = m->offset + vaddr - m->vaddr;  // loader elf file offset
      break;
    }
  }

  return found;
}

////////// Ptrace ////////////
static pid_t tracer_pid;
static int ptrace_tracee0_exit_code = 1;
static bool ptrace_has_group_stopped = true;

static_assert(sizeof(ptrace(0)) == sizeof(uint64_t));
static_assert(__SIZEOF_INT128__ == 16);
typedef typeof(ptrace(0)) ptrace_return_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef __int128 pt_result_t;
static_assert(alignof(pt_result_t) == 16);
#pragma GCC diagnostic pop

#define PT_FAIL(r) ((int64_t)((r) >> 64) < 0)
#define PT_SUCCESS(r) (!PT_FAIL(r))
#define PT_ERRNO(r) ((typeof(errno))llabs((int64_t)((r) >> 64)))
#define PT_VALUE(r) ((ptrace_return_t)(r))
#define _PT_OP_IS_PEEK(op) ((op) == PTRACE_PEEKTEXT || (op) == PTRACE_PEEKDATA || (op) == PTRACE_PEEKUSER)
[[gnu::always_inline]]
static inline pt_result_t _pt_check_rst(const pid_t pid, const ptrace_return_t r, const bool is_peek, const bool strict,
                                        char *const file, const int flen, char *const msg, const int line) {
  auto const success = (typeof(r))-1 != r || (is_peek && 0 == errno);
  auto rst = success ? (pt_result_t)(uint64_t)r : (((pt_result_t)(uint64_t)(int64_t)(-errno) << 64) | UINT64_MAX);
  if (!success) {
    switch (errno) {
    case ESRCH:
      pids_del(pid);
      [[fallthrough]];
    case EPERM:
      if (!strict)
        rst = ((pt_result_t)(int64_t)errno << 64) | UINT64_MAX;  // success with errno in high word
      break;
    default:
      _log_error(file, flen, msg, line);
    }
  }
  return rst;
}

#define _PTRACE_CALL(op, pid, addr, data, strict)                                                                  \
  (_PT_OP_IS_PEEK(op) ? _pt_check_rst(pid, (errno = 0, ptrace(op, pid, addr, data)), true, strict, __FILE__,       \
                                      strlen(__FILE__), ":%d ptrace" _STR_HELPER((op, pid, addr, data)), __LINE__) \
                      : _pt_check_rst(pid, ptrace(op, pid, addr, data), false, strict, __FILE__, strlen(__FILE__), \
                                      ":%d ptrace" _STR_HELPER((op, pid, addr, data)), __LINE__))

// call ptrace(...)
#define PT_CALL(op, pid, addr, data) _PTRACE_CALL(op, pid, addr, data, false)
#define PT_CALL_S(op, pid, addr, data) _PTRACE_CALL(op, pid, addr, data, true)

// call high level ptrace related functions which returning pt_result_t
#define PT_OK_CALL_CHK(exp, ok_, ...)                                       \
  __extension__({                                                           \
    auto const r = _OK_CALL(exp, PT_SUCCESS(_) __VA_OPT__(, ) __VA_ARGS__); \
    auto const _ = PT_VALUE(r);                                             \
    if (!(ok_)) { /* check value */                                         \
      ERR(#exp);                                                            \
      __VA_ARGS__;                                                          \
    }                                                                       \
    _;                                                                      \
  })
#define PT_OK_CALL(exp, ...) PT_OK_CALL_CHK(exp, true __VA_OPT__(, ) __VA_ARGS__)

static inline bool pt_cont(const pid_t pid, const int sig) {
  DEBUG(pid, 0, sig, "PTRACE_CONT");
  return PT_SUCCESS(PT_CALL(PTRACE_CONT, pid, 0, sig));
}
static inline bool pt_singlestep(const pid_t pid, const int sig) {
  DEBUG(pid, 0, 0, "PTRACE_SINGLESTEP");
  return PT_SUCCESS(PT_CALL(PTRACE_SINGLESTEP, pid, 0, sig));
}
static inline pt_result_t pt_get_msg(const pid_t pid) {
  unsigned long msg = 0;
  auto const r = PT_CALL_S(PTRACE_GETEVENTMSG, pid, 0, &msg);
  return PT_SUCCESS(r) ? (pt_result_t)(uint64_t)msg : r;
}
#define PT_IS_GROUP_STOP(sig, err) \
  ((SIGSTOP == (sig) || SIGTSTP == (sig) || SIGTTIN == (sig) || SIGTTOU == (sig)) && (err) == EINVAL)
static inline pt_result_t pt_get_siginfo(const pid_t pid, siginfo_t dst[static 1]) {
  auto const req_sig = dst->si_signo;  // in-out parameter dst.si_signo must be the current signal
  auto const r = ptrace(PTRACE_GETSIGINFO, pid, 0, dst);
  auto const ok_rst = (pt_result_t)sizeof(*dst);
  if (LIKELY(r == 0))
    return ok_rst;

  if (UNLIKELY(r == -1 && PT_IS_GROUP_STOP(req_sig, errno)))
    return ((pt_result_t)(uint64_t)(int64_t)(-EINVAL) << 64) | UINT64_MAX;  // group-stop, skip error log

  auto const rfull = _pt_check_rst(pid, r, false, true, __FILE__, strlen(__FILE__),
                                   ":%d ptrace" _STR_HELPER((PTRACE_GETSIGINFO, pid, 0, &si)), __LINE__);
  return PT_SUCCESS(rfull) ? ok_rst : rfull;
}

static inline pt_result_t pt_get_regs(const pid_t pid, common_regs_t dst[static 1]) {
#ifdef ARCH_X64
  if (!g_sc.has_ptrace_getregset) {
    auto const r = PT_CALL_S(PTRACE_GETREGS, pid, 0, dst);
    return PT_SUCCESS(r) ? (pt_result_t)sizeof(*dst) : ((r >> 64) << 64);
  }
#endif

  struct iovec iov = {.iov_base = dst, .iov_len = sizeof(*dst)};
  auto const r = PT_CALL_S(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
  if (PT_SUCCESS(r)) {
    if (iov.iov_len == sizeof(*dst))
      return (pt_result_t)sizeof(*dst);
    errno = EFAULT;  // for output iov_len is changed
    return ((pt_result_t)(uint64_t)(int64_t)(-EFAULT) << 64) | iov.iov_len;
  }
  return ((r >> 64) << 64) | iov.iov_len;
}

static inline pt_result_t pt_get_user(const pid_t pid, const size_t ofs) {
  return PT_CALL_S(PTRACE_PEEKUSER, pid, ofs, 0);
}
#define pt_get(pid, ...)            \
  _Generic((__VA_ARGS__ + 0),       \
      int: pt_get_msg,              \
      siginfo_t *: pt_get_siginfo,  \
      common_regs_t *: pt_get_regs, \
      size_t: pt_get_user)((pid)__VA_OPT__(, ) __VA_ARGS__)

/*static inline*/ pt_result_t pt_set_regs(const pid_t pid, const common_regs_t dst[static 1]) {
#ifdef ARCH_X64
  if (!g_sc.has_ptrace_getregset)
    return PT_CALL_S(PTRACE_SETREGS, pid, 0, dst);
#endif
  const struct iovec iov = {.iov_base = (typeof_unqual(*dst) *)dst, .iov_len = sizeof(*dst)};
  return PT_CALL_S(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}
/*static inline*/ pt_result_t pt_set_user(const pid_t pid, const size_t ofs, const uint64_t data) {
  return PT_CALL_S(PTRACE_POKEUSER, pid, ofs, data);
}
#define pt_set(pid, addr, ...) \
  _Generic(addr, common_regs_t *: pt_set_regs, size_t: pt_set_user)((pid), (addr)__VA_OPT__(, ) __VA_ARGS__)

static inline pt_result_t pt_vm_rw(const pid_t pid, const uintptr_t remote, void *const local, const size_t len,
                                   const bool is_read) {
  const struct iovec iov_r = {(void *)remote, len}, iov_l = {local, len};
  auto const nread = syscall(is_read ? SYS_process_vm_readv : SYS_process_vm_writev, pid, &iov_l, 1, &iov_r, 1, 0);
  if (nread < 0) {
    errno = -nread;
    return ((pt_result_t)nread << 64) | 0;
  }
  if ((size_t)nread < len) {
    errno = EIO;
    return ((pt_result_t)(uint64_t)(int64_t)-EIO << 64) | nread;
  }
  return (pt_result_t)(uint64_t)nread;
}

static inline pt_result_t pt_read_word(const pid_t pid, const uintptr_t remote_addr) {
#ifndef ARCH_X64
  if (align_d_dist(remote_addr, 8) == 0)
#endif
    return PT_CALL_S(PTRACE_PEEKDATA, pid, remote_addr, 0);  // x64 or remote_addr is aligned to 8

  uint64_t data;
  auto const r = pt_vm_rw(pid, remote_addr, &data, sizeof(data), true);
  return ((r >> 64) << 64) | (PT_SUCCESS(r) ? data : UINT64_MAX);
}
static inline pt_result_t pt_write_word(const pid_t pid, const uintptr_t remote_addr, const unsigned long data) {
  return PT_CALL_S(PTRACE_POKEDATA, pid, remote_addr, data);
}

#define PT_READ_CHK(pid, remote_addr, ok_, ...) \
  PT_OK_CALL_CHK(pt_read_word(pid, remote_addr), ok_ __VA_OPT__(, ) __VA_ARGS__)
#define PT_READ(pid, remote_addr, ...) PT_READ_CHK(pid, remote_addr, true __VA_OPT__(, ) __VA_ARGS__)
#define PT_WRITE(pid, remote_addr, word, ...) \
  PT_OK_CALL(pt_write_word(pid, remote_addr, word) __VA_OPT__(, ) __VA_ARGS__)

// assume dst_sz and src_sz are multiple of (batch_word_nr * sizeof(uint64_t))
// in expr "until_first_word_", variable "_" is the 1st word of the batch
// when success, return the readed/written size in bytes, not include the 1st word matches "until_first_word_" when read
#define PT_READ_BULKS(pid, remote_addr, batch_word_nr, dst, dst_sz, ok_1st_word_, until_1st_word_, err_full, ...) \
  __extension__({                                                                                                 \
    static_assert(batch_word_nr > 0);                                                                             \
    auto _pt_bulks_remote = (const uint64_t *)(uintptr_t)(remote_addr);                                           \
    auto _pt_bulks_local = (uint64_t *)(uintptr_t)(dst);                                                          \
    size_t _pt_bulks_sz = 0, _pt_bulks_full = 1;                                                                  \
    while (_pt_bulks_sz < (dst_sz)) {                                                                             \
      auto const _ = PT_READ_CHK((pid), (uint64_t)(_pt_bulks_remote++), ok_1st_word_ __VA_OPT__(, ) __VA_ARGS__); \
      if (until_1st_word_) {                                                                                      \
        _pt_bulks_full = 0;                                                                                       \
        break;                                                                                                    \
      }                                                                                                           \
      *_pt_bulks_local++ = _;                                                                                     \
      _pt_bulks_sz += sizeof(uint64_t);                                                                           \
      for (auto _pt_bulks_left = (batch_word_nr) - 1; _pt_bulks_left--; _pt_bulks_sz += sizeof(uint64_t))         \
        *_pt_bulks_local++ = PT_READ((pid), (uint64_t)(_pt_bulks_remote++)__VA_OPT__(, ) __VA_ARGS__);            \
    }                                                                                                             \
    if (err_full && _pt_bulks_full) {                                                                             \
      ERR("bulk read dest buffer is full: %s -> %s", #remote_addr, #dst);                                         \
      __VA_ARGS__;                                                                                                \
    }                                                                                                             \
    _pt_bulks_sz;                                                                                                 \
  })

#ifdef ARCH_X64
#  define _PT_BUCKS_USE_VM_API(remote_addr, sz, force) (!(force) && 8 < (sz) && g_sc.has_vm_rwv)
#else
#  define _PT_BUCKS_USE_VM_API(remote_addr, sz, force) (!(force) && (8 < (sz) || align_d_dist(remote_addr, 8) != 0))
#endif

#define PT_READ_BULKS_FAST(pid, remote_addr, dst, dst_sz, ...)                                                       \
  __extension__({                                                                                                    \
    size_t _pt_bulks_sz = 0;                                                                                         \
    if (_PT_BUCKS_USE_VM_API(remote_addr, dst_sz, false))                                                            \
      _pt_bulks_sz = PT_OK_CALL(pt_vm_rw(pid, remote_addr, dst, dst_sz, true) __VA_OPT__(, ) __VA_ARGS__);           \
    else                                                                                                             \
      _pt_bulks_sz = PT_READ_BULKS(pid, remote_addr, 1, dst, dst_sz, true, false, false __VA_OPT__(, ) __VA_ARGS__); \
    _pt_bulks_sz;                                                                                                    \
  })
#define PT_WRITE_BULKS(pid, remote_addr, src, src_sz, force, ...)                                           \
  __extension__({                                                                                           \
    size_t _pt_bulks_sz = 0;                                                                                \
    if (_PT_BUCKS_USE_VM_API(remote_addr, src_sz, force))                                                   \
      _pt_bulks_sz = PT_OK_CALL(pt_vm_rw(pid, remote_addr, src, src_sz, false) __VA_OPT__(, ) __VA_ARGS__); \
    else {                                                                                                  \
      auto _pt_bulks_remote = (const uint64_t *)(uintptr_t)(remote_addr);                                   \
      auto _pt_bulks_local = (uint64_t *)(uintptr_t)(src);                                                  \
      for (; _pt_bulks_sz < (src_sz); _pt_bulks_sz += sizeof(uint64_t))                                     \
        PT_WRITE((pid), (uint64_t)(_pt_bulks_remote++), *_pt_bulks_local++ __VA_OPT__(, ) __VA_ARGS__);     \
    }                                                                                                       \
    _pt_bulks_sz;                                                                                           \
  })

// assume size is multiple of sizeof(uint64_t), return the length not including '\0'
// when success: return strlen(buf), buf[return] == 0
// when overflow: return size, buf[size-1] == 0
// when error: return -1, buf[0] == 0
static size_t pt_read_cstring(const pid_t pid, uintptr_t remote_addr, void *const buf, const size_t size) {
  size_t copied = 0;
  uint64_t *wbuf = buf;
  uint8_t *const cbuf = buf;
  while (copied < size) {
    *wbuf = PT_READ(pid, remote_addr, *cbuf = 0; return (size_t)-1);
    auto const p = memchr(wbuf, 0, sizeof(*wbuf));
    if (p)
      return copied + ((uintptr_t)p - (uintptr_t)wbuf);  // not including '\0'
    ++wbuf;
    copied += sizeof(uint64_t);
    remote_addr += sizeof(uint64_t);
  }
  cbuf[size - 1] = 0;
  return size;  // overflow
}

[[noreturn]]
static void kill9_child_and_exit(const pid_t child, const int code) {
  _OK_CALL(kill(child, SIGKILL), _ == 0 || errno == ESRCH);
  _Exit(code);
}

static void ptrace_handshake_as_tracer_or_die(const pid_t child) {
  int status;
  while (true) {
    // only process term signals, ignore others signals including stop/cont
    {
      auto const signals = atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed);
      _OK_CALL(min_exit_signal(signals, false), _ == 0, kill9_child_and_exit(child, 128 + _));
    }

    // wait child stop
    auto const p = _OK_CALL(waitpid(child, &status, 0), _ == -1 || _ == child, kill9_child_and_exit(child, 64));
    if (-1 == p) {
      switch (errno) {
      case ECHILD:  // child does not exist
        FATAL(65, "child exits before ptrace handshaking");
      case EINTR:  // caught signals
        continue;
      default:
        FATAL(66, "waitpid when ptrace handshaking");
      }
    }

    break;
  }

  // the first stop, do handshake
  if (WIFEXITED(status)) {
    _Exit(WEXITSTATUS(status));  // child exits by exit()
  } else if (WIFSIGNALED(status)) {
    _Exit(128 + WTERMSIG(status));  // child exits by signal
  } else if (!WIFSTOPPED(status)) {
    kill9_child_and_exit(child, 67);
  }

#ifdef ENABLE_DEBUG_LOG
  const int sig =
#endif  // ENABLE_DEBUG_LOG
      _OK_CALL(WSTOPSIG(status), _ == SIGSTOP || _ == SIGTRAP, kill9_child_and_exit(child, 68));

  // alloc pid map/list
  if (!pids_init(child))
    kill9_child_and_exit(child, 69);

  DEBUG(child, status >> 16, sig, "TRACEE0 FIRST STOP");

  constexpr auto options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD;
  constexpr auto options_w_exitkill = options | PTRACE_O_EXITKILL;

#ifdef ARCH_X64
  {
    auto const try_set_opt = _OK_CALL(ptrace(PTRACE_SETOPTIONS, child, 0, options_w_exitkill),
                                      _ != -1 || errno == EINVAL, kill9_child_and_exit(child, 70));
    if (try_set_opt == -1)
      _OK_CALL(ptrace(PTRACE_SETOPTIONS, child, 0, options), _ != -1, kill9_child_and_exit(child, 71));

    init_sys_config_ptrace(child, try_set_opt != -1);
  }
#else
  _OK_CALL(ptrace(PTRACE_SETOPTIONS, child, 0, options_w_exitkill), _ != -1, kill9_child_and_exit(child, 71));
#endif

  // process term signals before continue child, ignore others
  {
    auto const signals = atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed);
    _OK_CALL(min_exit_signal(signals, false), _ == 0, kill9_child_and_exit(child, 128 + _));
  }

  // begin trace the first tracee
  pids_add(child);
  _OK_CALL(ptrace(PTRACE_CONT, child, 0, 0), _ != -1, kill9_child_and_exit(child, 72));
}

static uint_fast32_t process_signals() {
  uint_fast32_t signals = 0;
  while (0 != (signals = atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed))) {
    if (signals & _SIGBIT1(0)) {
      DEBUG(0, 0, signals, "receive kill signals");
      return signals;  // return to switch to existing loop
    }
    if (signals & _SIGBIT1(SIGSTOP)) {
      // signals here should be kill-ed from user, not group-stopped
      auto const sig = __builtin_ctz(signals & _SIGBIT4(SIGTTIN, SIGTTOU, SIGTSTP, SIGCONT));
      DEBUG(0, 0, sig, "receive STOP/CONT signal");
      pids_kill_tracee0(sig);
      signals &= ~_SIGBIT5(SIGTTIN, SIGTTOU, SIGTSTP, SIGCONT, SIGSTOP);

      if (sig == SIGCONT && ptrace_has_group_stopped) {
        pids_pt_cont_all();
        ptrace_has_group_stopped = false;
      }
    }

    for (; signals; signals &= signals - 1) {
      DEBUG(0, 0, __builtin_ctz(signals), "receive normal signal");
      pids_kill_tracee0(__builtin_ctz(signals));  // user level signals only forward to tracee0
    }
  }
  return signals;
}

static inline uint64_t now_ns() {
  struct timespec ts;
  syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);  // only used in exiting stage, syscall is accecptable
  return (uint64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

typedef struct {
  uint64_t rsp;
  uint64_t argc;
  uint64_t argv0;
  uint64_t argv0_1st_word;
  uint64_t argv_ofs;
  uint64_t envp_ofs;
  uint64_t auxv_ofs;
  uint64_t end_ofs;
  uint64_t param_ofs;
  uint64_t total_size;
  uint64_t auxv_map[64];  // AT_EXECFN = 31
  uint8_t at_base_idx;
  uint8_t at_pagesz_idx;
} exec_arg_t;

// download and parse the original execve stack defined by 64bit Linux ABI
// [rsp low->high]: |argc|argv0|...|0|envp0|...|0|auxv0t|auxv0v|...|0|0|padding|AT_RANDOM data|
static bool parse_exec_arg(const pid_t pid, const uint64_t rsp, const uint64_t rip, exec_arg_t *const exec_arg) {
  uint64_t ofs = 0;  // offset for both remote rsp base and local exec buffer base
  exec_arg->rsp = rsp;

  // argc, at least 1
  exec_arg->argc = PT_READ_CHK(pid, rsp + ofs, 0 < _ && _ < (1 << 18), return false);
  *(uint64_t *)(g_buffer + ofs) = exec_arg->argc;
  ofs += sizeof(uint64_t);

  // argv[]
  exec_arg->argv_ofs = ofs;
  PT_READ_BULKS(pid, rsp + ofs, 1, g_buffer + ofs, sizeof(uint64_t), _ != 0, false, false, return false);
  // skip download argv[1...argc]
  // PT_READ_BULKS(pid, rsp + ofs, 1, g_buffer + ofs, exec_arg->argc * sizeof(uint64_t), _ != 0, false, false, return
  // false);
  ofs += (exec_arg->argc + 1) * sizeof(uint64_t);
  *(uint64_t *)(g_buffer + ofs - sizeof(uint64_t)) = 0;  // append NULL after argv
  exec_arg->argv0 = *(uint64_t *)(g_buffer + exec_arg->argv_ofs);

  // envp[]
  exec_arg->envp_ofs = ofs;
  ofs += PT_READ_BULKS(pid, rsp + ofs, 1, g_buffer + ofs, (1 << 21), true, _ == 0, true, return false);
  *(uint64_t *)(g_buffer + ofs) = 0;  // append NULL after envp
  ofs += sizeof(uint64_t);

  // auxv[]
  exec_arg->auxv_ofs = ofs;
  static_assert(sizeof(Elf64_auxv_t) == 2 * sizeof(uint64_t));
  ofs += PT_READ_BULKS(pid, rsp + ofs, sizeof(Elf64_auxv_t) / sizeof(uint64_t), g_buffer + ofs,
                       128 * sizeof(Elf64_auxv_t), true, _ == AT_NULL, true, return false);
  // append AT_NULL marker after auxv
  *(Elf64_auxv_t *)(g_buffer + ofs) = (Elf64_auxv_t){.a_type = AT_NULL, .a_un.a_val = 0};
  ofs += sizeof(Elf64_auxv_t);

  // from rsp + end_ofs on the tracee, there may be 8 bytes padding, leave them not be overwritten
  // from g_buffer + end_ofs on tracer, the inject_param will be appended
  exec_arg->end_ofs = ofs;

  // analyze aux table
  memset(exec_arg->auxv_map, 0, sizeof(exec_arg->auxv_map));
  {
    uint8_t i = 0;
    for (auto p = (const Elf64_auxv_t *)(g_buffer + exec_arg->auxv_ofs); p->a_type != AT_NULL; ++p, ++i) {
      if (p->a_type < ARRAY_SIZE(exec_arg->auxv_map))
        exec_arg->auxv_map[p->a_type] = p->a_un.a_val;
      if (p->a_type == AT_BASE)
        exec_arg->at_base_idx = i;
      else if (p->a_type == AT_PAGESZ)
        exec_arg->at_pagesz_idx = i;
    }
  }

  if (exec_arg->auxv_map[AT_ENTRY] == rip) {
    DEBUG(pid, 0, 0, "static elf");
    return false;
  }

  // AT_BASE is required for munmap() old interp
  // AT_EXECFN is required for restoring when error
  if (!exec_arg->auxv_map[AT_BASE] || !exec_arg->auxv_map[AT_EXECFN] || !exec_arg->auxv_map[AT_PHDR] ||
      !exec_arg->auxv_map[AT_ENTRY] || !exec_arg->auxv_map[AT_PHNUM] ||
      exec_arg->auxv_map[AT_PHENT] != sizeof(Elf64_Phdr)) {
    DEBUG(pid, 0, 0, "non standard elf");
    return false;
  }
  if (exec_arg->auxv_map[AT_SECURE]) {
    DEBUG(pid, 0, 0, "run with setsid");
    return false;
  }
  if (!exec_arg->auxv_map[AT_PAGESZ] || exec_arg->auxv_map[AT_PAGESZ] != g_sc.pagesz) {
    DEBUG(pid, 0, 0, "AT_PAGESZ is unset or different to the system conf");
    return false;
  }

  exec_arg->argv0_1st_word = PT_READ(pid, exec_arg->argv0, return false);

  return true;
}

// analyze PT_INTERP from main elf
static bool check_tracee_interp(const pid_t pid, const exec_arg_t exec_arg[static 1]) {
  uint64_t pt_phdr_vaddr = 0, pt_interp_vaddr = 0;
  static_assert(offsetof(Elf64_Phdr, p_type) % 8 == 0);
  static_assert(sizeof_member(Elf64_Phdr, p_type) == 4);
  static_assert(sizeof_member(Elf64_Phdr, p_vaddr) == 8);
  static_assert(sizeof_member(Elf64_Phdr, p_memsz) == 8);
  for (size_t i = 0; i < exec_arg->auxv_map[AT_PHNUM] && (!pt_phdr_vaddr || !pt_interp_vaddr); ++i) {
    auto const header = exec_arg->auxv_map[AT_PHDR] + i * sizeof(Elf64_Phdr);
    auto const type = (uint32_t)PT_READ(pid, header + offsetof(Elf64_Phdr, p_type), return false);

    if (PT_PHDR == type)
      pt_phdr_vaddr = PT_READ(pid, header + offsetof(Elf64_Phdr, p_vaddr), return false);
    else if (PT_INTERP == type) {
      // check len first
      const size_t len = PT_READ(pid, header + offsetof(Elf64_Phdr, p_memsz), return false);
      if (len < strlen(SYS_INTERP_PATH) + 1 || len > PATH_MAX) {
        DEBUG(pid, 0, 0, "non standard interp by len");
        return false;
      }
      pt_interp_vaddr = PT_READ(pid, header + offsetof(Elf64_Phdr, p_vaddr), return false);
    }
  }

  if (!pt_interp_vaddr)  // pt_phdr_vaddr is optional
    return false;

  auto const interp_addr = exec_arg->auxv_map[AT_PHDR] - pt_phdr_vaddr + pt_interp_vaddr;

  // checking System V ABI standard interp path, length is already checked
  char interp_path[SYS_INTERP_PATH_WORD_NR * sizeof(uint64_t)];
  PT_READ_BULKS_FAST(pid, interp_addr, interp_path, sizeof(interp_path), return false);
  interp_path[sizeof(interp_path) - 1] = '\0';
  if (0 != memcmp(interp_path, SYS_INTERP_PATH, strlen(SYS_INTERP_PATH) + 1)) {
    DEBUG(pid, 0, 0, "non standard interp path");
    return false;
  }
  return true;
}

static inline size_t calc_g_loader_param_sz() {
  size_t sz = 0;
  sz += sizeof(loader_param_t);                 // param header
  sz += MAX_MMAP_CNT * sizeof(mmap_param_t);    // mmap params
  sz += MAX_MMAP_CNT * sizeof(munmap_param_t);  // munmap params
  sz += 3 * PATH_MAX;                           // interp path, libc dir and chlibc path
  sz += g_sc.max_arg_strlen + 1;                // a magic-prefixed argv0 string for restoring
  return sz + 1024;
}
static inline size_t calc_g_buffer_sz(const size_t arg_max) {
  size_t sz = calc_g_loader_param_sz();
  sz = align_page_u(sz);
  sz += arg_max;  // download the initial stack here, align to page
  return sz + 1024;
}

static loader_param_t *g_loader_param;
static uint32_t g_loader_param_written;

static void init_loader_params() {
  g_loader_param = (typeof(g_loader_param))g_buffer;
  g_buffer = align_page_u(g_buffer + calc_g_loader_param_sz());  // fix g_buffer address

  // init const part
  {
    const loader_param_t header = {
        .regs = {0},
        .relo_offsets = {0},
    };
    memcpy(g_loader_param, &header, sizeof(header));
  }

  // fill mmap params
  {
    auto const begin = RELO_SET_OFFSET(g_loader_param, mmap_params);
    auto const len = target_interp.pt_mmap_cnt * sizeof(*begin);
    memcpy(begin, target_interp.pt_mmap_params, len);
    g_loader_param->written += len;
  }

  // fill munmap params
  {
    auto const dst = RELO_SET_OFFSET(g_loader_param, munmap_params);
    auto src = system_interp.pt_mmap_params;
    for (auto i = 0; i < system_interp.pt_mmap_cnt; ++i)
      dst[i] = (typeof(*dst)){.vaddr = src[i].vaddr, .length = src[i].length};
    g_loader_param->written += system_interp.pt_mmap_cnt * sizeof(*dst);
  }

  // fill interp_path
  {
    auto const p = RELO_SET_OFFSET(g_loader_param, interp_path);
    g_loader_param->written += 1 + stpcpy(p, target_interp.path) - p;
  }

  // fill libc_dir
  {
    auto const p = RELO_SET_OFFSET(g_loader_param, libc_dir);
    g_loader_param->written += 1 + stpcpy(p, target_interp.libc_dir) - p;
  }

  // fill chlibc_path
  {
    auto const p = RELO_SET_OFFSET(g_loader_param, chlibc_path);
    g_loader_param->written += 1 + stpcpy(p, chlibc_info.path) - p;
  }

  // fill prefix of argv0_w_magic
  {
    memcpy(RELO_SET_OFFSET(g_loader_param, argv0_w_magic), "/\xFF\xFF\xFF\xFF\xFF\xFF/", 8);
    g_loader_param->written += 8;
  }

  g_loader_param_written = g_loader_param->written;  // save for resetting written
}

static bool handle_exec(const pid_t pid) {
  common_regs_t regs;
  PT_OK_CALL(pt_get(pid, &regs), return false);

  exec_arg_t exec_arg;
  if (!parse_exec_arg(pid, regs._M_SP, regs._M_PC, &exec_arg))  // rsp aligns to 16 bytes via 64bit Linux ABI
    return false;

  if (0 == memcmp(&exec_arg.argv0_1st_word, "/\xFF\xFF\xFF\xFF\xFF\xFF/", 8)) {
    DEBUG(pid, 0, 0, "loader failing fallback");
    PT_WRITE(pid, regs._M_SP + exec_arg.argv_ofs, exec_arg.argv0 + 8, return false);  // restore argv0
    return false;
  }
  if (!check_tracee_interp(pid, &exec_arg))
    return false;

  // fill loader params of this tracee
  g_loader_param->written = g_loader_param_written;
  g_loader_param->written +=
      1 + _OK_CALL(pt_read_cstring(pid, exec_arg.argv0, g_loader_param->data + g_loader_param_written,
                                   g_sc.max_arg_strlen - 8),
                   _ < g_sc.max_arg_strlen - 8, return false);

  RELO_SET_OFFSET(g_loader_param, argc);
  g_loader_param->written += sizeof(uint64_t);

  RELO_SET_OFFSET(g_loader_param, argv);
  g_loader_param->written += exec_arg.envp_ofs - exec_arg.argv_ofs;

  RELO_SET_OFFSET(g_loader_param, envp);
  g_loader_param->written += exec_arg.auxv_ofs - exec_arg.envp_ofs - sizeof(uint64_t);

  RELO_SET_OFFSET(g_loader_param, envp_null);
  g_loader_param->written += sizeof(uint64_t);

  RELO_SET_OFFSET(g_loader_param, auxv);
  g_loader_param->written += exec_arg.end_ofs - exec_arg.end_ofs;

  RELO_SET_OFFSET(g_loader_param, lib_paths);
  g_loader_param->written += 0;

  RELO_SET_OFFSET(g_loader_param, end);

  auto const pc_page = align_page_d(regs._M_PC);  // write to the begin of the page
  regs._M_PC = target_interp.entry_vaddr;         // save entry vaddr before writing to stack
  g_loader_param->regs = regs;                    // now g_loader_param.written is overwritten by regs

  const loader_reg_flags_t reg_flags = {
      .at_base_idx = exec_arg.at_base_idx,
      .at_pagesz_idx = exec_arg.at_pagesz_idx,
#ifdef ARCH_ARM64
      .support_bti = g_sc.prot_bti != 0,
#endif
  };

  // upload loader param to the remote stack
  auto const stack_upload_sz = LOADER_PARAM_SZ_BEFORE_STACK(g_loader_param);
  regs._M_SP = exec_arg.rsp - stack_upload_sz;
  PT_WRITE_BULKS(pid, regs._M_SP, g_loader_param, stack_upload_sz, false, return false);

  // prepare loader_loader syscall args
  auto const loader_loader_sz = (uintptr_t)&loader_loader_end - (uintptr_t)&loader_loader;
  auto const r_chlibc_path = regs._M_SP + LOADER_PARAM_CHLIBC_PATH_OFS(g_loader_param);
  regs._M_PC = pc_page + (uintptr_t)&loader_loader_entry - (uintptr_t)&loader_loader;

  // loader abi
  regs._M_S1 = loader_info.filesz;
  regs._M_S2 = exec_arg.auxv_map[AT_EXECFN];
  regs._M_S3 = target_interp.is_dyn ? target_interp.total_memsz : 0;
  regs._M_S4 = reg_flags.raw;

#if defined(ARCH_X64)
  // old open() syscall only uses 2 regs, but after EVENT_EXEC, rax will always set to 0
  // we will set rax to SYS_open at loader_loader_entry
  static_assert(SYS_open == 2);
  regs._M_SYS_ARG1 = r_chlibc_path;
  regs._M_SYS_ARG2 = O_RDONLY;
  regs._M_SYS_ARG3 = PROT_READ | PROT_EXEC;
  regs._M_SYS_ARG4 = MAP_PRIVATE;
  regs._M_SYS_ARG5 = SYS_mmap;
  regs._M_SYS_ARG6 = loader_info.filesz;
  regs.rbx = SYS_close - SYS_open;

  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, loader_info.entry_vaddr, return false);
  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, pc_page - regs.rbx, return false);
#else  // defined(ARCH_ARM64)
  regs._M_SYS_NR = SYS_openat;       // no open() syscall
  regs._M_SYS_ARG1 = 0;              // If the pathname given in path is absolute, then dirfd is ignored.
  regs._M_SYS_ARG2 = r_chlibc_path;  // absolute path
  regs._M_SYS_ARG3 = O_RDONLY;
  regs._M_SYS_ARG4 = MAP_PRIVATE;
  regs._M_SYS_ARG5 = loader_info.filesz;
  regs._M_SYS_ARG6 = 0;
  regs.regs[19] = pc_page;

  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, loader_info.entry_vaddr, return false);  // to x2
  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, SYS_close, return false);  // to x8
  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, PROT_READ | PROT_EXEC | g_sc.prot_bti, return false);  // to x2
  regs._M_SP -= sizeof(uint64_t);
  PT_WRITE(pid, regs._M_SP, SYS_mmap, return false);  // to x8
#endif

  // upload loader_loader and registers
  // TODO FAIL needs restore
  auto const write_rx_page = true;  // force poke loader_loader to the readonly page
  PT_WRITE_BULKS(pid, pc_page, &loader_loader, loader_loader_sz, write_rx_page, return false);
  PT_OK_CALL(pt_set(pid, &regs), return false);
  return true;
}

[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader_loader() {
  __asm__ volatile(
      ".global loader_loader_end, loader_loader_pad_end, trap_restore_marker;"
#if defined(ARCH_X64)
#  ifndef __clang__
      "endbr64;"  // gcc does not auto insert endbr64 for a naked function
#  endif
      // syscall: rax <- rax(rdi, rsi, rdx, r10, r8, r9)
      // callee-saved: rbx, rbp, r12, r13, r14, r15

      // rax=fd? rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=close-open *rsp=entry_offset
      "xchg %%rax, %%r8;"
      // rax=mmap rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=fd? r9=filesz rbx=close-open *rsp=entry_offset
      "xchg %%rsi, %%r9;"
      // [rax=mmap rdi=chlibc_path(hint) rsi=filesz rdx=R-X r10=priv r8=fd? r9=0] rbx=close-open *rsp=entry_offset
      "syscall;"

      // rax=addr? rdi=chlibc_path(hint) r8=fd? rbx=close-open *rsp=entry_offset
      "movq %%r8, %%rdi;"
      // rax=addr? rdi=fd? r8=fd? rbx=close-open *rsp=entry_offset
      "xchg %%rax, %%rbx;"

      "loader_loader_entry:"
      // After EVENT_EXEC, the result register (rax) of execve syscall will always be set to zero.
      // round 1: rax=0 rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=close-open
      //          [rsp] = [loader_loader - (close - open), entry_offset]
      // round 2: rax=close-open rdi=fd? rbx=addr? *rsp=entry_offset
      "addb $2, %%al;"
      // round 1: [rax=open rdi=chlibc_path rsi=O_RDONLY(0)] rdx=R-X r10=priv r8=mmap r9=filesz rbx=close-open
      //          [rsp] = [loader_loader - (close - open), entry_offset]
      // round 2: [rax=close rdi=fd?] rbx=addr? *rsp=entry_offset
      "syscall;"
      // round 1: rax=fd? rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=close-open
      //          [rsp] = [loader_loader - (close - open), entry_offset]
      // round 2: rax=0? rdi=fd? rbx=addr? *rsp=entry_offset
      "addq %%rbx, (%%rsp);"
      "jc loader_loader_fail;"  // in round 2, mmap err overflow the previous addq

      // round 1: rax=fd? rdi=chlibc_path rsi=O_RDONLY(0) rdx=R-X r10=priv r8=mmap r9=filesz rbx=close-open
      //          [rsp] = [[loader_loader], entry_offset]
      // round 2: rax=0? rdi=fd? rbx=addr? [*rsp=entry_vaddr]
      "ret;"

      "loader_loader_fail:"
      "int3;"  // rbx = -(mmap errno)
      "trap_restore_marker:"
      "syscall; ud2; ud2; .2byte 0x3065;"  // mark of restoring via execve()

      "loader_loader_end:"
      "nop; nop; nop; nop; nop; nop;"

#elif defined(ARCH_ARM64)  // "bti c" is auto inject by the compiler
      // syscall: x0 <- x8(x0, x1, x2, x3, x4, x5)
      // callee-saved: x19--x28

      // x8=openat x0=fd_or_err x1=chlibc_path x2=loader_loader x3=priv x4=filesz x5=0 x19=?
      "ldp x8, x2, [sp], #16;"
      // x8=mmap x0=fd_or_err x1=chlibc_path x2=R-X x3=priv x4=filesz x5=0 x19=?
      "mov x1, x4;"
      // x8=mmap x0=fd_or_err x1=filesz x2=R-X x3=priv x4=filesz x5=0 x19=?
      "mov x4, x0;"
      // x8=mmap x0=fd_or_err(hint) x1=filesz x2=R-X x3=priv x4=fd_or_err x5=0 x19=?
      "svc #0;"
      // x8=mmap x0=addr_or_err x1=filesz x2=R-X x3=priv x4=fd_or_err x5=0 x19=?
      "ldp x8, x2, [sp], #16;"
      // x8=close x0=addr_or_err x1=filesz x2=entry_offset x3=priv x4=fd_or_err x5=0 x19=?
      "mov x19, x0;"
      "mov x0, x4;"

      "loader_loader_entry:"
      // round 1: x8=openat x0=0 x1=chlibc_path x2=O_RDONLY(0) x3=priv x4=filesz x5=0 x19=loader_loader
      // round 2: x8=close x0=fd_or_err x1=filesz x2=entry_offset x3=priv x4=fd_or_err x5=0 x19=addr_or_err
      "svc #0;"
      // round 1: x8=openat x0=fd_or_err x1=chlibc_path x2=O_RDONLY(0) x3=priv x4=filesz x5=0 x19=loader_loader
      // round 2: x8=close x0=0_or_err x1=filesz x2=entry_offset x3=priv x4=fd_or_err x5=0 x19=addr_or_err
      "adds x2, x2, x19;"
      "b.cs loader_loader_fail;"

      // round 1: jump loader_loader
      // round 2: jump entry vaddr
      "br x2;"

      "loader_loader_fail:"
      "trap_restore_marker:"
      // x19=-(mmap errno)
      "brk #0x3065; svc #0; udf #0x3065;"  // mark of restoring via execve()

      "loader_loader_end:"
#else                      // ARCH_RISCV64
      "loader_loader_entry:"
      "loader_loader_fail:"
      "trap_restore_marker:"
      "c.ebreak; ecall; .2byte 0x3065;"
      "loader_loader_end:"
      "nop; nop;"
#endif

      "nop;"
      "loader_loader_pad_end:" ::);
}

// handle trap events from tracees
// Return:
//   - 0: fail, the tracee will be killed
//   - 1: ok, let the tracee continue to run
//   - 2: ok, let the tracee run a single step
static int handle_trap(const pid_t pid) {
  common_regs_t regs;
  PT_OK_CALL(pt_get(pid, &regs), return 0);

  auto const r = pt_read_word(pid, regs._M_PC);
  if (PT_SUCCESS(r)) {
    auto const v = PT_VALUE(r);
    if (0 == memcmp(&v, trap_restore_marker, 8)) {
      loader_param_t param = {0};

      // download restore parameters
      PT_READ_BULKS_FAST(pid, regs._M_SP + offsetof(loader_param_t, relo_offsets), &param.relo_offsets,
                         sizeof(param) - offsetof(loader_param_t, relo_offsets), return 0);

      auto const remote_argv0_w_magic_addr = RELO_PTR_REMOTE(regs._M_SP, param, argv0_w_magic);
      auto const remote_argv_addr = RELO_PTR_REMOTE(regs._M_SP, param, argv);
      auto const remote_envp_addr = RELO_PTR_REMOTE(regs._M_SP, param, envp);
      auto const remote_at_execfn_addr = regs._M_S2;

      regs._M_PC += TRAP_OP_NEXT;
      regs._M_SYS_NR = SYS_execve;
#ifdef ARCH_X64
      regs.orig_rax = regs._M_SYS_NR;
#endif
      regs._M_SYS_ARG1 = remote_at_execfn_addr;
      regs._M_SYS_ARG2 = remote_argv_addr;
      regs._M_SYS_ARG3 = remote_envp_addr;

      PT_WRITE(pid, remote_argv_addr, remote_argv0_w_magic_addr, return 0);  // replace argv[0]
      PT_OK_CALL(pt_set(pid, &regs), return 0);
      return 1;
    }

    if (0 == memcmp(&v, trap_ok_marker, 8)) {
      // loader() success, now need munmap the loader() itself and stop
      if (TRAP_OP_NEXT) {
        regs._M_PC += TRAP_OP_NEXT;
        PT_OK_CALL(pt_set(pid, &regs), return 0);
      }
      return 2;
    }

    return 1;  // skip unknown trap
  }

  if (PT_ERRNO(r) == EFAULT || PT_ERRNO(r) == EIO) {
    loader_param_t param = {0};

    // download restore regs
    PT_READ_BULKS_FAST(pid, regs._M_SP, &param, end_offsetof(loader_param_t, regs), return 0);
    PT_OK_CALL(pt_set(pid, &param.regs), return 0);  // run new interp
    return 1;
  }

  ERR("cannot read 8 bytes from RIP[0:7]");
  return 0;
}

// process a waitpid() stop for pid > 0.
// exitsig>0 means in the existing stage with the specified signal
static void process(const pid_t pid, const int status, const int exitsig) {
  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    DEBUG(pid, 0, 0, "WIFEXITED || WIFSIGNALED");
    if (pids_tracee0() == pid)
      ptrace_tracee0_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    pids_del(pid);
    return;
  }

  if (UNLIKELY(!WIFSTOPPED(status)))
    FATAL(64, "must be WIFSTOPPED here");

  const int stopsig = WSTOPSIG(status);
  int deliver_sig = exitsig || (SIGTRAP == stopsig || (SIGTRAP | 0x80) == stopsig) ? exitsig : stopsig;

  if (stopsig == SIGTRAP) {
    // now PTRACE_EVENT stops or syscall-stops.
    switch (status >> 16) {
    case PTRACE_EVENT_EXIT:
      DEBUG(pid, status >> 16, exitsig, "EVENT_EXIT");
      if (pids_tracee0() == pid) {
        auto const r = pt_get(pid);
        if (PT_SUCCESS(r)) {
          const unsigned long msg = PT_VALUE(r);
          ptrace_tracee0_exit_code = msg & 0xff ? 128 + (msg & 0xff) : ((msg >> 8) & 0xff);
        }
      }
      deliver_sig = 0;  // skip exitsig on exit event
      pids_del(pid);
      break;

    case PTRACE_EVENT_FORK:
      [[fallthrough]];
    case PTRACE_EVENT_VFORK:
      [[fallthrough]];
    case PTRACE_EVENT_CLONE: {
      DEBUG(pid, status >> 16, exitsig, "EVENT_VORK|VFORK|CLONE");
      auto const r = pt_get(pid);
      if (PT_SUCCESS(r)) {
        if (exitsig)
          kill((pid_t)PT_VALUE(r), exitsig);  // fast kill
        else
          pids_add((pid_t)PT_VALUE(r));
      }
    } break;

    case PTRACE_EVENT_EXEC:
      DEBUG(pid, status >> 16, exitsig, "EVENT_EXEC");
      if (0 == exitsig && !handle_exec(pid))
        DEBUG(pid, status >> 16, exitsig, "handle_exec FAIL");

      break;

    case 0:
      DEBUG(pid, status >> 16, exitsig, "SIGTRAP");
      if (0 == exitsig) {
        auto const rst = handle_trap(pid);
        if (0 == rst) {
          deliver_sig = SIGKILL;
          DEBUG(pid, status >> 16, exitsig, "KILL tracee on non-recoverable errors");
        } else if (2 == rst && pt_singlestep(pid, deliver_sig))
          return;  // use singlestep to munmap the loader()
      }
      break;

    default:
      DEBUG(pid, status >> 16, exitsig, "unknown ptrace event or non ptrace-stop");
    }

  } else {
    // now signal-delivery-stops or group-stops
    switch (stopsig) {
    case SIGCONT:
      [[fallthrough]];
    case SIGKILL:
      [[fallthrough]];
    case SIGCHLD:
      DEBUG(pid, 0, stopsig, "SIGKILL/SIGCHLD/SIGCONT");
      deliver_sig = stopsig;
      break;

    case SIGABRT:
      [[fallthrough]];
    case SIGBUS:
      [[fallthrough]];
    case SIGFPE:
      [[fallthrough]];
    case SIGILL:
      [[fallthrough]];
    case SIGSEGV:
      [[fallthrough]];
    case SIGSYS:
      DEBUG(pid, 0, stopsig, "Core Dump Signals");
      deliver_sig = exitsig == SIGKILL ? SIGKILL : stopsig;
      break;

    case SIGSTOP:
      [[fallthrough]];
    case SIGTSTP:
      [[fallthrough]];
    case SIGTTIN:
      [[fallthrough]];
    case SIGTTOU: {
      siginfo_t si = {.si_signo = stopsig};
      auto r = pt_get(pid, &si);
      if (PT_SUCCESS(r)) {
        auto const first_stop =
            SIGSTOP == stopsig && (SI_USER == si.si_code || SI_KERNEL == si.si_code) && 0 == si.si_pid;
        if (first_stop) {
          deliver_sig = 0;
          DEBUG(pid, status >> 16, stopsig, "Attached SIGSTOP");
        } else
          DEBUG(pid, status >> 16, stopsig, "Stop Signals");
      } else if (PT_IS_GROUP_STOP(stopsig, PT_ERRNO(r))) {
        DEBUG(pid, status >> 16, stopsig, "Group-stop Signals");
        ptrace_has_group_stopped = true;
        return;  // in PTRACE_ATTACH mode, leave the tracees stopped
      }
    } break;

    default:
      if (exitsig || pids_tracee0() == pid || 32 <= (unsigned)stopsig) {
        DEBUG(pid, status >> 16, stopsig,
              exitsig ? "Inject kill signals"
                      : (32 <= (unsigned)stopsig ? "Forward RT Signals" : "Forward non tracee0 signals "));
      } else {
        siginfo_t si = {.si_signo = stopsig};
        if (PT_SUCCESS(pt_get(pid, &si))) {
          if ((si.si_code == SI_USER || si.si_code == SI_TKILL) && si.si_pid == tracer_pid) {
            // killed from tracer to tracee0
            static uint64_t sig_forward_dup_ttl[32] = {0};
            auto const curr = now_ns();
            if (curr < sig_forward_dup_ttl[stopsig])
              deliver_sig = 0;  // do not forward a duplicated signal
            else
              sig_forward_dup_ttl[stopsig] = curr + UINT64_C(20000000);  // 20ms
          }
        }
        DEBUG(pid, status >> 16, stopsig, deliver_sig ? "Forward normal signals" : "Drop a duplicated signal");
      }
      break;
    }
  }
  // CONT:
  pt_cont(pid, deliver_sig);
}

static uint_fast32_t ptrace_loop() {
  tracer_pid = getpid();
  uint_fast32_t signals;
  int status;
  while (0 == (signals = process_signals())) {
    // ERR("heartbeat %llu", now_ns() / 1000000000);
    auto const pid = waitpid(-1, &status, __WALL);  // wait signals or ptrace events
    if (pid > 0)
      process(pid, status, 0);
    else
      switch (errno) {
      case EINTR:
        break;  // stop by signal
      case ECHILD:
        return 0;  // no ptrace tracees
      default:
        ERR("waitpid unknown error");  // should never reach here
      }
  }
  return signals;
}

static int ptrace_exiting(const uint_fast32_t signals) {
  auto const is_kill = 0 != (signals & _SIGBIT1(SIGKILL));
  auto sig = min_exit_signal(signals, is_kill);
  if (!sig)
    return 0;
#ifdef ARCH_X64
  if (is_kill && g_sc.has_ptrace_exitkill)
    return 128 + sig;
  pids_kill_all(is_kill ? SIGKILL : SIGTERM);
#else
  if (is_kill)
    return 128 + sig;
  pids_kill_all(SIGTERM);
#endif

  auto curr = now_ns();
  auto const softline = curr + (1000000000LL * (is_kill ? 0LL : 1000LL)) / 1000;
#ifdef ARCH_X64
  auto deadline = curr + (1000000000LL * (is_kill ? 50LL : 1050LL)) / 1000;
#endif
  const struct timespec sleepns = {.tv_sec = 0, .tv_nsec = 701000};
  int status;

  // decent exiting loop
  while ((curr = now_ns()) < softline) {
    if (atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed) & _SIGBIT1(SIGKILL)) {
      // promote term to kill
      sig = min_exit_signal(signals, true);
#ifdef ARCH_X64
      if (g_sc.has_ptrace_exitkill)
        return 128 + sig;
      deadline = curr + 1000000000LL * 50LL / 1000;
      break;
#else
      return 128 + sig;
#endif
    }

    auto const pid = waitpid(-1, &status, __WALL | WNOHANG);
    if (pid > 0)
      process(pid, status, SIGTERM);
    else if (-1 == pid) {
      switch (errno) {
      case EINTR:
        continue;
      case ECHILD:
        return 128 + sig;  // no ptrace tracees
      default:
        ERR("waitpid unknown error");  // should never reach here
      }
    } else
      nanosleep(&sleepns, nullptr);  // process signals in the next loop
  }

#ifdef ARCH_X64
  if (g_sc.has_ptrace_exitkill)
    return 128 + sig;
  if (!is_kill)
    pids_kill_all(SIGKILL);  // promote signals

  // force exiting loop
  while ((curr = now_ns()) < deadline) {
    // ignore signal process
    auto const pid = waitpid(-1, &status, __WALL | WNOHANG);
    if (pid > 0)
      process(pid, status, SIGKILL);
    else if (-1 == pid) {
      switch (errno) {
      case EINTR:
        continue;
      case ECHILD:
        return 128 + sig;  // no ptrace tracees
      default:
        ERR("waitpid unknown error");  // should never reach here
      }
    } else
      nanosleep(&sleepns, nullptr);  // skip signals in this loop
  }
#endif

  return 128 + sig;
}

int main(const int argc, char *const argv[]) {
  auto exit_code = 1;
  if (argc < 1 || !argv || !argv[0] || !argv[0][0]) {
    return 64;
  }
  if (1 == argc) {
    _OK_CALL(printf("Usage: %s <cmd> [argv...]\n", *argv), _ > 0);
    return 0;
  }

  if (!init_sys_config()) {
    ERR("fail to init system config");
    return 65;
  }
  if (!init_elf_info("/proc/self/exe", nullptr, &chlibc_info, false) || !init_loader_info()) {
    ERR("fail to init chlibc elf or loader info");
    return 66;
  }
  if (!init_elf_info(find_target_interp_path(), find_target_libc_dir(), &target_interp, true) || !init_chlibc_root()) {
    ERR("fail to init target interp info");
    return 65;
  }
  if (!init_elf_info(SYS_INTERP_PATH, nullptr, &system_interp, true)) {
    ERR("fail to init system interp info");
    return 65;
  }
  if (!alloc_g_buffer()) {
    ERR("fail to alloc global buffer");
    return 66;
  }

  init_loader_params();  // build the common part of loader params

  // block all signals, saving init masks
  _OK_CALL(sigfillset(&sig_mask_all), _ == 0, _Exit(66));
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_all, &sig_mask_init), _ == 0, _Exit(67));

  setup_sentinel_if_need_or_die();
  setup_signal_handlers_or_die();

  // set sub reaper, support from 3.4 kernel, ignore error
  prctl(PR_SET_CHILD_SUBREAPER, 1);

  // test term signals, ignore all other signals
  {
    auto const signals = atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed);
    const int exit_sig = min_exit_signal(signals, false);
    if (exit_sig) {
      exit_code = 128 + exit_sig;
      goto EXIT;
    }
  }

  // block all signals before fork()
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_all, nullptr), _ == 0, return 68);

  auto const tracee0 = fork();

  if (0 == tracee0) {
    // ptrace handshake as the first tracee
    _OK_CALL(ptrace(PTRACE_TRACEME, 0, 0, 0), _ != -1, _Exit(1));
    _OK_CALL(raise(SIGSTOP), _ == 0, _Exit(2));  // si_code in (SI_USER, SI_TKILL), si_pid is the child pid

    // restore sig masks
    _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), _ == 0, _Exit(3));
    execvp(argv[1], argv + 1);
    FATAL(127, "chlibc: exec %s fail", argv[1]);
  }

  _OK_CALL(tracee0, _ != -1, return 69);

  // restore sig masks
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), _ == 0, kill9_child_and_exit(tracee0, 70));

  // ptrace main
  ptrace_handshake_as_tracer_or_die(tracee0);  // handshake and send the first PTRACE_CONT th tracee0
  auto const esignals = ptrace_loop();
  exit_code = ptrace_exiting(esignals);

#ifdef ARCH_X64
  if (exit_code && !g_sc.has_ptrace_exitkill && pids->raw)
    ERR("PIDs table is not clean, table head bits=%u, next=%u", pids->bits, pids->next);
#endif

EXIT:
  _log_writev(nullptr, 0);  // flush log
  return exit_code ? exit_code : ptrace_tracee0_exit_code;
}
