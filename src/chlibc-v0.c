// NOTE: v0 is only POC, which run new glibc interp via cmd:
//     ./interp --library-path ... ./main/elf
// which does not supports copy relocation and IFUNC

#define _GNU_SOURCE  // REG_RIP macro needs GNU source

#ifndef __x86_64__
#error "handle_exec now requires an x86_64 (x64) architecture. Compilation aborted."
// the registers, stack layout, and some ptrace() behavior is based on x64 Linux >= 2.6.18
// and should be able to adopted to aarch64 Linux >= 3.19 in the future
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
#include <linux/ptrace.h>
#endif

__asm__(".symver memcpy, memcpy@GLIBC_2.2.5");

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ARRAY_SIZE(x) (sizeof(int[_Generic(&(x), typeof(&(x)[0]) *: -1, default: 1)]) * 0 + sizeof(x) / sizeof(*(x)))
#define sizeof_member(t, m) (sizeof(((t *)nullptr)->m))
#define end_offsetof(t, m) (offsetof(t, m) + sizeof_member(t, m))
#define container_of(remote_addr, t, m) ((uint64_t)(remote_addr) - offsetof(t, m))
#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)
#define ALIGN_U(ptr, type) (type *)((((uintptr_t)(ptr)) + alignof(type) - 1) & ~(alignof(type) - 1))
#define ALIGN_D(ptr, type) (type *)(((uintptr_t)(ptr)) & ~(alignof(type) - 1))

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
    fd = open(env_path, O_WRONLY | O_APPEND | O_CREAT | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (_log_fd_ok(fd))
      return fd;
    close(fd);
  }

  // from stderr
  if (isatty(STDERR_FILENO)) {
    fd = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
    auto const flags = fcntl(fd, F_GETFL, 0);
    if (fd >= 3 && flags != -1 && fcntl(fd, F_SETFL, flags | O_CLOEXEC | O_NONBLOCK) != -1 && _log_fd_ok(fd))
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
#define DEBUG(pid, event, sig, msg)                                                                         \
  do {                                                                                                      \
    errno = 0;                                                                                              \
    _log_error(__FILE__, strlen(__FILE__), ":%d [c=%d][ev=%d][sig=%d] %s", __LINE__, pid, event, sig, msg); \
  } while (0)
#else  // ENABLE_DEBUG_LOG
#define DEBUG(...) ((void)0)
#endif  // ENABLE_DEBUG_LOG

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
#ifndef __x86_64__
#error "This base requires an x86_64 (x64) architecture. Compilation aborted."
#endif
    atomic_store_explicit(&sig_crash_ip, (uintptr_t)(((const ucontext_t *)ctx)->uc_mcontext.gregs[REG_RIP]),
                          memory_order_relaxed);
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
  auto const fd = open(ctermid(nullptr), O_RDONLY | O_NOCTTY | O_CLOEXEC);
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
  auto const fd = _OK_CALL(open("/proc/sys/kernel/pid_max", O_RDONLY | O_CLOEXEC), _ != -1);

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
#if 0
static inline bool pids_has(const pid_t pid) {
  auto const p = ((uint32_t)pid + pids_base_offset) & pids_base_mask;
  auto const curr = pids_slot_search(p >> 5, false);
  return curr && 0 != (curr->bits & _SIGBIT1(p & 31));
}
#endif
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

////////// INTERP ////////////
#define SYS_INTERP_PATH "/lib64/ld-linux-x86-64.so.2"
#define SYS_INTERP_PATH_WORD_NR ((sizeof(SYS_INTERP_PATH) + sizeof(uint64_t) - 1) / sizeof(uint64_t))

typedef struct {
  char path[PATH_MAX];  // set to empty string when initialized incorrectly
  char libc_dir[PATH_MAX];
  Elf64_Addr entry_vaddr;
  Elf64_Addr dl_argv_vaddr;
  Elf64_Addr dl_initial_searchlist_vaddr;
  bool has_argv0;  // support --argv0 STRING since glibc 2.33
} interp_info_t;

typedef struct {
  void *r_list;
  unsigned int r_nlist;
} _r_scope_elem;
typedef struct {
  int _dl_debug_mask;
  size_t _dl_pagesize;
  unsigned int _dl_osversion;
  const char *_dl_platform;
  size_t _dl_platformlen;
  _r_scope_elem _dl_initial_searchlist;
} rtld_global_ro_2_5;
typedef struct {
  int _dl_debug_mask;
  unsigned int _dl_osversion;
  const char *_dl_platform;
  size_t _dl_platformlen;
  size_t _dl_pagesize;
  _r_scope_elem _dl_initial_searchlist;
} rtld_global_ro_2_6;
typedef struct {
  int _dl_debug_mask;
  unsigned int _dl_osversion;
  const char *_dl_platform;
  size_t _dl_platformlen;
  size_t _dl_pagesize;
  int _dl_inhibit_cache;
  _r_scope_elem _dl_initial_searchlist;
} rtld_global_ro_2_16;
static_assert(offsetof(rtld_global_ro_2_5, _dl_initial_searchlist) ==
              offsetof(rtld_global_ro_2_16, _dl_initial_searchlist));
static_assert(offsetof(rtld_global_ro_2_6, _dl_initial_searchlist) + offsetof(_r_scope_elem, r_nlist) ==
              offsetof(rtld_global_ro_2_16, _dl_initial_searchlist));

static interp_info_t target_interp;
static char chlibc_root[PATH_MAX + 1];
static size_t chlibc_root_len = 0;

#define TARGET_ARCH "x86_64-conda-linux-gnu"
#define INTERP_NAME "ld-linux-x86-64.so.2"

static const char *find_target_interp_path() {
  static char resolved_path[PATH_MAX];
  char temp_path[MAX_ARG_STRLEN + PATH_MAX], self_exe[PATH_MAX];
  const char *env;

#define GETENV_SAFE(var) ((env = getenv(var)) && env[0] != '\0')
  // $CHLIBC_INTERP
  if (GETENV_SAFE("CHLIBC_INTERP") && realpath(env, resolved_path))
    return resolved_path;

  // $CHLIBC_GLIBC_HOME/ld-linux-x86-64.so.2
  if (GETENV_SAFE("CHLIBC_GLIBC_HOME")) {
    snprintf(temp_path, sizeof(temp_path), "%s/%s", env, INTERP_NAME);
    if (realpath(temp_path, resolved_path))
      return resolved_path;
  }

  // $CONDA_PREFIX/<arch>/sysroot/lib64/ld-linux-x86-64.so.2
  if (GETENV_SAFE("CONDA_PREFIX")) {
    snprintf(temp_path, sizeof(temp_path), "%s/%s/sysroot/lib64/%s", env, TARGET_ARCH, INTERP_NAME);
    if (realpath(temp_path, resolved_path))
      return resolved_path;
  }

  // dirname($0)/../<arch>/sysroot/lib64/ld-linux-x86-64.so.2
  if (realpath("/proc/self/exe", self_exe)) {
    snprintf(temp_path, sizeof(temp_path), "%s/../%s/sysroot/lib64/%s", dirname(self_exe), TARGET_ARCH, INTERP_NAME);
    if (realpath(temp_path, resolved_path))
      return resolved_path;
  }

#undef GETENV_SAFE
  ERR("no valid interp found");
  return nullptr;
}
static const char *find_target_libc_dir() {
  static char resolved_path[PATH_MAX];
  char temp_path[MAX_ARG_STRLEN + PATH_MAX], self_exe[PATH_MAX];
  const char *env;

#define GETENV_SAFE(var) ((env = getenv(var)) && env[0] != '\0')

  // $CHLIBC_GLIBC_HOME
  if (GETENV_SAFE("CHLIBC_GLIBC_HOME") && realpath(env, resolved_path))
    return resolved_path;

  // $CONDA_PREFIX/<arch>/sysroot/lib64
  if (GETENV_SAFE("CONDA_PREFIX")) {
    snprintf(temp_path, sizeof(temp_path), "%s/%s/sysroot/lib64", env, TARGET_ARCH);
    if (realpath(temp_path, resolved_path))
      return resolved_path;
  }

  // dirname($CHLIBC_INTERP)
  if (GETENV_SAFE("CHLIBC_INTERP")) {
    snprintf(temp_path, sizeof(temp_path), "%s", env);
    if (realpath(dirname(temp_path), resolved_path))
      return resolved_path;
  }

  // dirname($0)/../<arch>/sysroot/lib64
  if (realpath("/proc/self/exe", self_exe)) {
    snprintf(temp_path, sizeof(temp_path), "%s/../%s/sysroot/lib64", dirname(self_exe), TARGET_ARCH);
    if (realpath(temp_path, resolved_path))
      return resolved_path;
  }
#undef GETENV_SAFE
  ERR("no valid glibc dir found");
  return nullptr;
}
static bool init_chlibc_root() {
  char self_exe[PATH_MAX];
  const char *env;
  bool rst = false;

#define GETENV_SAFE(var) ((env = getenv(var)) && env[0] != '\0')

  if (GETENV_SAFE("CHLIBC_PREFIX") && realpath(env, chlibc_root))
    rst = true;  // CHLIBC_PREFIX
  else if (GETENV_SAFE("CONDA_PREFIX") && realpath(env, chlibc_root))
    rst = true;  // CONDA_PREFIX
  else if (realpath("/proc/self/exe", self_exe) && realpath(dirname(self_exe), chlibc_root))
    rst = true;  // dirname($0)/..

  if (rst) {
    chlibc_root_len = strlen(chlibc_root);
    chlibc_root[chlibc_root_len++] = '/';
    chlibc_root[chlibc_root_len] = '\0';
  } else
    ERR("no valid chlibc prefix found");

#undef GETENV_SAFE
  return rst;
}

static bool init_interp_info(const char *const path, const char *const libc_dir, interp_info_t *const info) {
  if (!path || !libc_dir)
    return false;

  bool rst = false;
  _OK_CALL(realpath(path, info->path), _ != nullptr, goto DONE);
  if (libc_dir)
    _OK_CALL(realpath(libc_dir, info->libc_dir), _ != nullptr, goto DONE);
  else {
    strcpy(info->libc_dir, info->path);
    basename(info->libc_dir);
  }

  auto fd = _OK_CALL(open(info->path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW), _ >= 0, goto DONE);
  struct stat st;

  _OK_CALL(fstat(fd, &st), _ >= 0, goto CLEAN_FD_DONE);
  _OK_CALL(S_ISREG(st.st_mode), _ != 0, goto CLEAN_FD_DONE);
  auto const elf = _OK_CALL((const uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0), _ != MAP_FAILED,
                            goto CLEAN_FD_DONE);
  close(fd);
  fd = -1;

  auto const ehdr = (const Elf64_Ehdr *)elf;
  _OK_CALL(memcmp(ehdr->e_ident, ELFMAG, SELFMAG), _ == 0, goto UNMAP_DONE);  // must elf
  _OK_CALL(ehdr->e_ident[EI_CLASS], _ == ELFCLASS64, goto UNMAP_DONE);        // must elf64

  info->entry_vaddr = ehdr->e_entry;

  auto const phdr = (const Elf64_Phdr *)(elf + ehdr->e_phoff);

  Elf64_Addr symtab_vadrr = 0;
  Elf64_Addr strtab_vadrr = 0;
  Elf64_Addr hash_vadrr = 0;
  Elf64_Addr gnu_hash_vadrr = 0;
  size_t syment = sizeof(Elf64_Sym);

  // first round, fill vaddrs for dynamic section
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr[i].p_type == PT_DYNAMIC) {
      for (auto dyn = (const Elf64_Dyn *)(elf + phdr[i].p_offset); dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
        case DT_SYMTAB:
          symtab_vadrr = dyn->d_un.d_ptr;
          break;
        case DT_STRTAB:
          strtab_vadrr = dyn->d_un.d_ptr;
          break;
        case DT_HASH:
          hash_vadrr = dyn->d_un.d_ptr;
          break;
        case DT_GNU_HASH:
          gnu_hash_vadrr = dyn->d_un.d_ptr;
          break;
        case DT_SYMENT:
          syment = dyn->d_un.d_val;
          break;
        }
      }
      break;
    }
  }

  if (!symtab_vadrr || !strtab_vadrr || (!hash_vadrr && !gnu_hash_vadrr) || syment < sizeof(Elf64_Sym)) {
    ERR("invalid PT_DYNAMIC vaddr");
    goto UNMAP_DONE;
  }

  const Elf64_Sym *symtab = nullptr;
  const char *strtab = nullptr;
  const uint32_t *hash = nullptr;
  const uint32_t *gnu_hash = nullptr;

  // second round, vaddrs -> file offsets
  for (int i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr[i].p_type == PT_LOAD) {
      // assume the layout is simple
      if ((size_t)(symtab_vadrr - phdr[i].p_vaddr) < phdr[i].p_memsz)
        symtab = (const Elf64_Sym *)(elf + phdr[i].p_offset + symtab_vadrr - phdr[i].p_vaddr);
      if ((size_t)(strtab_vadrr - phdr[i].p_vaddr) < phdr[i].p_memsz)
        strtab = (const char *)(elf + phdr[i].p_offset + strtab_vadrr - phdr[i].p_vaddr);
      if (hash_vadrr && (size_t)(hash_vadrr - phdr[i].p_vaddr) < phdr[i].p_memsz)
        hash = (const uint32_t *)(elf + phdr[i].p_offset + hash_vadrr - phdr[i].p_vaddr);
      if (gnu_hash_vadrr && (size_t)(gnu_hash_vadrr - phdr[i].p_vaddr) < phdr[i].p_memsz)
        gnu_hash = (const uint32_t *)(elf + phdr[i].p_offset + gnu_hash_vadrr - phdr[i].p_vaddr);

      if (symtab && strtab && hash)
        break;
    }
  }

  if (!symtab || !strtab || (!hash && !gnu_hash)) {
    ERR("invalid PT_DYNAMIC");
    goto UNMAP_DONE;
  }

  size_t nsyms = 0;
  if (hash)
    nsyms = hash[1];
  else {  // parsing GNU_HASH table
    auto const nbuckets = gnu_hash[0];
    auto const symoff = gnu_hash[1];
    auto const bloom_sz = gnu_hash[2];

    auto const bloom = (uint64_t *)(gnu_hash + 4);  // skip shift2
    auto const bucket = (uint32_t *)(bloom + bloom_sz);
    auto const chain = bucket + nbuckets;
    uint32_t max = 0;

    for (uint32_t i = 0; i < nbuckets; ++i) {
      if (bucket[i] > max)
        max = bucket[i];
    }

    if (max >= symoff) {
      uint32_t idx = max - symoff;
      while ((chain[idx] & 1) == 0)
        idx++;
      nsyms = symoff + idx + 1;
    }
  }

  // searching symbols
  info->dl_argv_vaddr = 0;
  info->dl_initial_searchlist_vaddr = 0;
  info->has_argv0 = false;
  for (size_t i = 0; i < nsyms; ++i) {
    auto const s = (const Elf64_Sym *)((const char *)symtab + i * syment);
    if (s->st_name) {
      auto const symname = strtab + s->st_name;
      if (!strcmp(symname, "_dl_argv"))
        info->dl_argv_vaddr = s->st_value;
      else if (!strcmp(symname, "_rtld_global_ro"))
        info->dl_initial_searchlist_vaddr = s->st_value + offsetof(rtld_global_ro_2_16, _dl_initial_searchlist);
      else if (!strcmp(symname, "_dl_initial_searchlist")) /* 2.2.5 */
        info->dl_initial_searchlist_vaddr = s->st_value;
      else if (!strcmp(symname, "__rtld_version_placeholder")) /* 2.34 */
        info->has_argv0 = true;
      else if (!strcmp(symname, "_dl_x86_get_cpu_features")) /* 2.33 on x64 */
        info->has_argv0 = true;
    }
  }

  if (!info->has_argv0 && (!info->dl_argv_vaddr || !info->dl_initial_searchlist_vaddr)) {
    ERR("cannot fix argv0");
    goto UNMAP_DONE;
  }

  rst = true;

UNMAP_DONE:
  munmap((void *)elf, st.st_size);
CLEAN_FD_DONE:
  if (fd >= 0)
    close(fd);
DONE:
  info->path[0] &= rst ? 0xFF : 0;
  return rst;
}

////////// Ptrace ////////////
static pid_t tracer_pid;
static bool ptrace_has_exitkill = true;
static int ptrace_tracee0_exit_code = 1;
static bool ptrace_has_group_stopped = 1;

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
static inline bool pt_syscall(const pid_t pid, const int sig) {
  DEBUG(pid, 0, 0, "PTRACE_SYSCALL");
  return PT_SUCCESS(PT_CALL(PTRACE_SYSCALL, pid, 0, sig));
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
static inline pt_result_t pt_get_regs(const pid_t pid, struct user_regs_struct dst[static 1]) {
  auto const r = PT_CALL_S(PTRACE_GETREGS, pid, 0, dst);
  return PT_SUCCESS(r) ? (pt_result_t)sizeof(*dst) : r;
}
static inline pt_result_t pt_get_user(const pid_t pid, const size_t ofs) {
  return PT_CALL_S(PTRACE_PEEKUSER, pid, ofs, 0);
}
#define pt_get(pid, ...)                      \
  _Generic((__VA_ARGS__ + 0),                 \
      int: pt_get_msg,                        \
      siginfo_t *: pt_get_siginfo,            \
      struct user_regs_struct *: pt_get_regs, \
      size_t: pt_get_user)((pid)__VA_OPT__(, ) __VA_ARGS__)

static inline pt_result_t pt_set_regs(const pid_t pid, const struct user_regs_struct dst[static 1]) {
  return PT_CALL_S(PTRACE_SETREGS, pid, 0, dst);
}
static inline pt_result_t pt_set_user(const pid_t pid, const size_t ofs, const uint64_t data) {
  return PT_CALL_S(PTRACE_POKEUSER, pid, ofs, data);
}
#define pt_set(pid, addr, ...) \
  _Generic(addr, struct user_regs_struct *: pt_set_regs, size_t: pt_set_user)((pid), (addr)__VA_OPT__(, ) __VA_ARGS__)

static_assert(sizeof(uintptr_t) == sizeof_member(struct user_regs_struct, rip));
static inline pt_result_t pt_read_word(const pid_t pid, const uintptr_t remote_addr) {
  return PT_CALL_S(PTRACE_PEEKDATA, pid, remote_addr, 0);
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

#define PT_READ_BULKS_FAST(pid, remote_addr, dst, dst_sz, ...) \
  PT_READ_BULKS(pid, remote_addr, 1, dst, dst_sz, true, false, false __VA_OPT__(, ) __VA_ARGS__)
#define PT_WRITE_BULKS(pid, remote_addr, src, src_sz, ...)                                            \
  __extension__({                                                                                     \
    auto _pt_bulks_remote = (const uint64_t *)(uintptr_t)(remote_addr);                               \
    auto _pt_bulks_local = (uint64_t *)(uintptr_t)(src);                                              \
    size_t _pt_bulks_sz = 0;                                                                          \
    for (; _pt_bulks_sz < (src_sz); _pt_bulks_sz += sizeof(uint64_t))                                 \
      PT_WRITE((pid), (uint64_t)(_pt_bulks_remote++), *_pt_bulks_local++ __VA_OPT__(, ) __VA_ARGS__); \
    _pt_bulks_sz;                                                                                     \
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

static bool alloc_exec_buffer();
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

  // alloc the exec handler buffer
  if (!alloc_exec_buffer())
    kill9_child_and_exit(child, 70);

  DEBUG(child, status >> 16, sig, "TRACEE0 FIRST STOP");

  static auto const options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                              PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD;
  static auto const options_w_exitkill = options | PTRACE_O_EXITKILL;

  auto const try_set_opt = _OK_CALL(ptrace(PTRACE_SETOPTIONS, child, 0, options_w_exitkill), _ != -1 || errno == EINVAL,
                                    kill9_child_and_exit(child, 70));
  if (try_set_opt == -1) {
    ptrace_has_exitkill = false;
    _OK_CALL(ptrace(PTRACE_SETOPTIONS, child, 0, options), _ != -1, kill9_child_and_exit(child, 71));
  }

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
  union {
    struct {
      union {
        uint64_t arg1;
        uint64_t interp;                 // execve
        uint64_t dl_initial_searchlist;  // pre-prctl for glibc before 2.33
        uint64_t set_name;               // prctl
      };
      union {
        uint64_t arg2;
        uint64_t argv;  // execve
        uint64_t comm;  // prctl
      };
      union {
        uint64_t arg3;
        uint64_t envp;   // execve
        uint64_t argv0;  // prctl && hw break
      };
      union {
        uint64_t arg4;
        uint64_t this_param;  // 0 for pre-execve, used to select syscall number of execve or prctl
      };
      union {
        uint64_t arg5;
        uint64_t dr0;
      };
      union {
        uint64_t arg6;
        uint64_t dr7;
      };
    };
    struct user_regs_struct ctx;
  };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  union {
    uint64_t argv_array[];
    char elf_path[];
  };
#pragma GCC diagnostic pop
} inject_param_t;
// stack: |argc|argv...NULL|envp...NULL|auxv...NULL,NULL|padding|param...execve_argv...NULL|string-table|padding|
// string table: |interp|argv0-w-prefix|--library-path|at_execfn|ld-path|(--argv0)|elf-path|padding|
// dr0 == &param
static_assert(alignof(inject_param_t) % 8 == 0);
static_assert(offsetof(inject_param_t, argv_array) == offsetof(inject_param_t, elf_path));

static size_t exec_buffer_sz;
static uint8_t *exec_buffer;  // global static buffer to copy the stack data on exec stop, should be align to 4K
static bool alloc_exec_buffer() {
  auto const arg_max = _OK_CALL(sysconf(_SC_ARG_MAX), INT64_C(4096) <= _ && _ <= INT64_C(4194304), return false);
  auto const page_size = _OK_CALL(getpagesize(), _ >= 1024, return false);

  // can hold the whole argv/envp/aux, plus two paths(interp and libcdir)
  // and at_execfn(at most MAX_ARG_STRLEN) and 1K spaces
  auto const buffer_page_nr =
      ((arg_max + sizeof(inject_param_t) + arg_max + PATH_MAX * 2 + MAX_ARG_STRLEN * 2 + 1024) + page_size - 1) /
      page_size;
  exec_buffer_sz = buffer_page_nr * page_size;

  exec_buffer = _OK_CALL(mmap(NULL, exec_buffer_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
                         _ != MAP_FAILED, return false);
  return true;
}

// uint64_t argv0);
typedef struct {
  uint64_t rsp;
  uint64_t argc;
  uint64_t argv0;
  uint64_t argv_ofs;
  uint64_t envp_ofs;
  uint64_t auxv_ofs;
  uint64_t end_ofs;
  uint64_t param_ofs;
  uint64_t total_size;
  uint64_t auxv_map[64];  // AT_EXECFN = 31
} exec_arg_t;

// download and parse the original execve stack defined by 64bit Linux ABI
// [rsp low->high]: |argc|argv0|...|0|envp0|...|0|auxv0t|auxv0v|...|0|0|padding|AT_RANDOM data|
static bool parse_exec_arg(const pid_t pid, const uint64_t rsp, exec_arg_t *const exec_arg) {
  uint64_t ofs = 0;  // offset for both remote rsp base and local exec buffer base
  exec_arg->rsp = rsp;

  // argc, at least 1
  exec_arg->argc = PT_READ_CHK(pid, rsp + ofs, 0 < _ && _ < (1 << 18), return false);
  *(uint64_t *)(exec_buffer + ofs) = exec_arg->argc;
  ofs += sizeof(uint64_t);

  // argv[]
  exec_arg->argv_ofs = ofs;
  PT_READ_BULKS(pid, rsp + ofs, 1, exec_buffer + ofs, exec_arg->argc * sizeof(uint64_t), _ != 0, false, false,
                return false);
  ofs += (exec_arg->argc + 1) * sizeof(uint64_t);
  *(uint64_t *)(exec_buffer + ofs - sizeof(uint64_t)) = 0;  // append NULL after argv
  exec_arg->argv0 = *(uint64_t *)(exec_buffer + exec_arg->argv_ofs);

  // envp[]
  exec_arg->envp_ofs = ofs;
  ofs += PT_READ_BULKS(pid, rsp + ofs, 1, exec_buffer + ofs, (1 << 21), true, _ == 0, true, return false);
  *(uint64_t *)(exec_buffer + ofs) = 0;  // append NULL after envp
  ofs += sizeof(uint64_t);

  // auxv[]
  exec_arg->auxv_ofs = ofs;
  static_assert(sizeof(Elf64_auxv_t) == 2 * sizeof(uint64_t));
  ofs += PT_READ_BULKS(pid, rsp + ofs, sizeof(Elf64_auxv_t) / sizeof(uint64_t), exec_buffer + ofs,
                       128 * sizeof(Elf64_auxv_t), true, _ == AT_NULL, true, return false);
  // append AT_NULL marker after auxv
  *(Elf64_auxv_t *)(exec_buffer + ofs) = (Elf64_auxv_t){.a_type = AT_NULL, .a_un.a_val = 0};
  ofs += sizeof(Elf64_auxv_t);

  // from rsp + end_ofs on the tracee, there may be 8 bytes padding, leave them not be overwritten
  // from exec_buffer + auxv_end_ofs on tracer, the inject_param will be appended
  exec_arg->end_ofs = ofs;

  // analyze aux table
  memset(exec_arg->auxv_map, 0, sizeof(exec_arg->auxv_map));
  for (auto p = (const Elf64_auxv_t *)(exec_buffer + exec_arg->auxv_ofs); p->a_type != AT_NULL; ++p)
    if (p->a_type < ARRAY_SIZE(exec_arg->auxv_map))
      exec_arg->auxv_map[p->a_type] = p->a_un.a_val;

  if (!exec_arg->auxv_map[AT_EXECFN] || !exec_arg->auxv_map[AT_PHDR] || !exec_arg->auxv_map[AT_ENTRY] ||
      !exec_arg->auxv_map[AT_PHNUM] || exec_arg->auxv_map[AT_PHENT] != sizeof(Elf64_Phdr)) {
    DEBUG(pid, 0, 0, "non standard elf");
    return false;
  }
  if (exec_arg->auxv_map[AT_SECURE]) {
    DEBUG(pid, 0, 0, "run with setsid");
    return false;
  }

  return true;
}

static bool fill_param_static(const pid_t pid, exec_arg_t *const exec_arg, inject_param_t *const param) {
  // when static linked elf, distinguish the second stage of execve the target interp
  auto const execfn = (char *)(exec_buffer + exec_arg->end_ofs);
  _OK_CALL(pt_read_cstring(pid, exec_arg->auxv_map[AT_EXECFN], execfn, MAX_ARG_STRLEN), _ < MAX_ARG_STRLEN,
           return false);
  if (0 != strcmp(execfn, target_interp.path)) {
    DEBUG(pid, 0, 0, "normal static linked elf");
    return false;
  }
  auto const argv0_prefix = PT_READ(pid, exec_arg->argv0, return false);
  if (0 != memcmp(&argv0_prefix, "/\xFF\xFF\xFF\xFF\xFF\xFF/", 8) || exec_arg->argc < 6) {
    // no magic prefix or argc is too small.
    // argv[] contains at least [argv0, --library-path, AT_EXECFN, --library-path, path, execfn, ...]
    DEBUG(pid, 0, 0, "run target interp directly");
    return false;
  }

  // now, the current exec event is the injected one, fix some basic info first

  // fix argv0: replace orig-argv0 with interp path
  *(uint64_t *)(exec_buffer + exec_arg->argv_ofs) = exec_arg->auxv_map[AT_EXECFN];

  // fix AT_BASE and AT_EXECFN in auxv map
  auto const interp_at_base = exec_arg->auxv_map[AT_ENTRY] - target_interp.entry_vaddr;
  auto const orig_at_execfn = ((const uint64_t *)(exec_buffer + exec_arg->argv_ofs))[2];  // argv[2]
  for (auto p = (Elf64_auxv_t *)(exec_buffer + exec_arg->auxv_ofs); p->a_type != AT_NULL; ++p) {
    if (p->a_type == AT_BASE)
      p->a_un.a_val = interp_at_base;
    else if (p->a_type == AT_EXECFN)
      p->a_un.a_val = orig_at_execfn;
  }

  // copy elf_path
  size_t written = 0;
  if (!target_interp.has_argv0) {
    auto const argv5 = ((const uint64_t *)(exec_buffer + exec_arg->argv_ofs))[5];  // elf path in argv
    written = 1 + _OK_CALL(pt_read_cstring(pid, argv5, param->elf_path, PATH_MAX), _ < PATH_MAX, return false);
  }

  // calculate comm
  auto const argv2 = ((const uint64_t *)(exec_buffer + exec_arg->argv_ofs))[2];  // orig at_execfn in argv
  char *at_execfn = param->elf_path + written;
  _OK_CALL(pt_read_cstring(pid, argv2, at_execfn, MAX_ARG_STRLEN), _ < MAX_ARG_STRLEN, return false);
  auto const last_slash = strrchr(at_execfn, '/');
  auto const comm_idx = last_slash != nullptr ? last_slash + 1 - at_execfn : 0;

  auto const inc = exec_arg->param_ofs - exec_arg->end_ofs + sizeof(*param) + written;
  exec_arg->rsp = (typeof(exec_arg->rsp))ALIGN_D(exec_arg->rsp - inc, pt_result_t);
  exec_arg->total_size = exec_arg->end_ofs + inc;

  // fill param
  param->dl_initial_searchlist = interp_at_base + target_interp.dl_initial_searchlist_vaddr;
  param->comm = argv2 + comm_idx;                     // in system string table
  param->argv0 = exec_arg->argv0 + sizeof(uint64_t);  // in system string table
  param->this_param = exec_arg->rsp + exec_arg->param_ofs;
  param->dr0 = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[0])), return false);
  param->dr7 = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[7])), return false);

  // let argv0 point to elf_path in param
  if (!target_interp.has_argv0)
    ((uint64_t *)(exec_buffer + exec_arg->argv_ofs))[5] =
        exec_arg->rsp + exec_arg->param_ofs + offsetof(typeof(*param), elf_path);

  return true;
}
static bool fill_param_dynamic(const pid_t pid, exec_arg_t *const exec_arg, inject_param_t *const param) {
  // analyze PT_INTERP from main elf
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

  // layout from exec_arg.end_ofs see struct inject_param_t
  auto const execve_argc = exec_arg->argc + (target_interp.has_argv0 ? 7 : 5);  // argv_array size
  auto const strtbl = (char *)(param->argv_array + execve_argc + 1);            // string table
  size_t written = 0;                                                           // chars written to string table
  auto const strtbl_ofs = (uintptr_t)strtbl - (uintptr_t)exec_buffer;

  // copy argv[1..argc], including last NULL
  memcpy(param->argv_array + (execve_argc - exec_arg->argc + 1), exec_buffer + exec_arg->argv_ofs + sizeof(uint64_t),
         exec_arg->argc * sizeof(uint64_t));

  // copy interp
  param->interp = strtbl_ofs + written;
  written = 1 + stpcpy(strtbl + written, target_interp.path) - strtbl;

  // copy old argv[0]
  param->argv_array[0] = strtbl_ofs + written;
  memcpy(strtbl + written, "/\xFF\xFF\xFF\xFF\xFF\xFF/", 8);  // put magic before argv0
  written += 8;
  written += 1 + _OK_CALL(pt_read_cstring(pid, exec_arg->argv0, strtbl + written, MAX_ARG_STRLEN - 8),
                          _ < MAX_ARG_STRLEN - 8, return false);

  // copy "--library-path"
  auto const str_library_path_ofs = strtbl_ofs + written;
  written = 1 + stpcpy(strtbl + written, "--library-path") - strtbl;

  // copy AT_EXECFN
  param->argv_array[1] = str_library_path_ofs;
  param->argv_array[2] = strtbl_ofs + written;
  written += 1 + _OK_CALL(pt_read_cstring(pid, exec_arg->auxv_map[AT_EXECFN], strtbl + written, MAX_ARG_STRLEN),
                          _ < MAX_ARG_STRLEN, return false);

  // copy library path
  param->argv_array[3] = str_library_path_ofs;
  param->argv_array[4] = strtbl_ofs + written;
  written = 1 + stpcpy(strtbl + written, target_interp.libc_dir) - strtbl;

  // append env LD_LIBRARY_PATH
  static_assert(sizeof("LD_LIBRARY_PATH=") == 17);
  for (auto p = (const uint64_t *)(exec_buffer + exec_arg->envp_ofs); *p; ++p) {
    uint64_t name[2];
    name[0] = PT_READ(pid, *p, return false);
    if (memcmp(name, "LD_LIBRARY_PATH=", 8) != 0)
      continue;
    name[1] = PT_READ(pid, *p + 8, return false);
    if (memcmp(name, "LD_LIBRARY_PATH=", 16) != 0)
      continue;

    auto const ld_lib_path_len =
        _OK_CALL(pt_read_cstring(pid, *p + 16, strtbl + written, MAX_ARG_STRLEN), _ < MAX_ARG_STRLEN, return false);
    if (ld_lib_path_len) {
      strtbl[written - 1] = ':';  // replace '\0' with ':'
      written += ld_lib_path_len + 1;
    }
    break;
  }

  // copy --argv0 for new glibc
  if (target_interp.has_argv0) {
    param->argv_array[5] = strtbl_ofs + written;
    written = 1 + stpcpy(strtbl + written, "--argv0") - strtbl;
    param->argv_array[6] = param->argv_array[0] + 8;
  }

  // copy main elf path, read from /proc/pid/exe, since AT_EXECFN may be a script path
  param->argv_array[target_interp.has_argv0 ? 7 : 5] = strtbl_ofs + written;
  {
    char proc_exec[64];
    _OK_CALL(snprintf(proc_exec, sizeof(proc_exec), "/proc/%d/exe", pid), _ < (int)sizeof(proc_exec), return false);
    _OK_CALL(realpath(proc_exec, strtbl + written), _ != nullptr, return false);
    if (strncmp(strtbl + written, chlibc_root, chlibc_root_len) != 0)
      return false;  // not under chlibc root
    written += strlen(strtbl + written) + 1;
  }

  // new rsp must be aligned to 16 bytes
  auto const inc = strtbl_ofs - exec_arg->end_ofs + written;
  exec_arg->rsp = (typeof(exec_arg->rsp))ALIGN_D(exec_arg->rsp - inc, pt_result_t);
  exec_arg->total_size = exec_arg->end_ofs + inc;

  // fix remote pointers in param
  param->interp += exec_arg->rsp;
  param->argv = exec_arg->rsp + exec_arg->param_ofs + offsetof(typeof(*param), argv_array);
  param->envp = exec_arg->rsp + exec_arg->envp_ofs;
  for (size_t i = 0, c = target_interp.has_argv0 ? 8 : 6; i < c; ++i)
    param->argv_array[i] += exec_arg->rsp;

  param->this_param = 0;
  param->dr0 = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[0])), return false);
  param->dr7 = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[7])), return false);

  return true;
}

static bool handle_exec(const pid_t pid) {
  struct user_regs_struct regs;
  PT_OK_CALL(pt_get(pid, &regs), return false);

  exec_arg_t exec_arg;
  if (!parse_exec_arg(pid, regs.rsp, &exec_arg))  // rsp aligns to 16 bytes via 64bit Linux ABI
    return false;

  auto const param = ALIGN_U(exec_buffer + exec_arg.end_ofs, inject_param_t);
  exec_arg.param_ofs = (uintptr_t)param - (uintptr_t)exec_buffer;

  if (exec_arg.auxv_map[AT_ENTRY] == regs.rip ? !fill_param_static(pid, &exec_arg, param)    // static elf
                                              : !fill_param_dynamic(pid, &exec_arg, param))  // elf load by PT_INTERP
    return false;

  // backup param address in DR0, disable HW breakpoints
  auto const param_remote = exec_arg.rsp + exec_arg.param_ofs;
  _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[0]), param_remote), PT_SUCCESS(_), return false);
  _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[7]), 0), PT_SUCCESS(_), return false);

  // alloca() from stack by moving down the _start() arguments on stack
  // the original argc...auxv[AT_NULL] are overwritten
  regs.rsp = exec_arg.rsp;
  _OK_CALL(pt_set(pid, &regs), PT_SUCCESS(_), return false);
  PT_WRITE_BULKS(pid, exec_arg.rsp, exec_buffer, exec_arg.total_size);

  return true;  // continue to syscall
}

static bool inject_syscall(const pid_t pid, struct user_regs_struct *const regs) {
  // download param
  auto const param_remote = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[0])), return false);
  inject_param_t param;
  PT_READ_BULKS_FAST(pid, param_remote, &param, end_offsetof(typeof(param), arg6));  // copy only syscall parameters

  // upload regs
  static_assert(sizeof_member(typeof(param), ctx) == sizeof(*regs));
  PT_WRITE_BULKS(pid, param_remote + offsetof(typeof(param), ctx), regs, sizeof(*regs));

  auto const syscall_num = param.this_param == 0 ? SYS_execve : SYS_prctl;
  auto restore_dr = true;

  if (syscall_num == SYS_prctl) {
    if (!target_interp.has_argv0) {
      // setup HW breakpoints, DR0 = dl_initial_searchlist
      restore_dr = false;
      auto const dr0 = param.dl_initial_searchlist;

      uint64_t dr7 = 0;
      dr7 |= 1 << 0;   // L0 = 1
      dr7 |= 1 << 16;  // RW0 = 01 (write)
      dr7 |= 3 << 18;  // LEN0 = 11 (4 bytes to support all old glibc from 2.5 to 2.32)

      _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[0]), dr0), PT_SUCCESS(_), return false);
      _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[7]), dr7), PT_SUCCESS(_), return false);
    }
    param.set_name = PR_SET_NAME;
  }

  if (restore_dr) {
    // restore DR0, DR7
    _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[0]), param.dr0), PT_SUCCESS(_), return false);
    _OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[7]), param.dr7), PT_SUCCESS(_), return false);
  } else
    param.this_param = param_remote;

  regs->rax = regs->orig_rax = syscall_num;
  regs->rdi = param.arg1;
  regs->rsi = param.arg2;
  regs->rdx = param.arg3;
  regs->r10 = param.arg4;
  regs->r8 = param.arg5;
  regs->r9 = param.arg6;

  _OK_CALL(pt_set(pid, regs), PT_SUCCESS(_), return false);

  return true;
}
static bool restore_syscall(const pid_t pid, struct user_regs_struct *const regs) {
  if ((errno = -(int64_t)regs->rax)) {
    ERR("inject syscall(%d) fail", regs->orig_rax);
    errno = 0;
  }

  // download param
  auto const param_remote = regs->r10;  // arg4
  inject_param_t param;
  PT_READ_BULKS_FAST(pid, param_remote, &param, end_offsetof(typeof(param), ctx));

  if (regs->orig_rax == SYS_prctl && !target_interp.has_argv0) {
    // restore and upload params for HW breakpoints
    param.argv0 = regs->rdx;  // arg3
    param.dr0 = regs->r8;     // arg5
    param.dr7 = regs->r9;     // arg6
    PT_WRITE(pid, param_remote + offsetof(typeof(param), argv0), param.argv0);
    PT_WRITE(pid, param_remote + offsetof(typeof(param), dr0), param.dr0);
    PT_WRITE(pid, param_remote + offsetof(typeof(param), dr7), param.dr7);
  }

  param.ctx.rip -= 2;  // point to 0F05 syscall
  _OK_CALL(pt_set(pid, &param.ctx), PT_SUCCESS(_), return false);
  return true;
}

// fix argv0 after main elf is loaded
static bool fix_argv0_on_hw_brk(const pid_t pid) {
  auto const dl_initial_searchlist = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[0])), return false);
  auto const dl_argv_p =
      dl_initial_searchlist - target_interp.dl_initial_searchlist_vaddr + target_interp.dl_argv_vaddr;
  auto const dl_argv = PT_READ(pid, dl_argv_p, return false);

  // download fix_argv0_param
  auto const elf_path = PT_READ_CHK(pid, dl_argv, _ != 0, return false);
  auto const param_remote = container_of(elf_path, inject_param_t, elf_path);
  inject_param_t param;
  PT_READ_BULKS_FAST(pid, param_remote, &param, sizeof(param));

  // fix argv0: elf_path -> previous argv0
  PT_WRITE(pid, dl_argv, param.argv0, return false);

  pt_set(pid, offsetof(struct user, u_debugreg[0]), param.dr0);  // restore DR0 and DR7
  pt_set(pid, offsetof(struct user, u_debugreg[7]), param.dr7);
  return true;
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
    // check hw breakpoint
    auto const dr6 = PT_OK_CALL(pt_get(pid, offsetof(struct user, u_debugreg[6])), goto CONT);
    if (dr6) {
      if (exitsig == 0 && dr6 & 1) {  // ignore DR1~3
        if (!fix_argv0_on_hw_brk(pid))
          DEBUG(pid, 0, 0, "fail to fix argv0 on hw breakpoint");
      }
      PT_OK_CALL(pt_set(pid, offsetof(struct user, u_debugreg[6]), 0), goto CONT);  // clear DR6
      goto CONT;
    }

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
      if (0 == exitsig && handle_exec(pid) && pt_syscall(pid, deliver_sig))
        return;  // continue to the next syscall to replace the interp

      break;

    default:
      DEBUG(pid, status >> 16, exitsig, "unknown ptrace event or non ptrace-stop");
    }

  } else if (stopsig == (SIGTRAP | 0x80)) {
    struct user_regs_struct regs;
    PT_OK_CALL(pt_get(pid, &regs), goto CONT);
    if (regs.orig_rax == SYS_execve && regs.rax == 0) {
      if (pt_syscall(pid, deliver_sig))
        return;  // exit-stop of execve after PTRACE_EVENT_EXEC
    } else if (regs.rax == regs.orig_rax || (int64_t)regs.rax == -(int64_t)ENOSYS) {
      // now on the enter-stop of brk(0) in interp for protecting the bootstrap heap
      if (inject_syscall(pid, &regs) && pt_syscall(pid, deliver_sig))
        return;  // continue to the syscall exit-stop
    } else if ((regs.orig_rax == SYS_execve && (int64_t)regs.rax < 0) || regs.orig_rax == SYS_prctl) {
      if (!restore_syscall(pid, &regs))
        deliver_sig = SIGKILL;  // restore fail, force kill the tracee
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
CONT:
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
  if (is_kill && ptrace_has_exitkill)
    return 128 + sig;

  pids_kill_all(is_kill ? SIGKILL : SIGTERM);

  auto curr = now_ns();
  auto const softline = curr + (1000000000LL * (is_kill ? 0LL : 1000LL)) / 1000;
  auto deadline = curr + (1000000000LL * (is_kill ? 50LL : 1050LL)) / 1000;
  const struct timespec sleepns = {.tv_sec = 0, .tv_nsec = 701000};
  int status;

  // decent exiting loop
  while ((curr = now_ns()) < softline) {
    if (atomic_exchange_explicit(&pending_signal, 0, memory_order_relaxed) & _SIGBIT1(SIGKILL)) {
      // promote term to kill
      sig = min_exit_signal(signals, true);
      if (ptrace_has_exitkill)
        return 128 + sig;
      deadline = curr + 1000000000LL * 50LL / 1000;
      break;
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

  if (ptrace_has_exitkill)
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

  if (!init_interp_info(find_target_interp_path(), find_target_libc_dir(), &target_interp) || !init_chlibc_root()) {
    ERR("fail to init target interp info");
    return 65;
  }

  // block all signals, saving init masks
  _OK_CALL(sigfillset(&sig_mask_all), _ == 0, _Exit(65));
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_all, &sig_mask_init), _ == 0, _Exit(66));

  setup_sentinel_if_need_or_die();
  setup_signal_handlers_or_die();

  // set sub reaper, support from 3.4 kernel
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
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_all, nullptr), _ == 0, return 67);

  auto const tracee0 = fork();

  if (0 == tracee0) {
    // ptrace handshake as the first tracee
    _OK_CALL(ptrace(PTRACE_TRACEME, 0, 0, 0), _ != -1, _Exit(1));
    _OK_CALL(raise(SIGSTOP), _ == 0, _Exit(2));  // si_code in (SI_USER, SI_TKILL), si_pid is the child pid

    // restore sig masks
    _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), _ == 0, return 3);
    execvp(argv[1], argv + 1);
    FATAL(127, "chlibc: exec %s fail", argv[1]);
  }

  _OK_CALL(tracee0, _ != -1, return 68);

  // restore sig masks
  _OK_CALL(sigprocmask(SIG_SETMASK, &sig_mask_init, nullptr), _ == 0, kill9_child_and_exit(tracee0, 69));

  // ptrace main
  ptrace_handshake_as_tracer_or_die(tracee0);  // handshake and send the first PTRACE_CONT th tracee0
  auto const esignals = ptrace_loop();
  exit_code = ptrace_exiting(esignals);

  if (exit_code && !ptrace_has_exitkill && pids->raw)
    ERR("PIDs table is not clean, table head bits=%u, next=%u", pids->bits, pids->next);

EXIT:
  _log_writev(nullptr, 0);  // flush log
  return exit_code ? exit_code : ptrace_tracee0_exit_code;
}
