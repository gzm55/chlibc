#include <errno.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static inline void do_mount(const char *source, const char *target, const char *type) {
  mkdir(target, 0755);
  if (mount(source, target, type, 0, NULL) != 0)
    fprintf(stderr, "Mount %s on %s (%s) failed: %s\n", source, target, type, strerror(errno));
  else
    printf("Mounted %s on %s\n", source, target);
}

static inline void print_env() {
  printf("\n--- Environment Variables ---\n");
  for (char **env = environ; *env != NULL; env++) {
    printf("%s\n", *env);
  }
  printf("\n");
}

static inline void init_terminal() {
  setsid();
  if (-1 == ioctl(STDERR_FILENO, TIOCSCTTY, 1))
    perror("TIOCSCTTY failed");
  if (-1 == tcsetpgrp(STDERR_FILENO, getpgrp()))
    perror("tcsetpgrp failed");
}

static void do_main(const int argc, char *const argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
    return;
  }

  do_mount("proc", "/proc", "proc");

  init_terminal();

  print_env();

  auto const pid = fork();
  if (pid < 0) {
    perror("Fork failed");
    return;
  }
  if (pid == 0) {
    // child
    printf("Executing: %s\n\n", argv[1]);
    execvp(argv[1], &argv[1]);
    perror("Exec failed");
    _Exit(127);
  }

  // init waits the child
  int status;
  waitpid(pid, &status, 0);

  if (WIFEXITED(status))
    printf("\nChild exited normally with code: %d\n", WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
    printf("\nChild terminated by signal: %d\n", WTERMSIG(status));
}

int main(const int argc, char *const argv[]) {
  printf("--- Simple Init Started (PID %d) ---\n", getpid());
  do_main(argc, argv);

  printf("--- Reboot to close VM ---\n");
  reboot(LINUX_REBOOT_CMD_RESTART);  // reboot and '-no-reboot' option to poweroff the VM

  __builtin_unreachable();
  return 0;
}
