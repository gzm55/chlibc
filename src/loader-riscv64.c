// TODO
[[noreturn]] [[gnu::naked]] [[gnu::noinline]]
void loader_loader() {
  __asm__ volatile(
      ".global loader_loader_entry, loader_loader_end, loader_loader_restore_syscall, trap_restore_marker;"
      "loader_loader_entry:"
      "fail_trap:"
      "trap_restore_marker:"
      "c.ebreak;"
      "loader_loader_restore_syscall:"
      "ecall; .2byte 0x3065;"
      "loader_loader_end:" ::);
}
