SECTIONS {
  .loader :
  {
    *(.loader.rodata*)
    *(.loader.text*)

    . = (. < 0x1000 ? 0x1000 : .);
    *(.loader.entry)
  }
} INSERT AFTER .text;

#if defined(__x86_64__)
  ASSERT(loader_loader_end - loader_loader == 21, "loader_loader size is not  21 on x86_64")
  ASSERT(loader_end - trap_ok_marker == 10, "ok marker size is not 10")
#else // aarch64
  ASSERT(loader_loader_end - loader_loader == 10*4, "loader_loader size is not 10*4 on aarch64")
  ASSERT(loader_end - trap_ok_marker == 16, "ok marker size is not 16")
#endif

ASSERT(loader_end - trap_munmap_fail_marker == 8, "munmap fail marker size is not 8")
