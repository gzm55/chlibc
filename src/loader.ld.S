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
  ASSERT(loader_loader_end - loader_loader == 4 + 22 + 8, "loader_loader size is not  4 + 26 + 8 on x86_64")
#else // aarch64
  ASSERT(loader_loader_end - loader_loader == (1 + 12 + 2)*4, "loader_loader size is not (1 + 12 + 1)*4 on aarch64")
#endif

ASSERT(((loader_loader_end - loader_loader + 7) & ~7) <= loader_loader_pad_end - loader_loader, "pad is not enough for 8 bytes")
