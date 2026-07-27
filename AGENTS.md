## Build / Dev Commands

- `./pixiw run configure` — CMake configure (all 4 architectures)
- `./pixiw run build` — build all Debug + Release for all arches
- `./pixiw run lint` — all pre-commit checks (typos, linters, formatters)
- `./pixiw run fmt` — format only (no lint checks), auto-fixes
- Single arch: `cmake --preset clang-x86_64 -S .` then `./cmake-build --preset clang-x86_64-release`

`pixiw` is the repo-root pixi wrapper — it auto-installs pixi if missing.

## Architecture & Presets

| Arch        | Compiler | Preset           | Build Dir              |
|-------------|----------|------------------|------------------------|
| x86_64      | clang    | clang-x86_64     | build/clang-x86_64     |
| aarch64     | clang    | clang-aarch64    | build/clang-aarch64    |
| riscv64     | gcc      | gcc-riscv64      | build/gcc-riscv64      |
| powerpc64le | gcc      | gcc-powerpc64le  | build/gcc-powerpc64le  |

## Key Constraints

- **C23 only.** `__STDC_VERSION__ >= 202311L` required. GCC ≥ 14 or Clang ≥ 18.
- **GNU extensions required** (`_GNU_SOURCE`). No MSVC, no musl.
- **No RPATH/RUNPATH.** Build will FATAL_ERROR if `LD_RUN_PATH` is set. All RPATH is aggressively stripped.
- **Warnings are errors** (`CMAKE_COMPILE_WARNING_AS_ERROR ON`).
- **64-bit little-endian only.** Compile-time asserts enforce this.
- **Version from env:** `PIXI_PROJECT_VERSION` (pixi) or `PKG_VERSION` (rattler-build). Falls back to `0.1.0-dev`.

## Code Structure

| Path                                   | Role                                                             |
|----------------------------------------|------------------------------------------------------------------|
| `src/chlibc.c`                         | Main binary — ptrace-based execve interceptor (~2400 lines)      |
| `src/loader.c` + `src/loader-{arch}.c` | Freestanding loader injected into target process                 |
| `src/loader.h`                         | Shared types between chlibc and loader (regs, relocation macros) |
| `src/loader.ld.S`                      | Linker script template for embedding loader                      |
| `src/common.h`                         | Arch detection, alignment macros, utility types                  |
| `src/init.c`                           | Minimal init for QEMU VM test initramfs                          |
| `src/dump-args.c`                      | Test helper — prints argv/env for VM test assertions             |
| `cmake/toolchain/`                     | Cross-compile toolchain files, one per arch + conda-build        |
| `vm-test/`                             | QEMU integration tests (no unit tests exist)                     |

## The Loader Component (`chlibc-loader`)

Compiled with `-ffreestanding` — **no standard library, no libc calls**. It implements its own tiny libc (string ops, memcpy) inline. Key restrictions:
- Must only produce `.loader.*` ELF sections (enforced by `loader_audit.sh`)
- Only position-relative relocations allowed (no absolute/GOT/PIC relocs)
- No FPU or SIMD register use — `-mgeneral-regs-only` (x86_64/aarch64) or `-msoft-float -mno-altivec -mno-vsx` (ppc64le)
- **The loader is embedded into the chlibc binary** via a custom linker script. All addresses are relocated at runtime using the `RELO_*` macro system.

When adding code to `loader.c`, never call external functions or use floating-point types.

## Testing

**There are no unit tests.** All testing is QEMU-based VM integration:
- `./pixiw run vm-test` — runs all 6 VM tests
- `./pixiw run vm-test-x86_64-2_6_18` — individual VM test
- `vm-test/run.sh <arch> <build_dir> <kernel_ver> [pixi_env]`
- Tests pass by grepping VM serial output for expected glibc paths or "FATAL: kernel too old"

Tests download kernels and glibc RPMs into `vm-test/dl-cache/`. First run may be slow.

## Lint & Format

- `./pixiw run lint` runs lefthook across all files: typos, toml/yaml/json/cmake linters + formatters, clang-format
- Clang-format: Google-based, 2-space indent, 120 cols, `PointerAlignment: Right`, `StatementMacros: ["_Pragma", "LOADER_SECTION"]`
- Pre-commit hooks auto-fix EOF, trailing whitespace, BOM, and formatting. **Typos are NOT auto-fixed** (requires manual confirmation).
- Exclude `*.patch` from trailing-whitespace fixer.

## Release Process

`./release.sh [patch|minor|major]` — requires clean working tree + `.dev` version suffix. It:
1. Lints + builds, verifies clean tree again
2. Strips `.dev` → sets release version → commits `pixi.toml` + `conda/recipe.yaml`
3. Rebuilds from scratch (`rm -rf build`) for clean checksums
4. Tags with SHA256 checksums of all 4 arch binaries for reproducible build verification
5. Restores `.dev` suffix, bumps version, updates conda recipe hash

**Never bump the version manually without understanding this flow.** The `conda/recipe.yaml` version + hash must stay in sync.

## Code Audit (2025-07)

All 17 issues from the 2025-07 code audit have been resolved (8 fixed, 9 WONTFIX — see git log for details).
