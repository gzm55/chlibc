# chlibc

A lightweight 64-bit Linux userspace tool that lets you run any dynamically linked program with a **custom glibc** (Conda, custom build, or alternate sysroot).
It uses ptrace to transparently replace the dynamic linker (`PT_INTERP`) and libc at every `execve` — no containers, no binary patching, no `LD_*` env hacks.

## Runtime Kernel Requirements

| Architecture   | Minimum Kernel Version |
|----------------|------------------------|
| x86_64 (X64)   | Linux >= 2.6.18        |
| AMD64          | Linux >= 3.19          |
| RISC-V 64      | Linux >= 5.4           |

## Usage

### Basic usage:

```bash
chlibc <target_program> [args...]
```

### Environment Variables

| Variable            | Description                                                 |
|---------------------|-------------------------------------------------------------|
| `CONDA_PREFIX`      | Auto-detects everything (recommended)                       |
| `CHLIBC_INTERP`     | Path to target dynamic linker (e.g. `ld-linux-x86-64.so.2`) |
| `CHLIBC_GLIBC_HOME` | Root directory of custom glibc                              |
| `CHLIBC_PREFIX`     | Only replace when binary is under this path                 |

### Example

```bash
export CONDA_PREFIX=/opt/conda/envs/myenv
chlibc python
chlibc /path/to/script.py
```

## Build

Requirements
- Linux x64 or MacOS aarch64
- CMake and Ninja
- pixi (recommended)

### Using pixi

```bash
./pixiw run configure
./pixiw run build
```

Using `pixi`, builds are fully reproducible.

### Manual build

```bash
cmake --preset clang-x86_64 -S .
./cmake-build --preset clang-x86_64-release
```
