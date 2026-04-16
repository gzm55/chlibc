# chlibc

A lightweight 64bit Linux userspace loader that enables running programs with a custom glibc environment.
It dynamically intercepts execution and redirects the target process to a specified runtime (e.g. Conda sysroot or custom glibc build).

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

- `CHLIBC_INTERP`: Path to target dynamic linker (e.g. ld-linux-x86-64.so.2)
- `CHLIBC_GLIBC_HOME`: Root directory of custom glibc
- `CHLIBC_PREFIX`: Override project root path, only replace the interp and glibc when the elf is under this directory.
- `CONDA_PREFIX`: When set, automatically detects the previous three environments

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

### Manual build

```bash
cmake --preset clang-x86_64 -S .
./cmake-build --preset clang-x86_64-release
```
