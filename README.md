# chlibc

A lightweight 64-bit Linux userspace tool that lets you run any dynamically linked program with a **custom glibc** (Conda, custom build, or alternate sysroot).
It uses ptrace to transparently replace the dynamic linker (`PT_INTERP`) and libc at every `execve` — no containers, no binary patching, no `LD_*` env hacks.

## Runtime Kernel Requirements

| Architecture | Minimum Kernel Version |
|--------------|------------------------|
| x86_64 (X64) | Linux >= 2.6.18        |
| PowerPC64 LE | Linux >= 3.10          |
| aarch64      | Linux >= 3.19          |
| RISC-V 64    | Linux >= 5.4           |

## Usage

### Basic usage:

```bash
chlibc <target_program> [args...]
```

### Path Configuration

Three paths control chlibc's behavior, auto-discovered in priority order:

| Path               | Variable            | Fallback Chain                                                              | Purpose                                                                                                                         |
| ------------------ | ------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| **Interpreter**    | `CHLIBC_INTERP`     | `CHLIBC_GLIBC_HOME` → `CONDA_PREFIX` → `dirname($0)/../<arch>/sysroot`      | Target dynamic linker (`ld.so`).   |
| **GLIBC Home**     | `CHLIBC_GLIBC_HOME` | `CONDA_PREFIX` → `dirname(CHLIBC_INTERP)` → `dirname($0)/../<arch>/sysroot` | Custom glibc root directory. Injected as first entry in `LD_LIBRARY_PATH`.                  |
| **Prefix / Scope** | `CHLIBC_PREFIX`     | `CONDA_PREFIX` → `dirname($0)/..`                                           | Replacement scope limit. Only binaries under this path (`/proc/<pid>/exe`) are intercepted. |


### Environment Variables

| Variable             | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `CONDA_PREFIX`       | Auto-detects everything (recommended)                                       |
| `CHLIBC_INTERP`      | Path to target dynamic linker (e.g. `ld-linux-x86-64.so.2`)                 |
| `CHLIBC_GLIBC_HOME`  | Root directory of custom glibc                                              |
| `CHLIBC_PREFIX`      | Only replace when binary is under this path                                 |
| `CHLIBC_LOGGER_FILE` | Path to log file. If unset, defaults to stderr (if TTY) or syslog fallback. |


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

### Release Process

The project automates version management and release preparation using the `release.sh` script.

#### Prerequisites

Before initiating a release, ensure your local environment meets the following conditions:
1. **Clean Working Tree:** Your working directory must be clean (no uncommitted changes in tracked files).
2. **Development Versioning:** The current version in `pixi.toml` must end with a `-dev` suffix (e.g., `0.1.0-dev`).
3. **Toolchain Readiness:** The pixi multi-architecture environments must be fully functional for all target compilations.

#### Executing a Release

Run the release script from the repository root, optionally passing the semantic version bump type (`patch`, `minor`, or `major`). If omitted, it defaults to `patch`.

```bash
# Perform a patch release (e.g., 0.1.0-dev -> 0.1.0 -> 0.1.1-dev)
./release.sh
./release.sh patch

# Perform a minor release (e.g., 0.1.0-dev -> 0.1.0 -> 0.2.0-dev)
./release.sh minor

# Perform a major release (e.g., 1.0.0-dev -> 1.0.0 -> 2.0.0-dev)
./release.sh major
```

#### Post-Release Manual Steps

1. Push to Remote Server: `git push origin main --tags`
2. Publish on GitHub Releases: Navigate to the Releases section of the github repository
   and edit the draft of the new release created by CI workflow.
3. Write the release summary.
4. Click Publish release.
