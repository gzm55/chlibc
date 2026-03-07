# -------------------------------------------------------------------------------
# Target System Configuration
# -------------------------------------------------------------------------------
set(CMAKE_SYSTEM_NAME Linux) # only support Linux OS
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_CROSSCOMPILING TRUE)

# -------------------------------------------------------------------------------
# Compiler Paths
# -------------------------------------------------------------------------------

if(NOT DEFINED ENV{CONDA_PREFIX})
  message(FATAL_ERROR "CONDA_PREFIX environment variable not set. Please run via 'pixi run'.")
endif()

set(CMAKE_C_COMPILER_TARGET aarch64-conda-linux-gnu)
set(CMAKE_SYSROOT "$ENV{CONDA_PREFIX}/${CMAKE_C_COMPILER_TARGET}/sysroot")

set(CMAKE_C_COMPILER "clang")
set(CMAKE_STRIP "strip")

# -------------------------------------------------------------------------------
# Search Policy (Sysroot Control)
# -------------------------------------------------------------------------------

# find header/lib/package under the conda prefix
set(CMAKE_FIND_ROOT_PATH "${CMAKE_SYSROOT}" "$ENV{CONDA_PREFIX}")

# do not depends on the header/lib on host
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# -------------------------------------------------------------------------------
# Flags Optimization
# -------------------------------------------------------------------------------

set(C_FLAGS_ARCH "-march=armv8.2-a -mtune=neoverse-n1")
set(CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld --rtlib=compiler-rt")
