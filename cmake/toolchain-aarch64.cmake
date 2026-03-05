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

set(TOOLCHAIN_bin_prefix "$ENV{CONDA_PREFIX}/bin/aarch64-conda-linux-gnu-")
set(TOOLCHAIN_sysroot "$ENV{CONDA_PREFIX}/aarch64-conda-linux-gnu/sysroot")

set(CMAKE_C_COMPILER   "${TOOLCHAIN_bin_prefix}gcc")
set(CMAKE_STRIP        "${TOOLCHAIN_bin_prefix}strip")

# -------------------------------------------------------------------------------
# Search Policy (Sysroot Control)
# -------------------------------------------------------------------------------

# find header/lib/package under the conda prefix
set(CMAKE_FIND_ROOT_PATH "${TOOLCHAIN_sysroot}" "$ENV{CONDA_PREFIX}")

# do not depends on the header/lib on host
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# -------------------------------------------------------------------------------
# Flags Optimization
# -------------------------------------------------------------------------------

set(C_FLAGS_ARCH "")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath-link,${TOOLCHAIN_sysroot}/lib")
