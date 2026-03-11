message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# cmake-format: off
# Toolchain file
#   - passed from preset.json or cli
#   - may be executed multiple times when project()
#   - must be idempotent
# cmake-format: on

# Target System Configuration
set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_SYSTEM_NAME Linux) # only support Linux OS

cmake_path(GET CMAKE_CURRENT_LIST_FILE STEM _cc_and_arch)
string(REGEX REPLACE "^([^-]+)-(.*)$" "\\1" _cc "${_cc_and_arch}")
string(REGEX REPLACE "^([^-]+)-(.*)$" "\\2" CMAKE_SYSTEM_PROCESSOR "${_cc_and_arch}")

# Compiler Paths
if(NOT DEFINED ENV{CONDA_PREFIX})
  message(FATAL_ERROR "CONDA_PREFIX environment variable not set. Please run via 'pixi run'.")
endif()

set(CMAKE_C_COMPILER_TARGET "${CMAKE_SYSTEM_PROCESSOR}-conda-linux-gnu")
set(CMAKE_SYSROOT "$ENV{CONDA_PREFIX}/${CMAKE_C_COMPILER_TARGET}/sysroot")

if(_cc STREQUAL "clang")
  set(_toolchain_bin_prefix "")
  set(_toolchain_tool_prefix llvm-)
elseif(_cc STREQUAL "gcc")
  set(_toolchain_bin_prefix "${CMAKE_C_COMPILER_TARGET}-")
  set(_toolchain_tool_prefix "${_toolchain_bin_prefix}")
else()
  message(FATAL_ERROR "Only supports Clang and GCC")
endif()

set(CMAKE_C_COMPILER "${_toolchain_bin_prefix}${_cc}")
set(CMAKE_OBJCOPY "${_toolchain_tool_prefix}strip")

# Search Policy (Sysroot Control)

# find header/lib/package under the conda prefix
set(CMAKE_FIND_ROOT_PATH "${CMAKE_SYSROOT}" "$ENV{CONDA_PREFIX}")

# do not depends on the header/lib on host
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Init flags: append arch specific flags after the user passed (cached) _INIT variables

# restore to cached value from cli arguments and append start markers
set(CMAKE_C_FLAGS_INIT "$CACHE{CMAKE_C_FLAGS_INIT} -U__CMAKE_C_FLAGS_INIT") # empty marker
set(CMAKE_EXE_LINKER_FLAGS_INIT "$CACHE{CMAKE_EXE_LINKER_FLAGS_INIT} -D__CMAKE_EXE_LINKER_FLAGS_INIT") # begin marker
string(STRIP "${CMAKE_C_FLAGS_INIT}" CMAKE_C_FLAGS_INIT)
string(STRIP "${CMAKE_EXE_LINKER_FLAGS_INIT}" CMAKE_EXE_LINKER_FLAGS_INIT)

if(_cc STREQUAL "clang")
  # switch linker and runtime lib
  string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -fuse-ld=lld")
  string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " --rtlib=compiler-rt")
else()
  string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " LINKER:-rpath-link,${CMAKE_SYSROOT}/lib")
endif()

string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -U__CMAKE_EXE_LINKER_FLAGS_INIT") # end marker

# register post project() hook
list(APPEND CMAKE_PROJECT_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/per-project-post.cmake")
list(REMOVE_DUPLICATES CMAKE_PROJECT_INCLUDE)

unset(_cc)
unset(_cc_and_arch)
unset(_toolchain_bin_prefix)
unset(_toolchain_tool_prefix)
