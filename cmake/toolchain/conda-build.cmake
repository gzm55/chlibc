message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# unused var from CMAKE_ARGS
unset(CMAKE_CXX_COMPILER_AR)
unset(CMAKE_CXX_COMPILER_RANLIB)
unset(MAKE_FIND_ROOT_PATH_MODE_LIBRARY)
unset(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY)
unset(CMAKE_INSTALL_LIBDIR)

# Toolchain file for conda-build, accept most args from conda-build or rattler-build
if(NOT DEFINED ENV{CONDA_BUILD})
  message(FATAL_ERROR "CONDA_BUILD variable not set. Please run via 'conda-build' or 'rattler-build'.")
endif()

# Target System Configuration, only support Linux OS
set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_SYSTEM_NAME
    "Linux"
    CACHE STRING "Target System Name")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Require CMAKE_SYSTEM_NAME=Linux, unsupported operating system: '${CMAKE_SYSTEM_NAME}'.")
endif()

# Compiler target and sysroot
set(CMAKE_C_COMPILER_TARGET "$ENV{HOST}")
set(CMAKE_SYSROOT "$ENV{CONDA_BUILD_SYSROOT}")

if($ENV{CC} MATCHES "clang")
  set(CMAKE_C_PP_FLAGS "--target=${CMAKE_C_COMPILER_TARGET}")
  set(_toolchain_tool_prefix llvm-)
elseif($ENV{CC} MATCHES "gcc")
  set(CMAKE_C_PP_FLAGS "")
  set(_toolchain_tool_prefix "${CMAKE_C_COMPILER_TARGET}-")
else()
  message(FATAL_ERROR "Only supports Clang and GCC via CC env, but found '$ENV{CC}'.")
endif()

set(CMAKE_C_COMPILER "$ENV{CC}")
set(CMAKE_OBJCOPY "${_toolchain_tool_prefix}objcopy")
set(CMAKE_READELF "${_toolchain_tool_prefix}readelf")
set(CMAKE_STRIP "${_toolchain_tool_prefix}strip")

# Init flags: append arch specific flags after the user passed (cached) _INIT variables

set(CMAKE_C_FLAGS_INIT "$CACHE{CMAKE_C_FLAGS_INIT} -U__CMAKE_C_FLAGS_INIT")
string(STRIP "${CMAKE_C_FLAGS_INIT}" CMAKE_C_FLAGS_INIT)

# restore to cached value from cli arguments and append start markers
set(CMAKE_EXE_LINKER_FLAGS_INIT "$CACHE{CMAKE_EXE_LINKER_FLAGS_INIT} -D__CMAKE_EXE_LINKER_FLAGS_INIT") # begin marker
string(STRIP "${CMAKE_EXE_LINKER_FLAGS_INIT}" CMAKE_EXE_LINKER_FLAGS_INIT)

string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " LINKER:--sort-common")
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " LINKER:-z,relro")
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " LINKER:-z,now")
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " LINKER:--gc-sections")

if($ENV{CC} MATCHES "clang")
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

unset(_toolchain_tool_prefix)
