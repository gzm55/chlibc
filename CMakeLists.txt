cmake_minimum_required(VERSION 3.10)
project(chlibc C)

# global options
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# message(STATUS "---------------------------------------") message(STATUS "Global C_FLAGS: ${CMAKE_C_FLAGS}")
# message(STATUS "Debug C_FLAGS:  ${CMAKE_C_FLAGS_DEBUG}") message(STATUS "Release C_FLAGS:${CMAKE_C_FLAGS_RELEASE}")
# message(STATUS "---------------------------------------")
#
# default C_FLAGS on x86_64/aarch64: (x86_64 only):-march=... -mtune=... -ftree-vectorize -fPIC -fstack-protector-strong
# -fno-plt (x86_64 only):-O2 (aarch64 only):-O3 (x86_64 only):-ffunction-sections -pipe -isystem $CONDA_PREFIX/include
#
# final options: CMAKE_C_FLAGS CMAKE_C_FLAGS_<CONFIG> target_compile_options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS_ARCH}") # append options for each arch, like mtune
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic") # append common warning options

if(CMAKE_C_COMPILER_ID MATCHES "Clang") # also matches AppleClang
  set(CMAKE_C_CLANG_TIDY clang-tidy)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -Wlogical-op -Wstringop-truncation -Wformat-security -Wstringop-overflow=4 -fanalyzer")
else()
  message(FATAL_ERROR, "Unsupported compiler: ${CMAKE_C_COMPILER_ID}.")
endif()

set(CMAKE_C_FLAGS_DEBUG "-g -fno-omit-frame-pointer -O0 -DENABLE_DEBUG_LOG=1")
set(CMAKE_C_FLAGS_RELEASE "-O3 -ffast-math -DNDEBUG")

# enable strip for release
set(CMAKE_STRIP_FLAGS "-s")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--hash-style=both")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s")

# enable clang-tidy in default conda env

# output dir
set(_target_bin_dir "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${_target_bin_dir})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${_target_bin_dir})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${_target_bin_dir})

# targets
add_executable(chlibc src/chlibc.c)
target_compile_definitions(chlibc PRIVATE _GNU_SOURCE) # elable GNU extension header features

add_executable(dump-args src/dump-args.c)
target_link_libraries(dump-args PRIVATE ${CMAKE_DL_LIBS})

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  # v0 is only works on x86_64
  add_executable(chlibc-v0 src/chlibc-v0.c)
endif()

# common options
get_property(
  all_targets
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  PROPERTY BUILDSYSTEM_TARGETS)
foreach(tgt ${all_targets})
  get_target_property(target_type ${tgt} TYPE)
  if(target_type STREQUAL "EXECUTABLE")
    # filename postfix
    set_target_properties(${tgt} PROPERTIES DEBUG_POSTFIX "-dbg")
  endif()
endforeach()
