cmake_minimum_required(VERSION 4.2) # use new set/unset(CACHE{KEY}...) feature
message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# default toolchain and hook path
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_SOURCE_DIR}/cmake/toolchain/clang-x86_64.cmake"
    CACHE FILEPATH "")
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    "${CMAKE_SOURCE_DIR}/cmake/top-include.cmake"
    CACHE FILEPATH "")

# cmake-lint: disable=W0106
if(DEFINED ENV{PKG_VERSION})
  set(PROJECT_VERSION_RAW "$ENV{PKG_VERSION}") # rattler-build mode
elseif(DEFINED ENV{PIXI_PROJECT_VERSION})
  set(PROJECT_VERSION_RAW "$ENV{PIXI_PROJECT_VERSION}") # pixi run mode
else()
  set(PROJECT_VERSION_RAW "0.1.0-dev")
endif()
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" PROJECT_VERSION_NUM "${PROJECT_VERSION_RAW}")

project(
  chlibc
  VERSION ${PROJECT_VERSION_NUM}
  LANGUAGES C)

# output dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")

# global options
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# disable RPATH/RUNPATH
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)
set(CMAKE_SKIP_AS_NEEDED_RPATH TRUE)

add_compile_options(-D__MAIN_ADD_C_FLAGS) # markers

# enable more warnings and lint
add_compile_options(-Wall -Wextra -pedantic) # common warning options
if(CMAKE_C_COMPILER_ID MATCHES "Clang") # also matches AppleClang
  set(CMAKE_C_CLANG_TIDY clang-tidy)
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU") # gcc
  add_compile_options(-Wlogical-op -Wstringop-truncation -Wformat-security -Wstringop-overflow=4 -fanalyzer)
else()
  message(FATAL_ERROR, "Unsupported compiler: ${CMAKE_C_COMPILER_ID}.")
endif()

# visibility
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# disable PIE for old OS on x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_compile_options(-fno-PIC -fno-PIE -fno-stack-protector)
endif()

add_compile_options(-fno-stack-protector)

# reproducible build
add_compile_options("-fno-ident") # no .comment section
add_compile_options("-frandom-seed=chlibc_fixed_seed")
add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")

add_compile_options(-U__MAIN_ADD_C_FLAGS)

# debug/release options
add_compile_options(-D__CONFIG_ADD_C_FLAGS)
add_compile_options($<$<CONFIG:Debug>:-g>)
add_compile_options($<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
add_compile_options($<$<CONFIG:Debug>:-O0>)
add_compile_options($<$<CONFIG:Debug>:-DENABLE_DEBUG_LOG=1>)
add_compile_options(-U__CONFIG_ADD_C_FLAGS)

add_link_options(-D__MAIN_ADD_L_FLAGS)

# reproducible build
add_link_options("-Wl,--build-id=0x6BC42CC7360375F3")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux"
   AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"
   AND CMAKE_C_COMPILER_ID MATCHES "Clang")
  # On linux64, the default clang cfg (${CMAKE_C_COMPILER_TARGET}-clang.cfg) always insert -rpath and -rpath-link flags
  add_link_options(--config "${CMAKE_SOURCE_DIR}/.pixi/envs/default/bin/${CMAKE_C_COMPILER_TARGET}.cfg")
  add_link_options(--no-default-config)
endif()

# enable strip for release
add_link_options($<$<CONFIG:Release>:-s>)

# disable PIE for old OS on x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_link_options(-no-pie LINKER:--hash-style=both)
endif()

add_link_options(-U__MAIN_ADD_L_FLAGS)

# targets
add_library(chlibc-loader OBJECT src/loader.c src/loader-${CMAKE_SYSTEM_PROCESSOR}.c)
target_compile_definitions(chlibc-loader PRIVATE _GNU_SOURCE) # enable GNU features, like MAP_ANONYMOUS
set_target_properties(chlibc-loader PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(
  chlibc-loader
  PRIVATE -fPIE
          -ffreestanding # no stdlib
          -fno-stack-protector # no __stack_chk_fail
          -fno-unwind-tables # no unwind tables
          -fno-asynchronous-unwind-tables
          -fno-plt # not PLT
          -mgeneral-regs-only # no fp & simd registers
)

add_executable(chlibc src/chlibc.c)
target_compile_definitions(
  chlibc PRIVATE PROJECT_VERSION_STR="${PROJECT_VERSION_RAW}" _GNU_SOURCE) # enable GNU extension header features
target_link_libraries(chlibc PRIVATE chlibc-loader)
add_custom_command(
  TARGET chlibc
  PRE_LINK
  COMMAND "${CMAKE_LINKER}" -r -o "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/chlibc-loader.dir/loader-linked-$<CONFIG>.o"
          $<TARGET_OBJECTS:chlibc-loader>
  COMMAND "${CMAKE_COMMAND}" -E env "READELF_BIN=${CMAKE_READELF}" "${CMAKE_SOURCE_DIR}/loader_audit.sh"
          "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/chlibc-loader.dir/loader-linked-$<CONFIG>.o"
  COMMENT "Checking loader objects ..."
  COMMAND_EXPAND_LISTS VERBATIM)
# process linker script
add_custom_command(
  TARGET chlibc
  PRE_LINK
  COMMAND ${CMAKE_C_COMPILER} -E -x c ${CMAKE_C_PP_FLAGS} -P ${CMAKE_CURRENT_SOURCE_DIR}/src/loader.ld.S -o
          ${CMAKE_CURRENT_BINARY_DIR}/loader.ld
  COMMENT "Generating the loader linker script ..."
  VERBATIM)
target_link_options(chlibc PRIVATE -T ${CMAKE_CURRENT_BINARY_DIR}/loader.ld)

# disable kernel startup checking
add_custom_command(
  TARGET chlibc
  POST_BUILD
  COMMAND ${CMAKE_OBJCOPY} -R .comment -R .note.ABI-tag $<TARGET_FILE:chlibc>
  COMMENT "Stripping .note.ABI-tag section from $<TARGET_FILE_NAME:chlibc>..."
  VERBATIM)
# checking target elf
add_custom_command(
  TARGET chlibc
  POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E env "READELF_BIN=${CMAKE_READELF}" "${CMAKE_SOURCE_DIR}/elf_release_audit.sh"
          "$<TARGET_FILE:chlibc>"
  COMMENT "Checking $<TARGET_FILE_NAME:chlibc>..."
  VERBATIM)

install(TARGETS chlibc RUNTIME DESTINATION bin)

add_executable(dump-args src/dump-args.c)
target_link_libraries(dump-args PRIVATE ${CMAKE_DL_LIBS})

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  # v0 only works on x86_64
  add_executable(chlibc-v0 src/chlibc-v0.c)

  # disable kernel startup checking
  add_custom_command(
    TARGET chlibc-v0
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -R .comment -R .note.ABI-tag "$<TARGET_FILE:chlibc-v0>"
    COMMENT "Stripping .note.ABI-tag section from $<TARGET_FILE_NAME:chlibc-v0>..."
    VERBATIM)

  # checking target elf
  add_custom_command(
    TARGET chlibc-v0
    POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E env "READELF_BIN=${CMAKE_READELF}" "${CMAKE_SOURCE_DIR}/elf_release_audit.sh"
            "$<TARGET_FILE:chlibc>"
    COMMENT "Checking $<TARGET_FILE_NAME:chlibc>..."
    VERBATIM)
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
