cmake_minimum_required(VERSION 4.2) # use new set/unset(CACHE{KEY}...) feature
message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# default toolchain and hook path
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_SOURCE_DIR}/cmake/toolchain/clang-x86_64.cmake"
    CACHE FILEPATH "")
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    "${CMAKE_SOURCE_DIR}/cmake/toolchain/top-include.cmake"
    CACHE FILEPATH "")

project(chlibc C)

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
add_compile_options(-fvisibility=hidden)

# disable PIE for old OS on x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_compile_options(-fno-PIC -fno-PIE -fno-stack-protector)
  # -fno-builtin
endif()

add_compile_options(-U__MAIN_ADD_C_FLAGS)

# debug/release options
add_compile_options(-D__CONFIG_ADD_C_FLAGS)
add_compile_options($<$<CONFIG:Debug>:-g>)
add_compile_options($<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
add_compile_options($<$<CONFIG:Debug>:-O0>)
add_compile_options($<$<CONFIG:Debug>:-DENABLE_DEBUG_LOG=1>)
add_compile_options($<$<CONFIG:Release>:-ffast-math>)
add_compile_options(-U__CONFIG_ADD_C_FLAGS)

add_link_options(-D__MAIN_ADD_L_FLAGS)

# enable strip for release
add_link_options($<$<CONFIG:Release>:-s>)

# disable PIE for old OS on x86_64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_link_options(-no-pie LINKER:--hash-style=both LINKER:-z,lazy)
endif()

add_link_options(-U__MAIN_ADD_L_FLAGS)

# targets
add_executable(chlibc src/chlibc.c)
target_compile_definitions(chlibc PRIVATE _GNU_SOURCE) # elable GNU extension header features
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
    TARGET chlibc
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
