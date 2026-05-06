message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# toolchain post project hook for C language

get_property(_langs GLOBAL PROPERTY ENABLED_LANGUAGES)
if(NOT "C" IN_LIST _langs)
  unset(_langs)
  return()
endif()
unset(_langs)

include_guard(GLOBAL)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  if(CMAKE_C_COMPILER_ID MATCHES "Clang") # also matches AppleClang
    add_compile_options(-D__POST_PRJ_ADD_C_FLAGS)

    add_compile_options(-march=x86-64)
    add_compile_options(-mtune=haswell)
    add_compile_options(-fcf-protection=full) # enable CET

    add_compile_options(-U__POST_PRJ_ADD_C_FLAGS)
  else()
    add_compile_options(-U__POST_PRJ_ADD_C_FLAGS)
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  add_compile_options(-D__POST_PRJ_ADD_C_FLAGS)

  add_compile_options(-march=armv8.2-a)
  add_compile_options(-mtune=neoverse-n1)
  add_compile_options(-mbranch-protection=bti) # enable BTI

  add_compile_options(-U__POST_PRJ_ADD_C_FLAGS)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
  add_compile_options(-D__POST_PRJ_ADD_C_FLAGS)
  add_compile_options(-march=rv64gc_zicfilp_zicfiss)
  add_compile_options(-mabi=lp64d)
  add_compile_options(-U__POST_PRJ_ADD_C_FLAGS)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "powerpc64le")
  add_compile_options(-D__POST_PRJ_ADD_C_FLAGS)
  add_compile_options(-mcpu=power8)
  add_compile_options(-mtune=power9)
  add_compile_options(-mabi=elfv2)
  add_compile_options(-mcmodel=medium)
  add_compile_options(-U__POST_PRJ_ADD_C_FLAGS)
else()
  message(FATAL_ERROR "Unknown CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR}")
endif()
