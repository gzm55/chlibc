message(VERBOSE "Processing ${CMAKE_CURRENT_LIST_FILE}")

# This script must be included via CMAKE_PROJECT_TOP_LEVEL_INCLUDES and will only be processed once after toolchain

# --- Hook & Env Watchdog ---

set(_hook_vars CMAKE_TOOLCHAIN_FILE CMAKE_PROJECT_TOP_LEVEL_INCLUDES CMAKE_PROJECT_INCLUDE_BEFORE CMAKE_PROJECT_INCLUDE)

foreach(var_name IN LISTS _hook_vars)
  if(NOT DEFINED ${var_name})
    continue()
  endif()
  foreach(path IN LISTS ${var_name})
    if(NOT EXISTS "${path}")
      continue()
    endif()
    cmake_path(ABSOLUTE_PATH path BASE_DIRECTORY "${CMAKE_SOURCE_DIR}" NORMALIZE OUTPUT_VARIABLE _abs_path)

    set_property(
      DIRECTORY "${CMAKE_SOURCE_DIR}"
      APPEND
      PROPERTY CMAKE_CONFIGURE_DEPENDS "${_abs_path}")
    message(VERBOSE "Watching Hook: ${_abs_path}")
  endforeach()
endforeach()

set(_pixi_lock "${CMAKE_SOURCE_DIR}/pixi.lock")
if(EXISTS "${_pixi_lock}")
  cmake_path(NORMAL_PATH _pixi_lock)
  set_property(
    DIRECTORY "${CMAKE_SOURCE_DIR}"
    APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS "${_pixi_lock}")
  message(VERBOSE "Watching Environment: ${_pixi_lock}")
endif()

unset(_hook_vars)
unset(var_name)
unset(path)
unset(_abs_path)
unset(_pixi_lock)
