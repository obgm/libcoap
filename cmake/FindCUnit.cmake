# FindCUnit.cmake
# -----------------
#
# Find the CUnit library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following `IMPORTED` targets:
#
# ``cunit``
#   The CUnit library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``CUnit_FOUND``
#   System has the CUnit library.
# ``CUnit_INCLUDE_DIR``
#   The CUnit include directory.
# ``CUnit_LIBRARIES``
#   All CUnit libraries.
#
# Hints
# ^^^^^
#
# Set ``CUnit_ROOT_DIR`` to the root directory of a CUnit installation.

find_path(CUnit_INCLUDE_DIR
  NAMES CUnit/CUnit.h
  PATH_SUFFIXES include
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CUnit_ROOT_DIR}
  )

find_library(CUnit_LIBRARIES
  NAMES cunit
  PATH_SUFFIXES lib
  HINTS ${PROJECT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CUnit_ROOT_DIR}
  )

if(CUnit_LIBRARIES)
  set(CUnit_FOUND TRUE)
else()
  set(CUnit_FOUND FALSE)
  set(error_message "CUnit not found. Set 'CUnit_ROOT_DIR' to the root directory of a CUnit installation.")
  if(CUnit_FIND_REQUIRED)
    message(FATAL_ERROR "${error_message}")
  elseif(NOT CUDA_FIND_QUIETLY)
    message(STATUS "${error_message}")
  endif()
endif()

if(NOT TARGET cunit)
  add_library(cunit
    UNKNOWN
    IMPORTED
    )
  set_target_properties(cunit PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CUnit_INCLUDE_DIR}"
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${CUnit_LIBRARIES}"
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CUnit DEFAULT_MSG
  CUnit_INCLUDE_DIR
  CUnit_LIBRARIES
  )

mark_as_advanced(
  CUnit_INCLUDE_DIR
  CUnit_LIBRARIES
  )
